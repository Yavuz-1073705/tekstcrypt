"""Sleutelbeheer: genereren, opslaan, laden en herkennen van symmetrische sleutels.

Sleutelbestanden zijn JSON. Een sleutel kan onbeveiligd (alleen base64) of
beveiligd met een wachtwoord worden opgeslagen. Bij een beveiligd bestand wordt
de echte sleutel ingepakt ("key wrapping") met AES-256-GCM onder een sleutel
die met Argon2id uit het wachtwoord is afgeleid.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError, FormatError, KeyFileError
from .kdf import DEFAULT_PARAMS, KdfParams, check_password_strength, derive_key, new_salt

KEY_SIZE = 32  # 256 bit
KEY_ID_SIZE = 8
NONCE_SIZE = 12
KEYFILE_FORMAT = "tekstcrypt-key"
KEYFILE_VERSION = 1
ALGORITHM = "AES-256-GCM"

_FINGERPRINT_DOMAIN = b"tekstcrypt/fingerprint/v1"
_WRAP_AAD_PREFIX = b"tekstcrypt/keyfile/v1"


@dataclass(frozen=True)
class SymmetricKey:
    """Een 256-bit AES-sleutel.

    ``repr=False`` zorgt dat het sleutelmateriaal nooit per ongeluk in een
    foutmelding, log of debugger-weergave terechtkomt.
    """

    material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.material) != KEY_SIZE:
            raise FormatError(f"Sleutel moet precies {KEY_SIZE} bytes zijn.")

    @classmethod
    def generate(cls) -> "SymmetricKey":
        """Genereer een nieuwe sleutel met de CSPRNG van het besturingssysteem."""
        return cls(AESGCM.generate_key(bit_length=KEY_SIZE * 8))

    @property
    def _digest(self) -> bytes:
        return hashlib.sha256(_FINGERPRINT_DOMAIN + self.material).digest()

    @property
    def key_id(self) -> bytes:
        """Korte, niet-geheime identificatie van de sleutel (8 bytes).

        Wordt in elk bericht meegestuurd, zodat de applicatie direct kan zeggen
        dat een bericht met een andere sleutel is versleuteld.
        """
        return self._digest[:KEY_ID_SIZE]

    @property
    def fingerprint(self) -> str:
        """Menselijk leesbare vingerafdruk (128 bit) om sleutels te vergelijken.

        Twee gebruikers kunnen via een tweede kanaal (bijv. telefonisch)
        controleren of ze dezelfde sleutel hebben, zonder de sleutel zelf te
        hoeven uitspreken.
        """
        hexed = self._digest[:16].hex().upper()
        return "-".join(hexed[i : i + 4] for i in range(0, len(hexed), 4))


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise FormatError(f"Sleutelbestand bevat ongeldige base64 in '{what}'.") from exc


def _wrap_aad(key_id: bytes) -> bytes:
    # De key-id wordt als associated data meegenomen: wie het key_id-veld in het
    # bestand aanpast, laat de authenticatie mislukken.
    return _WRAP_AAD_PREFIX + key_id


def key_to_document(
    key: SymmetricKey,
    password: str | None = None,
    params: KdfParams = DEFAULT_PARAMS,
) -> dict:
    """Zet een sleutel om naar een JSON-structuur (optioneel wachtwoord-beveiligd)."""
    doc: dict = {
        "format": KEYFILE_FORMAT,
        "version": KEYFILE_VERSION,
        "algorithm": ALGORITHM,
        "key_id": key.key_id.hex(),
        "fingerprint": key.fingerprint,
    }
    if password is None:
        doc["protected"] = False
        doc["key"] = _b64e(key.material)
        return doc

    check_password_strength(password)
    salt = new_salt()
    nonce = os.urandom(NONCE_SIZE)
    kek = derive_key(password, salt, params)  # key-encryption key
    wrapped = AESGCM(kek).encrypt(nonce, key.material, _wrap_aad(key.key_id))
    doc["protected"] = True
    doc["kdf"] = {
        "name": "argon2id",
        "salt": _b64e(salt),
        "memory_cost": params.memory_cost,
        "iterations": params.iterations,
        "lanes": params.lanes,
    }
    doc["nonce"] = _b64e(nonce)
    doc["wrapped_key"] = _b64e(wrapped)
    return doc


def key_from_document(doc: dict, password: str | None = None) -> SymmetricKey:
    """Lees een sleutel uit een JSON-structuur; vraagt een wachtwoord als die beveiligd is."""
    if not isinstance(doc, dict) or doc.get("format") != KEYFILE_FORMAT:
        raise FormatError("Dit is geen tekstcrypt-sleutelbestand.")
    if doc.get("version") != KEYFILE_VERSION:
        raise FormatError(f"Niet-ondersteunde sleutelbestandversie: {doc.get('version')!r}.")

    try:
        expected_id = bytes.fromhex(doc["key_id"])
        if not doc["protected"]:
            key = SymmetricKey(_b64d(doc["key"], "key"))
        else:
            if password is None:
                raise KeyFileError("Dit sleutelbestand is beveiligd met een wachtwoord.")
            kdf = doc["kdf"]
            if kdf.get("name") != "argon2id":
                raise FormatError("Onbekende sleutelafleidingsfunctie in sleutelbestand.")
            params = KdfParams(
                memory_cost=int(kdf["memory_cost"]),
                iterations=int(kdf["iterations"]),
                lanes=int(kdf["lanes"]),
            )
            kek = derive_key(password, _b64d(kdf["salt"], "salt"), params)
            try:
                material = AESGCM(kek).decrypt(
                    _b64d(doc["nonce"], "nonce"),
                    _b64d(doc["wrapped_key"], "wrapped_key"),
                    _wrap_aad(expected_id),
                )
            except InvalidTag as exc:
                raise DecryptionError(
                    "Verkeerd wachtwoord voor sleutelbestand, of het bestand is aangepast."
                ) from exc
            key = SymmetricKey(material)
    except (KeyError, TypeError, ValueError) as exc:
        raise FormatError("Sleutelbestand is onvolledig of beschadigd.") from exc

    if key.key_id != expected_id:
        raise FormatError("Sleutel komt niet overeen met de key-id in het bestand (beschadigd?).")
    return key


def save_key(
    key: SymmetricKey,
    path: str | os.PathLike,
    password: str | None = None,
    *,
    overwrite: bool = False,
    params: KdfParams = DEFAULT_PARAMS,
) -> Path:
    """Schrijf een sleutel naar schijf met zo beperkt mogelijke bestandsrechten."""
    path = Path(path)
    content = json.dumps(key_to_document(key, password, params), indent=2) + "\n"

    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        # 0o600: alleen de eigenaar mag lezen/schrijven (op POSIX-systemen).
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise KeyFileError(
            f"'{path}' bestaat al. Gebruik overschrijven als je dit echt wilt."
        ) from exc
    except OSError as exc:
        raise KeyFileError(f"Kan '{path}' niet schrijven: {exc.strerror}.") from exc

    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def read_key_document(path: str | os.PathLike) -> dict:
    """Lees de ruwe JSON van een sleutelbestand."""
    path = Path(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise KeyFileError(f"Sleutelbestand '{path}' bestaat niet.") from exc
    except OSError as exc:
        raise KeyFileError(f"Kan '{path}' niet lezen: {exc.strerror}.") from exc
    except json.JSONDecodeError as exc:
        raise FormatError(f"'{path}' is geen geldig sleutelbestand (geen JSON).") from exc


def is_protected(path: str | os.PathLike) -> bool:
    """Geeft aan of het sleutelbestand een wachtwoord nodig heeft."""
    return bool(read_key_document(path).get("protected"))


def load_key(path: str | os.PathLike, password: str | None = None) -> SymmetricKey:
    """Laad een sleutel uit een bestand."""
    return key_from_document(read_key_document(path), password)
