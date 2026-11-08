"""Versleutelen en ontsleutelen van tekst met AES-256-GCM.

Berichtformaat (daarna base64url-gecodeerd tot één tekstregel):

    Sleutelbestand-modus (mode 1):
        version (1) | mode (1) | key_id (8) | nonce (12) | ciphertext + tag (16)

    Wachtwoord-modus (mode 2):
        version (1) | mode (1) | salt (16) | memory_cost (4) | iterations (1)
        | lanes (1) | nonce (12) | ciphertext + tag (16)

Alles vóór de nonce is de *header*. Die wordt als associated data (AAD) aan
AES-GCM meegegeven: de header is niet geheim, maar wel beschermd tegen
manipulatie. Wie bijvoorbeeld de Argon2id-parameters of de modus verandert,
laat de authenticatie mislukken.
"""

from __future__ import annotations

import base64
import binascii
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError, FormatError
from .kdf import SALT_SIZE, DEFAULT_PARAMS, KdfParams, check_password_strength, derive_key, new_salt
from .keys import KEY_ID_SIZE, SymmetricKey

FORMAT_VERSION = 1
MODE_KEY = 1
MODE_PASSWORD = 2
NONCE_SIZE = 12  # 96 bit, de door NIST SP 800-38D aanbevolen lengte voor GCM
TAG_SIZE = 16

_KEY_HEADER = struct.Struct(f">BB{KEY_ID_SIZE}s")
_PASSWORD_HEADER = struct.Struct(f">BB{SALT_SIZE}sIBB")


@dataclass(frozen=True)
class ParsedMessage:
    """Een ontleed bericht, nog niet ontsleuteld."""

    mode: int
    header: bytes
    nonce: bytes
    ciphertext: bytes
    key_id: bytes | None = None
    salt: bytes | None = None
    kdf_params: KdfParams | None = None


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(token: str) -> bytes:
    cleaned = "".join(token.split())  # spaties/regeleinden van kopiëren negeren
    if not cleaned:
        raise FormatError("Er is geen versleutelde tekst opgegeven.")
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise FormatError("Dit is geen geldige versleutelde tekst (base64-fout).") from exc


def _seal(key: bytes, header: bytes, plaintext: str) -> str:
    # Elke versleuteling krijgt een nieuwe willekeurige nonce. Een nonce
    # hergebruiken met dezelfde sleutel breekt GCM volledig, dus die mag
    # nooit vast of voorspelbaar zijn.
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), header)
    return _encode(header + nonce + ciphertext)


def encrypt_with_key(plaintext: str, key: SymmetricKey) -> str:
    """Versleutel tekst met een sleutel uit een sleutelbestand."""
    header = _KEY_HEADER.pack(FORMAT_VERSION, MODE_KEY, key.key_id)
    return _seal(key.material, header, plaintext)


def encrypt_with_password(
    plaintext: str, password: str, params: KdfParams = DEFAULT_PARAMS
) -> str:
    """Versleutel tekst met een wachtwoord (Argon2id + AES-256-GCM)."""
    check_password_strength(password)
    params.validate()
    salt = new_salt()
    header = _PASSWORD_HEADER.pack(
        FORMAT_VERSION, MODE_PASSWORD, salt, params.memory_cost, params.iterations, params.lanes
    )
    return _seal(derive_key(password, salt, params), header, plaintext)


def parse(token: str) -> ParsedMessage:
    """Ontleed een bericht zonder te ontsleutelen (bijv. om de modus te bepalen)."""
    data = _decode(token)
    if len(data) < 2:
        raise FormatError("Versleutelde tekst is te kort.")
    version, mode = data[0], data[1]
    if version != FORMAT_VERSION:
        raise FormatError(f"Niet-ondersteunde berichtversie: {version}.")

    if mode == MODE_KEY:
        header_struct = _KEY_HEADER
    elif mode == MODE_PASSWORD:
        header_struct = _PASSWORD_HEADER
    else:
        raise FormatError(f"Onbekende versleutelingsmodus: {mode}.")

    header_len = header_struct.size
    if len(data) < header_len + NONCE_SIZE + TAG_SIZE:
        raise FormatError("Versleutelde tekst is onvolledig (afgekapt bij kopiëren?).")

    header = data[:header_len]
    nonce = data[header_len : header_len + NONCE_SIZE]
    ciphertext = data[header_len + NONCE_SIZE :]

    if mode == MODE_KEY:
        _, _, key_id = header_struct.unpack(header)
        return ParsedMessage(mode, header, nonce, ciphertext, key_id=key_id)

    _, _, salt, memory_cost, iterations, lanes = header_struct.unpack(header)
    params = KdfParams(memory_cost=memory_cost, iterations=iterations, lanes=lanes)
    params.validate()  # weiger kwaadaardig hoge parameters vóór de dure KDF
    return ParsedMessage(mode, header, nonce, ciphertext, salt=salt, kdf_params=params)


def message_mode(token: str) -> int:
    """Geef ``MODE_KEY`` of ``MODE_PASSWORD`` terug voor een bericht."""
    return parse(token).mode


def decrypt(
    token: str,
    *,
    key: SymmetricKey | None = None,
    password: str | None = None,
) -> str:
    """Ontsleutel een bericht met de juiste sleutel of het juiste wachtwoord."""
    msg = parse(token)

    if msg.mode == MODE_KEY:
        if key is None:
            raise DecryptionError("Dit bericht is versleuteld met een sleutelbestand; kies dat bestand.")
        if key.key_id != msg.key_id:
            raise DecryptionError(
                "Dit bericht is met een andere sleutel versleuteld "
                f"(key-id {msg.key_id.hex()}, jouw sleutel {key.key_id.hex()})."
            )
        aes_key = key.material
    else:
        if password is None:
            raise DecryptionError("Dit bericht is versleuteld met een wachtwoord; geef dat op.")
        aes_key = derive_key(password, msg.salt, msg.kdf_params)

    try:
        plaintext = AESGCM(aes_key).decrypt(msg.nonce, msg.ciphertext, msg.header)
    except InvalidTag as exc:
        # Bewust één algemene melding: we verraden niet *wat* er mis is.
        raise DecryptionError(
            "Ontsleutelen mislukt: verkeerde sleutel/wachtwoord, of de tekst is aangepast."
        ) from exc
    return plaintext.decode("utf-8")
