"""Sleutelafleiding uit een wachtwoord met Argon2id.

Een wachtwoord is géén cryptografische sleutel: het is te kort en te
voorspelbaar. Argon2id (RFC 9106, winnaar van de Password Hashing Competition)
rekt het wachtwoord op tot een 256-bit sleutel en maakt brute-force aanvallen
duur doordat elke poging veel geheugen en rekentijd kost.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import FormatError, WeakPasswordError

SALT_SIZE = 16  # 128 bit, aanbevolen door RFC 9106
DERIVED_KEY_SIZE = 32  # 256 bit, voor AES-256
MIN_PASSWORD_LENGTH = 8

# Bovengrenzen voor parameters die uit een (mogelijk kwaadaardig) bericht
# worden gelezen. Zonder deze grenzen kan een aanvaller een bericht maken dat
# bij het ontsleutelen gigabytes geheugen opeist (denial of service).
MAX_MEMORY_COST = 1024 * 1024  # 1 GiB, in KiB
MAX_ITERATIONS = 20
MAX_LANES = 16


@dataclass(frozen=True)
class KdfParams:
    """Argon2id-parameters. ``memory_cost`` is in KiB."""

    memory_cost: int = 64 * 1024  # 64 MiB
    iterations: int = 3
    lanes: int = 4

    def validate(self) -> None:
        """Controleer of de parameters binnen veilige en redelijke grenzen vallen."""
        if not 8 * self.lanes <= self.memory_cost <= MAX_MEMORY_COST:
            raise FormatError("Ongeldige Argon2id-geheugenparameter.")
        if not 1 <= self.iterations <= MAX_ITERATIONS:
            raise FormatError("Ongeldig aantal Argon2id-iteraties.")
        if not 1 <= self.lanes <= MAX_LANES:
            raise FormatError("Ongeldig aantal Argon2id-lanes.")


DEFAULT_PARAMS = KdfParams()


def new_salt() -> bytes:
    """Genereer een willekeurige salt met de CSPRNG van het besturingssysteem."""
    return os.urandom(SALT_SIZE)


def check_password_strength(password: str) -> None:
    """Weiger wachtwoorden die te kort zijn om enige bescherming te bieden."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Wachtwoord moet minstens {MIN_PASSWORD_LENGTH} tekens lang zijn."
        )


def derive_key(password: str, salt: bytes, params: KdfParams = DEFAULT_PARAMS) -> bytes:
    """Leid een 256-bit sleutel af uit ``password`` en ``salt``.

    Het wachtwoord wordt eerst NFC-genormaliseerd, zodat hetzelfde wachtwoord
    met bijvoorbeeld een 'é' op elk besturingssysteem dezelfde bytes oplevert.
    """
    params.validate()
    normalized = unicodedata.normalize("NFC", password).encode("utf-8")
    kdf = Argon2id(
        salt=salt,
        length=DERIVED_KEY_SIZE,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost,
    )
    return kdf.derive(normalized)
