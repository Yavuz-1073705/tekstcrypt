"""Foutklassen van tekstcrypt.

Alle fouten erven van ``TekstcryptError``, zodat de CLI en GUI ze op één plek
kunnen afvangen en een nette melding kunnen tonen in plaats van een stacktrace.
"""


class TekstcryptError(Exception):
    """Basisklasse voor alle fouten in deze applicatie."""


class FormatError(TekstcryptError):
    """De invoer is geen geldig tekstcrypt-bericht of sleutelbestand."""


class DecryptionError(TekstcryptError):
    """Ontsleutelen is mislukt: verkeerde sleutel/wachtwoord of gemanipuleerde data."""


class KeyFileError(TekstcryptError):
    """Er ging iets mis bij het lezen of schrijven van een sleutelbestand."""


class WeakPasswordError(TekstcryptError):
    """Het opgegeven wachtwoord voldoet niet aan de minimale eisen."""
