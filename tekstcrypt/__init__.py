"""tekstcrypt: tekst versleutelen en ontsleutelen met AES-256-GCM."""

from .crypto import MODE_KEY, MODE_PASSWORD, decrypt, encrypt_with_key, encrypt_with_password, message_mode
from .errors import DecryptionError, FormatError, KeyFileError, TekstcryptError, WeakPasswordError
from .keys import SymmetricKey, is_protected, load_key, save_key

__version__ = "1.0.0"

__all__ = [
    "MODE_KEY",
    "MODE_PASSWORD",
    "DecryptionError",
    "FormatError",
    "KeyFileError",
    "SymmetricKey",
    "TekstcryptError",
    "WeakPasswordError",
    "decrypt",
    "encrypt_with_key",
    "encrypt_with_password",
    "is_protected",
    "load_key",
    "message_mode",
    "save_key",
]
