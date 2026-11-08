import base64

import pytest

from tekstcrypt import crypto
from tekstcrypt.errors import DecryptionError, FormatError, WeakPasswordError
from tekstcrypt.kdf import KdfParams
from tekstcrypt.keys import SymmetricKey

# Lichte parameters zodat de tests snel zijn; productie gebruikt DEFAULT_PARAMS.
FAST = KdfParams(memory_cost=1024, iterations=1, lanes=1)
PASSWORD = "correct horse battery staple"


def _raw(token: str) -> bytearray:
    return bytearray(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))


def _token(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")


@pytest.mark.parametrize("text", ["Hallo wereld", "", "Ünïcödé ✓ 🔐", "regel 1\nregel 2", "x" * 10_000])
def test_roundtrip_with_key(text):
    key = SymmetricKey.generate()
    assert crypto.decrypt(crypto.encrypt_with_key(text, key), key=key) == text


@pytest.mark.parametrize("text", ["Hallo wereld", "Ünïcödé ✓ 🔐"])
def test_roundtrip_with_password(text):
    token = crypto.encrypt_with_password(text, PASSWORD, FAST)
    assert crypto.decrypt(token, password=PASSWORD) == text


def test_same_plaintext_gives_different_ciphertext():
    # Willekeurige nonce (en salt): identieke berichten zijn niet te herkennen.
    key = SymmetricKey.generate()
    assert crypto.encrypt_with_key("geheim", key) != crypto.encrypt_with_key("geheim", key)
    assert crypto.encrypt_with_password("geheim", PASSWORD, FAST) != crypto.encrypt_with_password(
        "geheim", PASSWORD, FAST
    )


def test_ciphertext_does_not_contain_plaintext():
    key = SymmetricKey.generate()
    raw = _raw(crypto.encrypt_with_key("ZEERGEHEIM", key))
    assert b"ZEERGEHEIM" not in raw


def test_message_mode():
    key = SymmetricKey.generate()
    assert crypto.message_mode(crypto.encrypt_with_key("a", key)) == crypto.MODE_KEY
    assert crypto.message_mode(crypto.encrypt_with_password("a", PASSWORD, FAST)) == crypto.MODE_PASSWORD


def test_wrong_key_is_rejected():
    token = crypto.encrypt_with_key("geheim", SymmetricKey.generate())
    with pytest.raises(DecryptionError, match="andere sleutel"):
        crypto.decrypt(token, key=SymmetricKey.generate())


def test_wrong_password_is_rejected():
    token = crypto.encrypt_with_password("geheim", PASSWORD, FAST)
    with pytest.raises(DecryptionError):
        crypto.decrypt(token, password="verkeerd wachtwoord")


def test_missing_key_or_password():
    key = SymmetricKey.generate()
    with pytest.raises(DecryptionError):
        crypto.decrypt(crypto.encrypt_with_key("a", key))
    with pytest.raises(DecryptionError):
        crypto.decrypt(crypto.encrypt_with_password("a", PASSWORD, FAST))


def test_tampered_ciphertext_is_detected():
    key = SymmetricKey.generate()
    raw = _raw(crypto.encrypt_with_key("Maak 100 euro over", key))
    raw[-20] ^= 0x01  # één bit omdraaien in de ciphertext
    with pytest.raises(DecryptionError, match="aangepast"):
        crypto.decrypt(_token(raw), key=key)


def test_tampered_header_is_detected():
    # Header is AAD: een aangepaste Argon2id-parameter moet de tag breken.
    raw = _raw(crypto.encrypt_with_password("geheim", PASSWORD, FAST))
    raw[2 + 16 + 4] = 2  # iterations-byte
    with pytest.raises(DecryptionError):
        crypto.decrypt(_token(raw), password=PASSWORD)


def test_forged_key_id_is_detected():
    key = SymmetricKey.generate()
    other = SymmetricKey.generate()
    raw = _raw(crypto.encrypt_with_key("geheim", key))
    raw[2:10] = other.key_id  # doe alsof het bericht voor 'other' is
    with pytest.raises(DecryptionError):
        crypto.decrypt(_token(raw), key=other)


def test_malicious_kdf_parameters_are_refused():
    # Een bericht dat 4 GiB geheugen vraagt, wordt geweigerd vóór de KDF draait.
    raw = _raw(crypto.encrypt_with_password("geheim", PASSWORD, FAST))
    raw[18:22] = (4 * 1024 * 1024).to_bytes(4, "big")
    with pytest.raises(FormatError):
        crypto.decrypt(_token(raw), password=PASSWORD)


def test_whitespace_in_token_is_ignored():
    key = SymmetricKey.generate()
    token = crypto.encrypt_with_key("geheim", key)
    spaced = "  " + token[:10] + "\n" + token[10:] + "\n"
    assert crypto.decrypt(spaced, key=key) == "geheim"


@pytest.mark.parametrize("bad", ["", "   ", "!!!geen base64!!!", "AQ", _token(b"\x09\x01" + b"\x00" * 60)])
def test_invalid_input_gives_format_error(bad):
    with pytest.raises(FormatError):
        crypto.decrypt(bad, key=SymmetricKey.generate())


def test_truncated_token_gives_format_error():
    key = SymmetricKey.generate()
    token = crypto.encrypt_with_key("geheim", key)
    with pytest.raises(FormatError, match="onvolledig"):
        crypto.decrypt(token[:20], key=key)


def test_unknown_mode():
    with pytest.raises(FormatError, match="modus"):
        crypto.decrypt(_token(b"\x01\x07" + b"\x00" * 60), key=SymmetricKey.generate())


def test_weak_password_is_refused():
    with pytest.raises(WeakPasswordError):
        crypto.encrypt_with_password("geheim", "kort", FAST)
