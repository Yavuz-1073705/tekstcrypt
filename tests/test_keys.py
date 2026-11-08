import json
import re

import pytest

from tekstcrypt.errors import DecryptionError, FormatError, KeyFileError, WeakPasswordError
from tekstcrypt.kdf import KdfParams
from tekstcrypt.keys import SymmetricKey, is_protected, load_key, save_key

FAST = KdfParams(memory_cost=1024, iterations=1, lanes=1)
PASSWORD = "sleutelwachtwoord"


def test_generated_keys_are_256_bit_and_unique():
    keys = {SymmetricKey.generate().material for _ in range(100)}
    assert len(keys) == 100
    assert all(len(k) == 32 for k in keys)


def test_key_material_not_in_repr():
    key = SymmetricKey.generate()
    assert key.material.hex() not in repr(key)
    assert str(key.material) not in repr(key)


def test_wrong_key_length_is_refused():
    with pytest.raises(FormatError):
        SymmetricKey(b"te kort")


def test_fingerprint_format_and_stability():
    key = SymmetricKey.generate()
    assert re.fullmatch(r"([0-9A-F]{4}-){7}[0-9A-F]{4}", key.fingerprint)
    assert SymmetricKey(key.material).fingerprint == key.fingerprint
    assert SymmetricKey.generate().fingerprint != key.fingerprint


def test_save_and_load_unprotected(tmp_path):
    key = SymmetricKey.generate()
    path = save_key(key, tmp_path / "a.key")
    assert not is_protected(path)
    assert load_key(path) == key


def test_save_and_load_protected(tmp_path):
    key = SymmetricKey.generate()
    path = save_key(key, tmp_path / "a.key", PASSWORD, params=FAST)
    assert is_protected(path)
    content = path.read_text()
    assert "wrapped_key" in content and '"key"' not in content
    assert load_key(path, PASSWORD) == key


def test_protected_key_needs_correct_password(tmp_path):
    path = save_key(SymmetricKey.generate(), tmp_path / "a.key", PASSWORD, params=FAST)
    with pytest.raises(KeyFileError):
        load_key(path)
    with pytest.raises(DecryptionError):
        load_key(path, "verkeerd wachtwoord")


def test_weak_password_for_keyfile_is_refused(tmp_path):
    with pytest.raises(WeakPasswordError):
        save_key(SymmetricKey.generate(), tmp_path / "a.key", "kort", params=FAST)


def test_existing_file_is_not_overwritten(tmp_path):
    path = save_key(SymmetricKey.generate(), tmp_path / "a.key")
    original = path.read_text()
    with pytest.raises(KeyFileError, match="bestaat al"):
        save_key(SymmetricKey.generate(), path)
    assert path.read_text() == original
    save_key(SymmetricKey.generate(), path, overwrite=True)
    assert path.read_text() != original


def test_tampered_key_id_in_protected_file(tmp_path):
    path = save_key(SymmetricKey.generate(), tmp_path / "a.key", PASSWORD, params=FAST)
    doc = json.loads(path.read_text())
    doc["key_id"] = SymmetricKey.generate().key_id.hex()
    path.write_text(json.dumps(doc))
    with pytest.raises(DecryptionError):
        load_key(path, PASSWORD)


def test_corrupt_unprotected_file(tmp_path):
    path = save_key(SymmetricKey.generate(), tmp_path / "a.key")
    doc = json.loads(path.read_text())
    doc["key_id"] = "00" * 8
    path.write_text(json.dumps(doc))
    with pytest.raises(FormatError):
        load_key(path)


@pytest.mark.parametrize("content", ["geen json", "{}", '{"format": "iets-anders"}',
                                     '{"format": "tekstcrypt-key", "version": 1}'])
def test_invalid_keyfiles(tmp_path, content):
    path = tmp_path / "a.key"
    path.write_text(content)
    with pytest.raises(FormatError):
        load_key(path)


def test_missing_keyfile(tmp_path):
    with pytest.raises(KeyFileError, match="bestaat niet"):
        load_key(tmp_path / "bestaat-niet.key")
