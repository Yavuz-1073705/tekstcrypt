import pytest

from tekstcrypt.cli import main


def prompts(*answers):
    """Nep-``getpass`` die vaste antwoorden teruggeeft."""
    it = iter(answers)
    return lambda _prompt="": next(it)


def test_keyfile_flow(tmp_path, capsys):
    keyfile = tmp_path / "test.key"
    assert main(["genereer-sleutel", "-o", str(keyfile)]) == 0
    assert "Vingerafdruk" in capsys.readouterr().out

    assert main(["versleutel", "-s", str(keyfile), "-t", "Hallo HR"]) == 0
    token = capsys.readouterr().out.strip()
    assert "Hallo" not in token

    assert main(["ontsleutel", "-s", str(keyfile), "-t", token]) == 0
    assert capsys.readouterr().out.strip() == "Hallo HR"


def test_protected_keyfile_flow(tmp_path, capsys):
    keyfile = tmp_path / "test.key"
    pw = "beveiligd-123"
    assert main(["genereer-sleutel", "-o", str(keyfile), "--beveilig"], ask_password=prompts(pw, pw)) == 0
    capsys.readouterr()

    assert main(["versleutel", "-s", str(keyfile), "-t", "geheim"], ask_password=prompts(pw)) == 0
    token = capsys.readouterr().out.strip()
    assert main(["ontsleutel", "-s", str(keyfile), "-t", token], ask_password=prompts(pw)) == 0
    assert capsys.readouterr().out.strip() == "geheim"


def test_password_flow(capsys):
    pw = "mijn wachtwoord"
    assert main(["versleutel", "-w", "-t", "via wachtwoord"], ask_password=prompts(pw, pw)) == 0
    token = capsys.readouterr().out.strip()
    assert main(["ontsleutel", "-t", token], ask_password=prompts(pw)) == 0
    assert capsys.readouterr().out.strip() == "via wachtwoord"


def test_file_input_and_output(tmp_path, capsys):
    keyfile, plain, enc, dec = (tmp_path / n for n in ("k.key", "in.txt", "enc.txt", "out.txt"))
    plain.write_text("Inhoud uit een bestand\nmet twee regels\n", encoding="utf-8")
    main(["genereer-sleutel", "-o", str(keyfile)])
    assert main(["versleutel", "-s", str(keyfile), "-i", str(plain), "-o", str(enc)]) == 0
    assert main(["ontsleutel", "-s", str(keyfile), "-i", str(enc), "-o", str(dec)]) == 0
    assert dec.read_text(encoding="utf-8") == plain.read_text(encoding="utf-8")


def test_stdin_input(tmp_path, capsys, monkeypatch):
    import io

    keyfile = tmp_path / "k.key"
    main(["genereer-sleutel", "-o", str(keyfile)])
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", io.StringIO("via stdin"))
    assert main(["versleutel", "-s", str(keyfile)]) == 0
    token = capsys.readouterr().out.strip()
    monkeypatch.setattr("sys.stdin", io.StringIO(token))
    assert main(["ontsleutel", "-s", str(keyfile)]) == 0
    assert capsys.readouterr().out.strip() == "via stdin"


def test_mismatched_passwords(capsys):
    assert main(["versleutel", "-w", "-t", "x"], ask_password=prompts("wachtwoord1", "wachtwoord2")) == 1
    assert "niet overeen" in capsys.readouterr().err


def test_keyfile_message_without_key(tmp_path, capsys):
    keyfile = tmp_path / "k.key"
    main(["genereer-sleutel", "-o", str(keyfile)])
    main(["versleutel", "-s", str(keyfile), "-t", "x"])
    token = capsys.readouterr().out.splitlines()[-1]
    assert main(["ontsleutel", "-t", token]) == 1
    assert "--sleutel" in capsys.readouterr().err


def test_wrong_key(tmp_path, capsys):
    a, b = tmp_path / "a.key", tmp_path / "b.key"
    main(["genereer-sleutel", "-o", str(a)])
    main(["genereer-sleutel", "-o", str(b)])
    main(["versleutel", "-s", str(a), "-t", "x"])
    token = capsys.readouterr().out.splitlines()[-1]
    assert main(["ontsleutel", "-s", str(b), "-t", token]) == 1
    assert "andere sleutel" in capsys.readouterr().err


def test_fingerprint_command(tmp_path, capsys):
    keyfile = tmp_path / "k.key"
    main(["genereer-sleutel", "-o", str(keyfile)])
    expected = capsys.readouterr().out.split("Vingerafdruk: ")[1].strip()
    assert main(["vingerafdruk", str(keyfile)]) == 0
    assert capsys.readouterr().out.strip() == expected


def test_refuses_to_overwrite_key(tmp_path, capsys):
    keyfile = tmp_path / "k.key"
    main(["genereer-sleutel", "-o", str(keyfile)])
    assert main(["genereer-sleutel", "-o", str(keyfile)]) == 1
    assert "bestaat al" in capsys.readouterr().err


def test_encrypt_requires_method():
    with pytest.raises(SystemExit):
        main(["versleutel", "-t", "x"])
