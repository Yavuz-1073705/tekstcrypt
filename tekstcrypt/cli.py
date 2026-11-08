"""Command-line interface van tekstcrypt.

Wachtwoorden worden altijd interactief gevraagd (via ``getpass``) en nooit als
argument meegegeven: argumenten komen in de shell-geschiedenis en zijn voor
andere processen zichtbaar in de proceslijst.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Callable

from . import __version__
from .crypto import MODE_KEY, decrypt, encrypt_with_key, encrypt_with_password, message_mode
from .errors import TekstcryptError
from .keys import SymmetricKey, is_protected, load_key, save_key

PasswordPrompt = Callable[[str], str]


def _ask_new_password(ask: PasswordPrompt, label: str) -> str:
    first = ask(f"{label}: ")
    if ask(f"Herhaal {label.lower()}: ") != first:
        raise TekstcryptError("De wachtwoorden komen niet overeen.")
    return first


def _load_key(path: str, ask: PasswordPrompt) -> SymmetricKey:
    password = ask(f"Wachtwoord voor sleutelbestand '{path}': ") if is_protected(path) else None
    return load_key(path, password)


def _read_input(args: argparse.Namespace) -> str:
    if args.tekst is not None:
        return args.tekst
    if args.invoer is not None:
        try:
            return Path(args.invoer).read_text(encoding="utf-8")
        except OSError as exc:
            raise TekstcryptError(f"Kan '{args.invoer}' niet lezen: {exc.strerror}.") from exc
    if sys.stdin.isatty():
        print("Typ de tekst en sluit af met Ctrl+Z, Enter (Windows) of Ctrl+D (Linux/macOS):",
              file=sys.stderr)
    return sys.stdin.read()


def _write_output(args: argparse.Namespace, text: str) -> None:
    if args.uitvoer is None:
        print(text)
        return
    try:
        Path(args.uitvoer).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    except OSError as exc:
        raise TekstcryptError(f"Kan '{args.uitvoer}' niet schrijven: {exc.strerror}.") from exc
    print(f"Opgeslagen in '{args.uitvoer}'.", file=sys.stderr)


def cmd_generate(args: argparse.Namespace, ask: PasswordPrompt) -> None:
    password = _ask_new_password(ask, "Wachtwoord voor het sleutelbestand") if args.beveilig else None
    key = SymmetricKey.generate()
    path = save_key(key, args.output, password, overwrite=args.overschrijf)
    status = "beveiligd met wachtwoord" if password else "ONBEVEILIGD - bewaar het bestand goed"
    print(f"Nieuwe AES-256-sleutel opgeslagen in '{path}' ({status}).")
    print(f"Vingerafdruk: {key.fingerprint}")


def cmd_fingerprint(args: argparse.Namespace, ask: PasswordPrompt) -> None:
    key = _load_key(args.sleutelbestand, ask)
    print(key.fingerprint)


def cmd_encrypt(args: argparse.Namespace, ask: PasswordPrompt) -> None:
    plaintext = _read_input(args)
    if args.sleutel:
        token = encrypt_with_key(plaintext, _load_key(args.sleutel, ask))
    else:
        token = encrypt_with_password(plaintext, _ask_new_password(ask, "Wachtwoord"))
    _write_output(args, token)


def cmd_decrypt(args: argparse.Namespace, ask: PasswordPrompt) -> None:
    token = _read_input(args)
    if message_mode(token) == MODE_KEY:
        if not args.sleutel:
            raise TekstcryptError("Dit bericht vereist een sleutelbestand: gebruik --sleutel BESTAND.")
        plaintext = decrypt(token, key=_load_key(args.sleutel, ask))
    else:
        plaintext = decrypt(token, password=ask("Wachtwoord: "))
    _write_output(args, plaintext)


def cmd_gui(args: argparse.Namespace, ask: PasswordPrompt) -> None:
    from .gui import run  # tkinter alleen laden als de GUI echt nodig is

    run()


def _add_io_arguments(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-t", "--tekst", help="tekst direct als argument (komt in je shell-geschiedenis!)")
    source.add_argument("-i", "--invoer", metavar="BESTAND", help="lees de tekst uit een bestand")
    parser.add_argument("-o", "--uitvoer", metavar="BESTAND", help="schrijf het resultaat naar een bestand")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tekstcrypt",
        description="Tekst versleutelen en ontsleutelen met AES-256-GCM.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="OPDRACHT")

    gen = sub.add_parser("genereer-sleutel", help="maak een nieuw AES-256-sleutelbestand")
    gen.add_argument("-o", "--output", required=True, metavar="BESTAND", help="pad van het sleutelbestand")
    gen.add_argument("--beveilig", action="store_true", help="versleutel het sleutelbestand met een wachtwoord")
    gen.add_argument("--overschrijf", action="store_true", help="overschrijf een bestaand bestand")
    gen.set_defaults(func=cmd_generate)

    fp = sub.add_parser("vingerafdruk", help="toon de vingerafdruk van een sleutel")
    fp.add_argument("sleutelbestand")
    fp.set_defaults(func=cmd_fingerprint)

    enc = sub.add_parser("versleutel", help="versleutel tekst")
    how = enc.add_mutually_exclusive_group(required=True)
    how.add_argument("-s", "--sleutel", metavar="BESTAND", help="gebruik een sleutelbestand")
    how.add_argument("-w", "--wachtwoord", action="store_true", help="gebruik een wachtwoord (wordt gevraagd)")
    _add_io_arguments(enc)
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("ontsleutel", help="ontsleutel tekst")
    dec.add_argument("-s", "--sleutel", metavar="BESTAND",
                     help="sleutelbestand (alleen nodig als het bericht met een sleutel is versleuteld)")
    _add_io_arguments(dec)
    dec.set_defaults(func=cmd_decrypt)

    gui = sub.add_parser("gui", help="start de grafische interface")
    gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None, *, ask_password: PasswordPrompt = getpass.getpass) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args, ask_password)
    except TekstcryptError as exc:
        print(f"Fout: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAfgebroken.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
