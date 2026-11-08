"""Eenvoudige grafische interface (Tkinter) voor tekstcrypt.

De GUI bevat zelf geen cryptografie: hij roept alleen dezelfde functies aan als
de CLI. Zo is er maar één plek waar versleuteld wordt.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText

from .crypto import MODE_KEY, decrypt, encrypt_with_key, encrypt_with_password, message_mode
from .errors import TekstcryptError
from .keys import SymmetricKey, is_protected, load_key, save_key

MODE_PASSWORD_UI = "wachtwoord"
MODE_KEYFILE_UI = "sleutel"


class TekstcryptApp(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=12)
        self.master = master
        self.key: SymmetricKey | None = None

        self.mode = tk.StringVar(value=MODE_PASSWORD_UI)
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.key_path = tk.StringVar(value="(geen sleutel geladen)")
        self.status = tk.StringVar(value="Klaar. Kies een methode, typ tekst en klik op Versleutelen.")

        self._build()
        self._on_mode_change()

    # ---------- opbouw ----------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)

        method = ttk.LabelFrame(self, text="Methode", padding=8)
        method.grid(row=0, column=0, sticky="ew")
        method.columnconfigure(1, weight=1)
        ttk.Radiobutton(method, text="Wachtwoord (Argon2id → AES-256-GCM)", value=MODE_PASSWORD_UI,
                        variable=self.mode, command=self._on_mode_change).grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Radiobutton(method, text="Sleutelbestand (willekeurige AES-256-sleutel)", value=MODE_KEYFILE_UI,
                        variable=self.mode, command=self._on_mode_change).grid(row=1, column=0, columnspan=3, sticky="w")

        ttk.Label(method, text="Wachtwoord:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.password_entry = ttk.Entry(method, textvariable=self.password, show="•")
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=(8, 0))
        self.show_check = ttk.Checkbutton(method, text="toon", variable=self.show_password,
                                          command=self._toggle_password)
        self.show_check.grid(row=2, column=2, sticky="w", pady=(8, 0))

        ttk.Label(method, text="Sleutel:").grid(row=3, column=0, sticky="w", pady=(6, 0))
        ttk.Label(method, textvariable=self.key_path, foreground="#555").grid(row=3, column=1, sticky="w", padx=6, pady=(6, 0))
        key_buttons = ttk.Frame(method)
        key_buttons.grid(row=3, column=2, sticky="e", pady=(6, 0))
        self.load_button = ttk.Button(key_buttons, text="Laden…", command=self._load_key)
        self.load_button.pack(side="left")
        self.new_button = ttk.Button(key_buttons, text="Nieuw…", command=self._new_key)
        self.new_button.pack(side="left", padx=(4, 0))

        ttk.Label(self, text="Invoer (platte tekst of versleutelde tekst):").grid(row=1, column=0, sticky="w", pady=(10, 2))
        self.input_text = ScrolledText(self, height=8, wrap="word", undo=True)
        self.input_text.grid(row=2, column=0, sticky="nsew")

        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew", pady=8)
        ttk.Button(actions, text="🔒 Versleutelen", command=self._encrypt).pack(side="left")
        ttk.Button(actions, text="🔓 Ontsleutelen", command=self._decrypt).pack(side="left", padx=6)
        ttk.Button(actions, text="↑ Uitvoer naar invoer", command=self._swap).pack(side="left")
        ttk.Button(actions, text="Wissen", command=self._clear).pack(side="right")

        ttk.Label(self, text="Uitvoer:").grid(row=4, column=0, sticky="w", pady=(0, 2))
        self.output_text = ScrolledText(self, height=8, wrap="char", state="disabled")
        self.output_text.grid(row=5, column=0, sticky="nsew")
        ttk.Button(self, text="Kopieer uitvoer", command=self._copy).grid(row=6, column=0, sticky="e", pady=(6, 0))

        ttk.Label(self, textvariable=self.status, foreground="#333", wraplength=640).grid(row=7, column=0, sticky="w", pady=(8, 0))

        self.rowconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

    # ---------- hulpfuncties ----------

    def _on_mode_change(self) -> None:
        password_mode = self.mode.get() == MODE_PASSWORD_UI
        self.password_entry.configure(state="normal" if password_mode else "disabled")
        self.show_check.configure(state="normal" if password_mode else "disabled")

    def _toggle_password(self) -> None:
        self.password_entry.configure(show="" if self.show_password.get() else "•")

    def _set_output(self, text: str) -> None:
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.configure(state="disabled")

    def _input(self) -> str:
        return self.input_text.get("1.0", "end-1c")

    def _error(self, exc: Exception) -> None:
        self.status.set(f"Fout: {exc}")
        messagebox.showerror("tekstcrypt", str(exc), parent=self.master)

    def _ask_password(self, title: str, prompt: str) -> str | None:
        return simpledialog.askstring(title, prompt, show="•", parent=self.master)

    def _set_key(self, key: SymmetricKey, path: str) -> None:
        self.key = key
        self.key_path.set(f"{Path(path).name}  ·  {key.fingerprint}")

    # ---------- sleutelbeheer ----------

    def _load_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Sleutelbestand laden", filetypes=[("Sleutelbestand", "*.key"), ("Alle bestanden", "*.*")]
        )
        if not path:
            return
        try:
            password = None
            if is_protected(path):
                password = self._ask_password("Beveiligde sleutel", "Wachtwoord van het sleutelbestand:")
                if password is None:
                    return
            self._set_key(load_key(path, password), path)
            self.mode.set(MODE_KEYFILE_UI)
            self._on_mode_change()
            self.status.set("Sleutel geladen. Vergelijk de vingerafdruk met je gesprekspartner.")
        except TekstcryptError as exc:
            self._error(exc)

    def _new_key(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Nieuwe sleutel opslaan", defaultextension=".key",
            filetypes=[("Sleutelbestand", "*.key")], initialfile="mijn-sleutel.key",
        )
        if not path:
            return
        password = None
        if messagebox.askyesno("Sleutel beveiligen",
                               "Wil je het sleutelbestand beveiligen met een wachtwoord?\n"
                               "(Aanbevolen: zonder wachtwoord kan iedereen met het bestand ontsleutelen.)",
                               parent=self.master):
            password = self._ask_password("Wachtwoord", "Kies een wachtwoord (min. 8 tekens):")
            if password is None:
                return
            if self._ask_password("Wachtwoord", "Herhaal het wachtwoord:") != password:
                self._error(TekstcryptError("De wachtwoorden komen niet overeen."))
                return
        try:
            key = SymmetricKey.generate()
            # De opslagdialoog heeft al om bevestiging gevraagd bij overschrijven.
            save_key(key, path, password, overwrite=True)
            self._set_key(key, path)
            self.mode.set(MODE_KEYFILE_UI)
            self._on_mode_change()
            self.status.set(f"Nieuwe sleutel opgeslagen in {path}.")
        except TekstcryptError as exc:
            self._error(exc)

    # ---------- acties ----------

    def _encrypt(self) -> None:
        try:
            if self.mode.get() == MODE_PASSWORD_UI:
                token = encrypt_with_password(self._input(), self.password.get())
            else:
                if self.key is None:
                    raise TekstcryptError("Laad of maak eerst een sleutelbestand.")
                token = encrypt_with_key(self._input(), self.key)
            self._set_output(token)
            self.status.set("Versleuteld met AES-256-GCM. De uitvoer is veilig om te delen.")
        except TekstcryptError as exc:
            self._error(exc)

    def _decrypt(self) -> None:
        try:
            token = self._input()
            if message_mode(token) == MODE_KEY:
                if self.key is None:
                    raise TekstcryptError("Dit bericht is met een sleutelbestand versleuteld. Laad eerst die sleutel.")
                plaintext = decrypt(token, key=self.key)
            else:
                plaintext = decrypt(token, password=self.password.get())
            self._set_output(plaintext)
            self.status.set("Ontsleuteld en geverifieerd: de tekst is niet aangepast.")
        except TekstcryptError as exc:
            self._error(exc)

    def _swap(self) -> None:
        text = self.output_text.get("1.0", "end-1c")
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        self._set_output("")

    def _clear(self) -> None:
        self.input_text.delete("1.0", "end")
        self._set_output("")
        self.password.set("")
        self.status.set("Gewist.")

    def _copy(self) -> None:
        self.master.clipboard_clear()
        self.master.clipboard_append(self.output_text.get("1.0", "end-1c"))
        self.status.set("Uitvoer gekopieerd naar het klembord.")


def run() -> None:
    root = tk.Tk()
    root.title("tekstcrypt – AES-256-GCM")
    root.geometry("720x640")
    root.minsize(560, 520)
    TekstcryptApp(root).pack(fill="both", expand=True)
    root.mainloop()


if __name__ == "__main__":
    run()
