# tekstcrypt: tekst versleutelen met AES-256-GCM

**Opdracht:** Symmetrische encryptie-applicatie (Werkplaats Security)

`tekstcrypt` is een Python-applicatie waarmee je tekst kunt versleutelen en ontsleutelen, via de command-line (CLI) of via een grafische interface (GUI). Alle cryptografie komt uit de bekende library [`cryptography`](https://cryptography.io). Ik heb zelf geen cryptografisch algoritme geschreven (*don't roll your own crypto*).

![Screenshot van de GUI](docs/gui.png)

## Inhoud

1. [Installatie en gebruik](#1-installatie-en-gebruik)
2. [Hoe de applicatie werkt](#2-hoe-de-applicatie-werkt)
3. [Onderzoek: symmetrisch en asymmetrisch](#3-onderzoek-symmetrisch-en-asymmetrisch)
4. [Gekozen algoritme: AES-256-GCM](#4-gekozen-algoritme-aes-256-gcm)
5. [Sleutelbeheer](#5-sleutelbeheer)
6. [Reflectie op Kerckhoffs's principe](#6-reflectie-op-kerckhoffss-principe)
7. [Beperkingen](#7-beperkingen)
8. [Tests](#8-tests)
9. [Bronnen](#9-bronnen)

---

## 1. Installatie en gebruik

Vereist: Python 3.10 of hoger.

```bash
git clone https://github.com/Yavuz-1073705/tekstcrypt.git
cd tekstcrypt
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

**GUI:** `python -m tekstcrypt gui`. Kies *Wachtwoord* of *Sleutelbestand* (*Nieuw…* maakt een sleutel, *Laden…* opent er een), typ tekst en klik op **Versleutelen** of **Ontsleutelen**. De app ziet zelf met welke methode een bericht is versleuteld.

**CLI:**

```text
> python -m tekstcrypt genereer-sleutel -o alice-bob.key --beveilig
Nieuwe AES-256-sleutel opgeslagen in 'alice-bob.key' (beveiligd met wachtwoord).
Vingerafdruk: 01DA-C562-D1C9-FF5D-C83A-5DB0-4EFC-905C

> python -m tekstcrypt versleutel -s alice-bob.key -t "Hallo docent!"
AQEB2sVi0cn_XRgQZaPs76aRvShk1-9cGb_qw3yuSlHiExIqP4yWQtCywsBPwx4kaSeo

> python -m tekstcrypt ontsleutel -s alice-bob.key -t AQEB2sVi0cn_XRgQ...
Hallo docent!

> python -m tekstcrypt versleutel --wachtwoord -i geheim.txt -o geheim.enc
```

Wachtwoorden worden altijd gevraagd en nooit als argument meegegeven, want argumenten komen in je shell-geschiedenis.

---

## 2. Hoe de applicatie werkt

```text
tekstcrypt/
├── crypto.py   AES-256-GCM versleutelen/ontsleutelen en het berichtformaat
├── kdf.py      Argon2id: sleutel afleiden uit een wachtwoord
├── keys.py     sleutelbeheer: genereren, opslaan, laden, vingerafdruk
├── errors.py   eigen foutmeldingen
├── cli.py      command-line interface
└── gui.py      grafische interface (Tkinter)
```

CLI en GUI bevatten zelf geen cryptografie: ze roepen dezelfde functies aan. Zo zit de gevoelige logica op één plek, en die is goed te testen.

Er zijn **twee manieren** om te versleutelen:

- **Sleutelbestand:** een willekeurige 256-bit sleutel. Altijd maximaal sterk, maar het bestand moet veilig bij de ontvanger komen.
- **Wachtwoord:** de sleutel wordt met Argon2id uit het wachtwoord afgeleid. Er hoeft niets te worden verstuurd, maar het is zo sterk als het wachtwoord.

**Versleutelen** gaat zo: de tekst wordt UTF-8, er komt een nieuwe willekeurige nonce bij, en AES-256-GCM maakt de ciphertext plus een authenticatietag. Het resultaat is één regel tekst (base64url) die je kunt kopiëren:

| versie | modus | key-id *of* salt + Argon2id-parameters | nonce (12 B) | ciphertext | tag (16 B) |
|---|---|---|---|---|---|

Alles vóór de nonce (de *header*) is niet geheim, maar gaat als *associated data* mee in GCM. Daardoor kan niemand de header ongemerkt aanpassen. Bij **ontsleutelen** controleert GCM eerst de tag. Is er één bit veranderd of is de sleutel fout, dan weigert de app het bericht.

---

## 3. Onderzoek: symmetrisch en asymmetrisch

**Symmetrische encryptie** gebruikt **één gedeelde geheime sleutel** om te versleutelen en te ontsleutelen (bijvoorbeeld AES of ChaCha20). Het is heel snel en werkt met korte sleutels (128 tot 256 bit). Het grote nadeel is het **sleuteldistributieprobleem**: beide partijen moeten de sleutel al hebben voordat ze veilig kunnen communiceren.

**Asymmetrische encryptie** (Diffie-Hellman 1976, RSA 1977, elliptische krommen) geeft elke gebruiker een **publieke sleutel** en een **privésleutel**. Iedereen kan met je publieke sleutel versleutelen, maar alleen jij kunt ontsleutelen. Daarmee is het distributieprobleem grotendeels opgelost en zijn digitale handtekeningen mogelijk. Het is wel veel trager en heeft langere sleutels nodig (RSA-3072 is ongeveer even sterk als AES-128).

| | Symmetrisch | Asymmetrisch |
|---|---|---|
| Sleutels | 1 gedeeld geheim | publiek + privé per gebruiker |
| Snelheid | zeer snel | traag |
| Sleutels voor *n* gebruikers | *n(n−1)/2* | *2n* |
| Grootste probleem | sleutel veilig uitwisselen | echtheid van publieke sleutels |

In de praktijk worden ze **gecombineerd (hybride)**: TLS, Signal en SSH spreken met asymmetrische cryptografie een symmetrische sessiesleutel af en versleutelen de data daarna met AES-GCM of ChaCha20.

**Belangrijke principes:**

- **Kerckhoffs's principe (1883):** een systeem moet veilig zijn, ook als alles behalve de sleutel bekend is. Shannon zei later: *"the enemy knows the system"*. Zie hoofdstuk 6.
- **Geen security through obscurity:** geheime algoritmen zoals CSS (dvd), A5/1 (GSM) en Crypto-1 (OV-chipkaart) werden gebroken zodra ze werden ontleed.
- **Confusion en diffusion (Shannon, 1949):** de relatie tussen sleutel en ciphertext moet ingewikkeld zijn, en een kleine wijziging moet zich over de hele uitvoer verspreiden.
- **Encryptie is niet genoeg:** voor integriteit en authenticiteit is een MAC of een AEAD-modus nodig.
- **Don't roll your own crypto:** het gaat vaak mis in de details (nonce-hergebruik, padding-oracles, zwakke random). Daarom gebruik ik alleen een bewezen library.

---

## 4. Gekozen algoritme: AES-256-GCM

**AES** is sinds 2001 de wereldstandaard (NIST FIPS 197). Het is gekozen via een open competitie, al meer dan twintig jaar onderzocht zonder praktische aanval, en snel dankzij hardware-ondersteuning (AES-NI).

**256 bit in plaats van 128:** AES-128 is nu ook veilig, maar quantumcomputers (het algoritme van Grover) halveren in theorie de effectieve sleutellengte. AES-256 houdt dan nog ~128 bit over. De extra rekentijd is voor tekstberichten verwaarloosbaar.

**GCM-modus:** de modus bepaalt hoe AES langere teksten versleutelt, en die keuze is net zo belangrijk.

| Modus | Geheim | Beschermd tegen aanpassen | Opmerking |
|---|---|---|---|
| ECB | ✗ | ✗ | identieke blokken geven identieke ciphertext, nooit gebruiken |
| CBC | ✓ | ✗ | aparte HMAC nodig, anders padding-oracle-aanvallen |
| **GCM** | ✓ | ✓ | **AEAD**: versleutelt en authenticeert in één stap |

GCM heeft per bericht een **unieke nonce** nodig. Twee keer dezelfde nonce met dezelfde sleutel breekt GCM volledig. Daarom krijgt elk bericht een nieuwe willekeurige nonce van 96 bit (`os.urandom(12)`).

**Alternatief:** ChaCha20-Poly1305 is even veilig en sneller zonder AES-hardware. Ik koos AES omdat de opdracht dat vraagt en AES-NI op laptops vrijwel altijd aanwezig is.

**Wachtwoorden: Argon2id.** Een wachtwoord is geen geschikte sleutel: te kort en te voorspelbaar. Argon2id (RFC 9106) maakt er een 256-bit sleutel van:

- 64 MiB geheugen, 3 iteraties, 4 lanes: ruim boven het OWASP-minimum. Eén poging kost ~0,1 s en veel geheugen, wat brute-force met GPU's sterk afremt.
- Elk bericht krijgt een nieuwe **salt** van 128 bit. Hetzelfde wachtwoord geeft dus steeds een andere sleutel, en rainbow tables werken niet.
- De parameters staan in het bericht (zodat ze later kunnen worden verhoogd), maar met **bovengrenzen**. Anders kan een aanvaller een bericht maken dat gigabytes geheugen vraagt.
- Wachtwoorden moeten minstens 8 tekens hebben.

---

## 5. Sleutelbeheer

### Generatie

De sleutel bestaat uit 256 bits uit de **veilige random-generator van het besturingssysteem** (`AESGCM.generate_key`, wat `os.urandom` gebruikt). Nooit uit Python's `random`-module of een tijdstempel.

Elke sleutel krijgt een **key-id** en een **vingerafdruk** (beide afgeleid met SHA-256). Die verraden niets over de sleutel zelf.

- De key-id staat in elk bericht, zodat de app meteen kan zeggen: *"dit bericht is met een andere sleutel versleuteld"*.
- Met de vingerafdruk (bijvoorbeeld `01DA-C562-…`) kunnen twee mensen via de telefoon controleren of ze dezelfde sleutel hebben.

In de wachtwoordmodus wordt de sleutel nooit opgeslagen. Hij wordt elke keer opnieuw afgeleid.

### Opslag

Sleutels worden opgeslagen in een JSON-bestand (`*.key`). Dat kan op twee manieren:

- **Onbeveiligd:** wie het bestand heeft, kan alles lezen. De CLI waarschuwt hiervoor.
- **Beveiligd met wachtwoord (aanbevolen, `--beveilig`):** de sleutel wordt zelf versleuteld (*key wrapping*). Met Argon2id wordt uit het wachtwoord een hulpsleutel gemaakt, en daarmee wordt de echte sleutel met AES-256-GCM versleuteld. Wie het bestand steelt, moet dus nog het wachtwoord kraken.

Extra maatregelen:
- Een bestaande sleutel wordt nooit per ongeluk overschreven, want dan ben je al je berichten kwijt.
- Het bestand krijgt rechten "alleen eigenaar" (`0600`).
- `*.key` staat in `.gitignore`, zodat sleutels niet in een repository belanden.
- De sleutel verschijnt nooit in foutmeldingen of logs.

### Uitwisseling

Dit is het kernprobleem van symmetrische encryptie: **de app kan de sleutel niet zelf veilig versturen.** Als de sleutel over hetzelfde kanaal gaat als de berichten, kan een afluisteraar hem ook onderscheppen. De uitwisseling gebeurt daarom buiten de app om, via twee kanalen:

1. Alice maakt een **beveiligde** sleutel en stuurt het bestand via kanaal A (bijvoorbeeld e-mail). Onderscheppen levert alleen een versleutelde sleutel op.
2. Ze geeft het wachtwoord via kanaal B (telefoon of persoonlijk).
3. Ze vergelijken de **vingerafdruk**. Zo weten ze dat niemand het bestand onderweg heeft vervangen (man-in-the-middle).

Bij de wachtwoordmodus spreken ze vooraf persoonlijk een sterke wachtzin af.

### Beveiligingsimplicaties

| Risico | Gevolg | Maatregel |
|---|---|---|
| Sleutel lekt uit | Alle berichten met die sleutel zijn leesbaar, ook oude | Wachtwoordbeveiliging, `.gitignore`, sleutels af en toe vervangen |
| Zwak wachtwoord | Onderschepte berichten zijn offline te kraken | Argon2id en minimale lengte. Een sterk wachtwoord blijft de taak van de gebruiker |
| Sleutel onderweg vervangen | Aanvaller leest mee | Vingerafdruk via een tweede kanaal controleren |
| Bericht aangepast | Gemanipuleerde inhoud | GCM-tag detecteert dit altijd |
| Geen handtekening | Iedereen met de sleutel kan een bericht maken; je kunt niet bewijzen wie het stuurde | Inherent aan symmetrisch; hiervoor is asymmetrische crypto nodig |

### Het probleem bij veel gebruikers

Elk paar gebruikers heeft een eigen sleutel nodig, anders kan C de berichten tussen A en B lezen. Dat zijn **n(n−1)/2** sleutels: 45 bij 10 gebruikers, 4.950 bij 100 en bijna 500.000 bij 1.000. Elke sleutel moet veilig worden uitgewisseld, bewaard, vervangen en ingetrokken. Bij veel gebruikers is dat **praktisch onbeheersbaar**. Deze app is daarom bedoeld voor een klein aantal vaste partners.

In de praktijk wordt dit opgelost met:
- **asymmetrische/hybride cryptografie**: elke gebruiker één sleutelpaar, en per gesprek wordt een sessiesleutel afgesproken (zoals in Signal en TLS);
- **een centrale sleutelserver** zoals Kerberos;
- **sleutelbeheerdiensten** zoals AWS KMS of Azure Key Vault.

Een logische uitbreiding van deze app is X25519-sleuteluitwisseling, zodat je de sleutel niet meer handmatig hoeft te delen.

---

## 6. Reflectie op Kerckhoffs's principe

> *"Een versleutelingssysteem moet veilig zijn, zelfs als alle details van het systeem, behalve de sleutel, publiek bekend zijn."*

Bij `tekstcrypt` is echt alles behalve de sleutel openbaar:
- de broncode staat op GitHub;
- het algoritme (AES-256-GCM), de KDF (Argon2id) en de library staan in deze README;
- het berichtformaat is beschreven;
- elk bericht bevat zelfs onversleuteld de salt, de nonce, de key-id en de Argon2id-parameters.

Toch kan een aanvaller met al die kennis en een onderschept bericht er niets mee:
- In de sleutelbestand-modus moet hij 2²⁵⁶ sleutels proberen. Dat is onmogelijk.
- In de wachtwoordmodus moet hij het wachtwoord raden, en elke poging kost veel tijd en geheugen.
- Het bericht aanpassen lukt ook niet, want de GCM-tag ontdekt dat.

De **enige** geheime informatie is de sleutel of het wachtwoord. Precies wat Kerckhoffs bedoelde. Salt, nonce en parameters hoeven niet geheim te zijn, alleen uniek of willekeurig.

**Waarom dit beter is dan geheimhouding:** had ik een eigen "geheim" algoritme bedacht, dan was alles gebroken zodra iemand de code bekijkt, en had ik het hele algoritme moeten vervangen in plaats van alleen een sleutel. Door een openbaar standaardalgoritme te gebruiken, profiteer ik van twintig jaar onderzoek door duizenden experts. Openheid is hier geen risico maar een bron van vertrouwen.

**Kanttekeningen:**
- Kerckhoffs legt al het gewicht op de sleutel. Een onbeveiligd sleutelbestand op een gedeelde pc maakt AES-256 waardeloos. Daarom is sleutelbeheer zo belangrijk.
- In de wachtwoordmodus *is* het wachtwoord de sleutel. Argon2id vertraagt een aanvaller, maar `welkom123` blijft makkelijk te raden.
- Ik vertrouw erop dat `cryptography`/OpenSSL AES correct implementeert. Dat past bij Kerckhoffs: een openbare, veel gecontroleerde implementatie is betrouwbaarder dan iets wat ik zelf schrijf.

**Conclusie:** `tekstcrypt` voldoet aan Kerckhoffs's principe. De veiligheid hangt alleen af van de sleutel. De echte uitdaging verschuift daarmee naar het sleutelbeheer, en dat is bij veel gebruikers zonder asymmetrische cryptografie vrijwel niet op te lossen.

---

## 7. Beperkingen

- De lengte van een bericht is zichtbaar (de ciphertext is 38 of 52 bytes langer dan de tekst).
- Python kan sleutels niet betrouwbaar uit het werkgeheugen wissen.
- Gekopieerde tekst blijft op het klembord staan, en `-t "tekst"` komt in de shell-geschiedenis. Gebruik voor gevoelige tekst liever `-i bestand`.
- Op Windows hebben de `0600`-rechten weinig effect. Daar beschermen de standaardrechten van de gebruikersmap het bestand.
- Er is geen *forward secrecy*: een gelekte sleutel ontsleutelt ook oude berichten.

---

## 8. Tests

```bash
python -m pytest -v
```

De **53 tests** controleren onder andere:
- dat versleutelen en ontsleutelen werkt, ook met emoji, lege tekst en lange tekst;
- dat dezelfde tekst twee keer een andere ciphertext geeft;
- dat een verkeerde sleutel of een verkeerd wachtwoord wordt geweigerd;
- dat een aangepaste bit, header of key-id wordt ontdekt;
- dat kwaadaardige parameters en ongeldige invoer worden afgevangen;
- het opslaan en laden van (beveiligde) sleutelbestanden;
- de volledige CLI.

---

## 9. Bronnen

- Kerckhoffs, A. (1883). La cryptographie militaire. *Journal des sciences militaires*, IX, 5–38, 161–191.
- Shannon, C. E. (1949). Communication theory of secrecy systems. *Bell System Technical Journal*, 28(4), 656–715.
- Diffie, W., & Hellman, M. (1976). New directions in cryptography. *IEEE Transactions on Information Theory*, 22(6), 644–654.
- NIST. (2001, bijgewerkt 2023). *FIPS 197: Advanced Encryption Standard (AES)*.
- Dworkin, M. (2007). *NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC*. NIST.
- Barker, E. (2020). *NIST SP 800-57 Part 1 Rev. 5: Recommendation for key management*. NIST.
- Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021). *RFC 9106: Argon2*. IETF.
- OWASP Foundation. (z.d.). *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Python Cryptographic Authority. (z.d.). *cryptography documentation*. https://cryptography.io
