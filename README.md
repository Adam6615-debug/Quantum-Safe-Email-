# Quantum-Safe Email Encryption Platform

A CLI desktop tool that sends and receives **real Gmail messages** whose
bodies are encrypted with **post-quantum hybrid cryptography
(RSA-2048 + ML-KEM-768 + AES-256-GCM)** and signed with **ML-DSA-65**.
All keys live in a local SQLite database — no cloud, no key server.

> Course: **CET334 — Cryptographic Algorithms & Protocols**
> Project type: group submission, three modules + integration layer.

---

## Team Members

| Member | Module | Files |
|---|---|---|
| Member 1 | Cryptographic Engine | [`member1_crypto/`](member1_crypto/) |
| Member 2 | Key Storage & Threat Analysis | [`member2_keystore/`](member2_keystore/) |
| Member 3 | Email Integration & CLI | [`member3_email/`](member3_email/) + [`main.py`](main.py) |

Each module is **self-contained and independently runnable** so each team
member can develop and test in isolation before merging.

---

## What This Does

The tool replaces the body of an outgoing email with a JSON attachment
(`encrypted_payload.qep`) that is wrapped twice — once with classical
RSA-2048-OAEP and once with the NIST-standardized post-quantum KEM
ML-KEM-768. The two resulting secrets are mixed via HKDF-SHA-256 and
used to derive an AES-256-GCM session key. The serialized payload is then
signed with ML-DSA-65 so the receiver can verify both **integrity** and
**authenticity**, even against an adversary with a future quantum computer.

When a recipient opens the email with this tool, the `.qep` attachment
is decapsulated, the AES key is reconstructed, the body is decrypted,
and the signature is checked. **Every byte transported on the wire is
already post-quantum confidential and post-quantum authenticated.**

---

## Security Architecture

```
                        ┌──────────────────────────────┐
                        │  random 32-byte seed         │
                        └──────────────┬───────────────┘
                                       │
              RSA-2048-OAEP-SHA256 ◄───┴───►  ML-KEM-768.encap
                       │                              │
                rsa_ciphertext                  mlkem_ciphertext
                                                      │
                                              shared_secret (32 B)
                                                      │
                              HKDF-SHA-256(seed ‖ shared_secret)
                                                      │
                                          AES-256 session key
                                                      │
                              AES-256-GCM(message)  →  ciphertext + tag

      JSON-encode payload  ─►  ML-DSA-65.sign  ─►  signature
```

* **Hybrid wrap.** The seed is dual-encrypted; an attacker must break
  *both* RSA-2048 *and* ML-KEM-768 (i.e. both classical and post-quantum
  primitives) to recover the AES key. This is **defence in depth**:
  if RSA falls to a future CRQC the ML-KEM lattice problem still holds.
* **Authenticated encryption.** AES-256-GCM provides confidentiality and
  message-tag integrity — bit-flips in transit are detected.
* **Signatures.** Every payload is signed with **ML-DSA-65** (NIST FIPS 204).
  A valid signature proves the payload was sealed by the holder of the
  matching private key — which prevents a man-in-the-middle from swapping
  out the encrypted body.
* **TOFU key exchange.** First emails carry a `sender_keys.qpk`
  attachment; the receiving client offers to import the keys
  (Trust-On-First-Use), so no out-of-band key server is required.

---

## Requirements

* **Python 3.10+** (tested on 3.10, 3.11, 3.12, 3.14)
* **Linux, macOS, or Windows 10/11**
* A **Gmail account with App Passwords enabled** (for SMTP + IMAP)
* ~10 MB of disk for dependencies; the SQLite key DB is <100 KB

---

## Installation

```bash
# 1. Clone (or download) and cd in
git clone <your repo URL>
cd quantum_email

# 2. (Recommended) virtualenv
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows PowerShell

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure Gmail credentials
cp .env.example .env                # then edit .env
```

### Post-quantum library notes (`liboqs` / `oqs`)

`requirements.txt` requests the official Open Quantum Safe binding
(`liboqs-python`) on non-Windows platforms because it requires the
liboqs C library which is non-trivial to build on Windows.

The crypto engine is designed to work either way:

* **If the real `oqs` binding is importable**, it is used directly.
* **Otherwise**, the engine falls back to the pure-Python reference
  implementations
  [`kyber-py`](https://pypi.org/project/kyber-py/) and
  [`dilithium-py`](https://pypi.org/project/dilithium-py/)
  of the *same* standardized algorithms (FIPS 203 / FIPS 204).

You don't have to do anything to enable the fallback — it kicks in
automatically. The functional behaviour is identical.

### Gmail App Password setup

1. Enable 2-Step Verification on your Google account.
2. Visit <https://myaccount.google.com/apppasswords>, generate a
   16-character app password, and paste it into `.env` as
   `EMAIL_APP_PASSWORD`. (Spaces are fine; Gmail strips them.)

---

## Usage — Step by Step

### First Time Setup
```bash
python main.py setup
```
Generates fresh RSA-2048, ML-KEM-768 and ML-DSA-65 keypairs and writes
them to `keys.db`. Re-run with `--force` to rotate.

### Exporting Your Keys
```bash
python main.py export-keys
```
Prints your public-key bundle and writes `my_public_keys.json`. Send this
JSON to a contact so they can encrypt mail to you.

### Adding a Contact
```bash
python main.py add-contact --email alice@gmail.com --keys alice_keys.json
```
You can also let TOFU handle this automatically — see below.

### Sending an Encrypted Email
```bash
python main.py send \
    --to alice@gmail.com \
    --subject "Quantum-safe ping" \
    --message "Hello Alice!  This body is post-quantum encrypted."
```
By default your public-key bundle is also attached so the recipient can
TOFU-import it on first contact. Pass `--no-tofu` to suppress.

### Receiving and Decrypting
```bash
python main.py receive --limit 5
```
Fetches up to five unread inbox messages, parses any `.qep` attachments,
decrypts and verifies each. If a `.qpk` bundle is found and the sender
isn't yet in your contacts, you will be prompted:

```
🔑 New contact detected: alice@gmail.com - this email includes a public-key bundle.
Import quantum-safe public keys for alice@gmail.com? [y/N]:
```

After verification successes you see:

```
🔐 [QUANTUM-VERIFIED] From: alice@gmail.com
```

Use `--auto-tofu` to skip the prompt in scripted demos.

### Listing & Deleting Contacts
```bash
python main.py list-contacts
python main.py delete-contact --email alice@gmail.com
```
TOFU-imported contacts are tagged with `🔑 [TOFU]`.

### Running Threat Analysis
```bash
python main.py threat-report --sensitivity 8 --key-age-days 90
```
Prints a colour-coded report explaining the quantum-threat posture of
each primitive plus a Harvest-Now/Decrypt-Later risk score.

### Running Tests
```bash
# Module unit tests (no email required)
python member1_crypto/crypto_engine.py
python member2_keystore/key_store.py
python member2_keystore/threat_analyzer.py

# Full local end-to-end test (no email sent)
python main.py test

# Live SMTP/IMAP probe (requires .env)
python member3_email/email_handler.py
```

---

## Bonus Feature — TOFU Auto Key Exchange

**Trust-On-First-Use** removes the friction of manual key swaps. Every
outgoing email automatically attaches the sender's three public keys as
a JSON file named `sender_keys.qpk`. When the recipient opens the
email:

1. The client notices `sender_keys.qpk` and that the sender is unknown.
2. The CLI asks **once** whether to trust those keys.
3. On confirmation the keys are stored in the `contacts` table with
   `tofu_verified = 1`.
4. From then on the client can encrypt back to that sender without any
   out-of-band exchange — the same model Signal, iMessage and recent
   email PQC drafts use.

TOFU contacts show up in `list-contacts` flagged with `🔑 [TOFU]`.

---

## NIST Standards Used

| Standard | Algorithm | Purpose |
|---|---|---|
| **FIPS 203** | ML-KEM-768 | Post-quantum key encapsulation (was Kyber) |
| **FIPS 204** | ML-DSA-65  | Post-quantum digital signatures (was Dilithium) |
| **FIPS 197** | AES-256    | Symmetric authenticated encryption (with GCM) |
| **RFC 8017** | RSA-OAEP-SHA256 | Classical key wrap (hybrid component) |
| **RFC 5869** | HKDF-SHA-256 | Key derivation from (RSA seed ‖ ML-KEM secret) |

---

## Project Structure

```
quantum_email/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── setup.py                       (optional bootstrap helper)
│
├── member1_crypto/
│   ├── __init__.py
│   └── crypto_engine.py           ← Member 1's deliverable
│
├── member2_keystore/
│   ├── __init__.py
│   ├── key_store.py               ← Member 2's deliverable (storage)
│   └── threat_analyzer.py         ← Member 2's deliverable (analysis)
│
├── member3_email/
│   ├── __init__.py
│   └── email_handler.py           ← Member 3's deliverable
│
├── main.py                        ← CLI integration (all three members)
└── keys.db                        ← Auto-created SQLite database
```
