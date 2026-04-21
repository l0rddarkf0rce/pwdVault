# vault.py — A Minimal, Secure, No‑Nonsense CLI Password Manager

**Version:** 1.0 (first public release)  
**Author:** Jose J. Cintron – <l0rddarkr0ce@yahoo.com>  

*Store your site credentials safely in a locally-encrypted JSON vault, protected by a master password hashed with Argon2id.*

`vault.py` is a compact, security‑first password manager designed for people who prefer simple tools, transparent cryptography, and zero cloud dependencies. Everything lives in a single JSON file, encrypted locally, protected by modern algorithms, and wrapped in a clean CLI.

It’s built for developers, tinkerers, and anyone who wants a lightweight alternative to heavyweight password vaults — without compromising on security.

* The master password is never written to disk – only a **salted Argon2id hash** is stored.  
* Each entry is encrypted with a **Fernet token** whose key is derived from the master password using **PBKDF2-HMAC-SHA256**.  
* An **HMAC-SHA256** tag is calculated over the whole database (excluding the tag itself) to detect tampering.

---

## ✨ Features at a Glance

## Features  

| ✅ | Feature |
|---|---------|
| ✅ | Master-password protection with Argon2id (memory-hard, time-hard). |
| ✅ | Per-site encryption using Fernet (AES-128-CBC + HMAC-SHA256). |
| ✅ | Automatic integrity protection with HMAC-SHA256. |
| ✅ | Atomic writes – the vault is never left in a partially-written state. |
| ✅ | Interactive REPL mode (no flags required). |
| ✅ | Full CLI (add, change, delete, list, print). |
| ✅ | Clear, colour-free UI output (pure `logging`). |
| ✅ | Easy migration from legacy SHA-256 master-hash (already removed). |
| ✅ | Simple, pip-installable dependencies only. |

---

## 🔐 Security Architecture

This project intentionally avoids “magic.” Every cryptographic step is explicit and inspectable.

### Master Password
- Hashed with Argon2id  
- Parameters:
  - `m=102400 KiB` (~100 MiB)
  - `t=2`
  - `p=8`
- Salt stored as URL‑safe Base64

### Per‑Entry Encryption
Each password entry uses:
- A random 16‑byte salt  
- PBKDF2‑HMAC‑SHA256 with 300,000 iterations  
- Derived key fed into Fernet for authenticated encryption  

### Vault Integrity
To detect tampering:
- A vault‑wide HMAC‑SHA256 is computed over the JSON (minus the `hmac` field)
- HMAC key derived from the master password + a dedicated salt
- Verification happens on every load

### Atomic Writes
Saving the vault:
1. Write to a temp file  
2. Flush + `fsync()`  
3. Atomically rename into place  

This prevents partial writes or corruption during crashes.

---

## Prerequisites  

* **Python 3.8+** (type-hints and `from __future__ import annotations` are used).  
* **argon2-cffi** – Argon2id implementation (`pip install argon2-cffi`).  
* **cryptography** – Fernet encryption (`pip install cryptography`).  
* Standard library modules (`argparse`, `json`, `logging`, …) which require no extra installation.  

All dependencies are **Apache-2.0** licensed and are listed in the `NOTICE` file.

---

## 📦 Installation

Requires Python 3.8+ and a few dependencies:

```bash
pip install argon2-cffi cryptography
```

Clone or drop `vault.py` anywhere — it’s fully self‑contained.

---

## 🚀 Usage

Run directly:

```bash
python vault.py
```

Or as a module:

```bash
python -m vault
```

The first run will prompt you to create a master password.

---

## 🛠️ Command‑Line Options

### Add a new entry
```bash
python -m vault -a example.com
```

### List all stored sites
```bash
python -m vault -l
```

### Print credentials for a site
```bash
python -m vault -p example.com
```

### Change an existing entry
```bash
python -m vault -c example.com
```

### Delete an entry
```bash
python -m vault -d example.com
```

### Force interactive mode
```bash
python -m vault -P
```

---

## 💬 Interactive Mode (REPL)

Running the script with no arguments launches a simple menu‑driven interface:

- View stored sites  
- Add new credentials  
- Change existing ones  
- Delete entries  
- Quit  

It’s intentionally minimal — fast, keyboard‑friendly, and easy to use.

---

## 📁 Vault File Format

The vault is a JSON file containing:

```json
{
  "masterHash": "...",
  "masterSalt": "...",
  "hmacSalt": "...",
  "hmac": "...",
  "passwords": [
    {
      "site": "example.com",
      "username": "alice",
      "pwd": "<fernet token>",
      "salt": "<per-entry salt>"
    }
  ]
}
```

All sensitive fields are URL‑safe Base64.

---

## 🧱 Project Structure

- **CryptoHelper** — Argon2id, PBKDF2, Fernet, HMAC  
- **MasterPasswordManager** — creation + verification  
- **VaultIO** — load/save, atomic writes, base64 normalization  
- **VaultEntry** — dataclass for individual credentials  
- **Vault** — CRUD operations + integrity checks  
- **Cli** — argument parsing, interactive mode, user prompts  
- **main()** — entrypoint  

---

## 📝 License

Apache‑2.0  
See the SPDX header for details.

---

## 🙌 Final Notes

This project is intentionally small but built with serious cryptographic hygiene. It’s perfect for:

- Developers who want a transparent, inspectable password manager  
- Security‑minded users who prefer local‑only tools  
- Anyone learning about practical cryptography in Python
