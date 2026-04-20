# vault – a simple encrypted password manager  

**Version:** 1.0 (first public release)  
**Author:** Jose J. Cintron – <mailto:l0rddarkr0ce@hotmail.com>  

*Store your site credentials safely in a locally-encrypted JSON vault, protected by a master password hashed with Argon2id.*

---  

## Table of Contents  

1. [Overview](#overview)  
2. [Features](#features)  
3. [Prerequisites](#prerequisites)  
4. [Installation](#installation)  
5. [Quick start (JSON backend)](#quick-start-json-backend)  
6. [Using SQLite (optional future release)](#using-sqlite-optional-future-release)  
7. [Command-line interface](#command-line-interface)  
8. [Configuration & files](#configuration--files)  
9. [Testing](#testing)  
10. [Contributing](#contributing)  
11. [License & attribution](#license--attribution)  
12. [Acknowledgements](#acknowledgements)  

---  

## Overview  

`vault.py` is a **single-file CLI tool** that lets you safely store usernames/passwords for any number of services.  

* The master password is never written to disk – only a **salted Argon2id hash** is stored.  
* Each entry is encrypted with a **Fernet token** whose key is derived from the master password using **PBKDF2-HMAC-SHA256**.  
* An **HMAC-SHA256** tag is calculated over the whole database (excluding the tag itself) to detect tampering.  

The current release stores the data in a **human-readable JSON file** (`passwords.json` by default).  A future release will optionally support an SQLite backend, but the JSON format is fully functional and portable.

---  

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

## Prerequisites  

* **Python 3.8+** (type-hints and `from __future__ import annotations` are used).  
* **argon2-cffi** – Argon2id implementation (`pip install argon2-cffi`).  
* **cryptography** – Fernet encryption (`pip install cryptography`).  
* Standard library modules (`argparse`, `json`, `logging`, …) which require no extra installation.  

All dependencies are **Apache-2.0** licensed and are listed in the `NOTICE` file.

---  

## Installation  

```bash
# 1️⃣ Clone the repository
git clone https://github.com/your-name/vault.git
cd vault

# 2️⃣ (optional) create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3️⃣ Install runtime dependencies
pip install -r requirements.txt
# requirements.txt contains:
#   argon2-cffi
#   cryptography