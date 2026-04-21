#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jose J. Cintron
# SPDX-License-Identifier: Apache-2.0
"""
    Program name: vault.py
    Version: 1.0
    Date Created: 2026/02/07
    Author: Jose J. Cintron
    E-mail: l0rddarkr0ce@yahoo.com
    
Description:
    A small CLI password manager that stores encrypted credentials in a
    JSON file. The file is protected by a master password that is hashed
    with Argon2id and each individual entry is encrypted with a Fernet
    key derived from the same master password via PBKDF2-HMAC-SHA256.

    The script also computes an HMAC-SHA256 over the whole file
    (excluding the HMAC field itself) to detect tampering.

Typical usage::
    $ python -m vault -a example.com
    $ python -m vault -l
    $ python -m vault -p example.com

Revision History:
    2026/02/07 - Original code created
    2026/04/08 - Added code to add a master hash to ensure that the
                 database has not been tampered with.
    2026/04/10 - Code refactoring
    2026/04/12 - Added propper loggin code 
    2026/04/15 - Documentation added
    2026/04/16 - Changed the password database to include the path of
                 the script.
                 Removed an include that was not needed.
"""

# ----------------------------------------------------------------------
# Imports
# ----------------------------------------------------------------------
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import (
    Any, 
    Dict, 
    List, 
    MutableMapping, 
    Optional, 
    Tuple, 
    TypedDict
)

import getpass
from argon2.low_level import (
    ARGON2_VERSION,
    Type,
    hash_secret_raw,
)
#from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----------------------------------------------------------------------
# Logging configuration
# ----------------------------------------------------------------------
logging.basicConfig(
    format="%(levelname)s: %(message)s",
    level=logging.INFO,               # change to DEBUG for more verbosity
    stream=sys.stderr,
)
log = logging.getLogger(__name__)
# ----------------------------------------------------------------------
# UI-only logger  (no level prefix)
# ----------------------------------------------------------------------
ui = logging.getLogger("vault.ui")
ui_handler = logging.StreamHandler(sys.stderr)
ui_handler.setFormatter(logging.Formatter("%(message)s"))
ui.addHandler(ui_handler)
ui.propagate = False          # stop messages from bubbling to `log`

# ----------------------------------------------------------------------
# Helper function for loggin
# ----------------------------------------------------------------------
def _log_and_exit(level: int, message: str) -> None:
    """
    Log *message* at the given *level* and terminate the program with exit-code 1.

    Parameters
    ----------
    level:
        One of ``logging.ERROR``, ``logging.WARNING`` or ``logging.INFO``.
    message:
        The text that will be written to the log before exiting.
    """
    if level == logging.ERROR:
        log.error(message)
    elif level == logging.WARNING:
        log.warning(message)
    else:
        log.info(message)
    sys.exit(1)

# ----------------------------------------------------------------------
# Constants (immutable)
# ----------------------------------------------------------------------
DEFAULT_DB = Path(__file__).resolve().parent / "passwords.json"
KDF_ITERATIONS = 300_000          # PBKDF2 for per-site keys
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 102_400      # KiB ≈ 100 MiB
ARGON2_PARALLELISM = 8
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# ----------------------------------------------------------------------
# TypedDict for the on-disk JSON format (used only for static analysis)
# ----------------------------------------------------------------------
class _VaultFileFormat(TypedDict, total=False):
    masterHash: str
    masterSalt: str
    hmacSalt: str
    hmac: str
    passwords: List[Dict[str, str]]  # each entry is a dict of strings

# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------
class VaultError(RuntimeError):
    """Base class for all vault-specific errors."""

# ----------------------------------------------------------------------
# Small pure helpers
# ----------------------------------------------------------------------
def _b64_url_decode(data: str) -> bytes:
    """
    Decode a URL-safe base64 string that may be missing padding.

    Parameters
    ----------
    data:
        The base64 text (without line-breaks).

    Returns
    -------
    bytes
        The decoded binary data.
    """
    padded = data.strip() + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)

def _b64_url_encode(data: bytes) -> str:
    """
    Encode *data* to a URL-safe base64 string without trailing new-line.

    Parameters
    ----------
    data:
        Binary payload to encode.

    Returns
    -------
    str
        Base64 text suitable for JSON storage.
    """
    return base64.urlsafe_b64encode(data).decode()

# ----------------------------------------------------------------------
# Crypto helper - unchanged except for a couple of log messages
# ----------------------------------------------------------------------
class CryptoHelper:
    """
    Collection of static helpers that wrap all cryptographic primitives used
    by the vault (Argon2id, PBKDF2-HMAC-SHA256, Fernet and HMAC-SHA256).
    """

    @staticmethod
    def generate_salt(length: int = ARGON2_SALT_LEN) -> str:
        """
        Produce a random URL-safe base64-encoded salt.

        Parameters
        ----------
        length:
            Number of random bytes before encoding (default is 16).

        Returns
        -------
        str
            Base64-encoded salt.
        """
        return _b64_url_encode(os.urandom(length))

    # ------------------------------------------------------------------
    # Argon2 hashing (deterministic salt)
    # ------------------------------------------------------------------
    @staticmethod
    def argon2_hash_password(pwd: str, salt_b64: str) -> str:
        """
        Derive an Argon2id hash from *pwd* using the supplied salt.

        The returned string follows the same layout as the output of the
        reference ``argon2`` CLI tool (``$argon2id$v=19$m=...,t=...,p=...$salt$hash``).

        Parameters
        ----------
        pwd:
            Plain-text password to hash.
        salt_b64:
            Base64-encoded salt generated with :meth:`generate_salt`.

        Returns
        -------
        str
            The full Argon2id hash string.
        """
        salt = _b64_url_decode(salt_b64)
        raw = hash_secret_raw(
            secret=pwd.encode(),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
            version=ARGON2_VERSION,
        )
        b64_salt = _b64_url_encode(salt)
        hex_hash = raw.hex()
        return f"$argon2id$v=19$m={ARGON2_MEMORY_COST},t={ARGON2_TIME_COST},p={ARGON2_PARALLELISM}${b64_salt}${hex_hash}"

    @staticmethod
    def argon2_verify_password(pwd: str, stored_hash: str) -> bool:
        """
        Verify *pwd* against an Argon2id hash created by
        :meth:`argon2_hash_password`.

        Parameters
        ----------
        pwd:
            Candidate password supplied by the user.
        stored_hash:
            The full Argon2id hash string read from the vault file.

        Returns
        -------
        bool
            ``True`` if the password matches, ``False`` otherwise.
        """
        try:
            # -------------------- parse stored string --------------------
            parts = stored_hash.split("$")
            if len(parts) != 6:
                raise ValueError("Malformed Argon2 hash string.")
            _, _, version_part, param_part, b64_salt, hex_hash = parts
            if not version_part.startswith("v="):
                raise ValueError("Unsupported Argon2 version.")

            param_dict = dict(kv.split("=") for kv in param_part.split(","))
            mem = int(param_dict["m"])
            time_c = int(param_dict["t"])
            paral = int(param_dict["p"])

            salt = _b64_url_decode(b64_salt)
            expected_raw = bytes.fromhex(hex_hash)

            # -------------------- re-hash candidate --------------------
            derived_raw = hash_secret_raw(
                secret=pwd.encode(),
                salt=salt,
                time_cost=time_c,
                memory_cost=mem,
                parallelism=paral,
                hash_len=len(expected_raw),
                type=Type.ID,
                version=ARGON2_VERSION,
            )
            # -------------------- constant-time compare ---------------
            return constant_time.bytes_eq(derived_raw, expected_raw)

        except Exception as exc:          # includes mismatched hash, parsing errors, etc.
            log.debug("Argon2 verification failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # PBKDF2 → Fernet key derivation (per-site)
    # ------------------------------------------------------------------
    @staticmethod
    def _pbkdf2_derive(password: bytes, salt: bytes) -> bytes:
        """
        Derive a 32-byte Fernet key from *password* and *salt* using PBKDF2-HMAC-SHA256.

        Parameters
        ----------
        password:
            UTF-8 encoded master password.
        salt:
            16-byte random salt (raw, not base64).

        Returns
        -------
        bytes
            URL-safe base64 representation of the derived key (as required by
            :class:`cryptography.fernet.Fernet`).
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    @classmethod
    def encrypt(cls, plaintext: str, master_pwd: str) -> Tuple[str, str]:
        """
        Encrypt *plaintext* using a key derived from *master_pwd*.

        A fresh random salt is generated for every call; the salt is returned so
        the ciphertext can be decrypted later.

        Parameters
        ----------
        plaintext:
            The clear-text password that should be stored.
        master_pwd:
            The master password supplied by the user.

        Returns
        -------
        tuple[str, str]
            ``(ciphertext, salt)`` - both values are URL-safe base64 strings.
        """
        raw_salt = os.urandom(16)
        salt_b64 = _b64_url_encode(raw_salt)
        key = cls._pbkdf2_derive(master_pwd.encode(), raw_salt)
        token = Fernet(key).encrypt(plaintext.encode())
        return token.decode(), salt_b64

    @classmethod
    def decrypt(cls, token_b64: str, master_pwd: str, salt_b64: str) -> str:
        """
        Decrypt a Fernet token that was produced by :meth:`encrypt`.

        Parameters
        ----------
        token_b64:
            Base64-encoded ciphertext.
        master_pwd:
            Master password used to derive the decryption key.
        salt_b64:
            The per-entry salt that was stored alongside the ciphertext.

        Returns
        -------
        str
            The original clear-text password.
        """
        raw_salt = _b64_url_decode(salt_b64)
        key = cls._pbkdf2_derive(master_pwd.encode(), raw_salt)
        plaintext = Fernet(key).decrypt(token_b64.encode())
        return plaintext.decode()

    # ------------------------------------------------------------------
    # HMAC-SHA256 for whole-vault integrity
    # ------------------------------------------------------------------
    @staticmethod
    def derive_hmac_key(master_pwd: str, hmac_salt_b64: str) -> bytes:
        """
        Derive a 32-byte HMAC key from the master password and a stored salt.

        Parameters
        ----------
        master_pwd:
            Master password supplied by the user.
        hmac_salt_b64:
            Base64-encoded salt stored in the vault file.

        Returns
        -------
        bytes
            Raw HMAC key (not base64-encoded).
        """
        salt = _b64_url_decode(hmac_salt_b64)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(master_pwd.encode())

    @staticmethod
    def calc_hmac(key: bytes, payload: bytes) -> str:
        """
        Compute a base64-encoded HMAC-SHA256 tag for *payload*.

        Parameters
        ----------
        key:
            Raw HMAC key derived from the master password.
        payload:
            Byte string over which the HMAC is calculated (normally the JSON
            representation of the vault without the ``hmac`` field).

        Returns
        -------
        str
            URL-safe base64-encoded HMAC tag.
        """
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(payload)
        return _b64_url_encode(h.finalize())

    @staticmethod
    def verify_hmac(key: bytes, payload: bytes, tag_b64: str) -> bool:
        """
        Verify that ``tag_b64`` matches the HMAC-SHA256 of *payload*.

        Parameters
        ----------
        key:
            Raw HMAC key.
        payload:
            Data that was originally HMAC-ed.
        tag_b64:
            Stored base64-encoded HMAC tag.

        Returns
        -------
        bool
            ``True`` when the tag is valid, ``False`` otherwise.
        """
        try:
            expected = _b64_url_decode(tag_b64)
        except Exception:
            return False
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(payload)
        try:
            h.verify(expected)
            return True
        except Exception:
            return False

# ----------------------------------------------------------------------
# Master-password manager - now uses the logger
# ----------------------------------------------------------------------
class MasterPasswordManager:
    """
    Handles creation, verification and (if necessary) upgrade of the master-
    password used to protect the vault.
    """

    @staticmethod
    def _prompt_new_password() -> str:
        """
        Interactively ask the user to create a new master password,
        validating that the two entries match and are non-empty.

        Returns
        -------
        str
            The freshly entered master password.
        """
        while True:
            pwd1 = getpass.getpass("Create master password: ")
            pwd2 = getpass.getpass("Confirm master password: ")
            if pwd1 != pwd2:
                log.warning("Passwords do not match - try again.")
                continue
            if not pwd1:
                log.warning("Password cannot be empty.")
                continue
            return pwd1

    @staticmethod
    def _prompt_existing_password(prompt: str = "Master password: ") -> str:
        """
        Prompt the user for the existing master password.

        Parameters
        ----------
        prompt:
            Text shown to the user (defaults to ``"Master password: "``).

        Returns
        -------
        str
            The password entered by the user.
        """
        return getpass.getpass(prompt)

    @classmethod
    def ensure_master(cls, vault_dict: MutableMapping[str, Any]) -> str:
        """
        Guarantee that a master password is available and verified.

        * If the vault contains no ``masterHash`` a brand-new master password
          is created and stored (together with a fresh salt).
        * If the vault already holds an Argon2id hash the user is asked for the
          password and the hash is verified.
        * If a hash exists *without* a salt, the file is considered malformed/obsolete;
          the program aborts with a clear error message.

        Parameters
        ----------
        vault_dict:
            The in-memory representation of the JSON vault (may be an empty
            skeleton).

        Returns
        -------
        str
            The verified master password (still in clear text; caller is
            responsible for wiping it when done).

        Raises
        ------
        SystemExit
            When verification fails too many times or an obsolete format is
            detected (handled via :func:`_log_and_exit`).
        """
        stored_hash = vault_dict.get("masterHash", "")
        stored_salt = vault_dict.get("masterSalt", "")

        # --------------------------------------------------------------
        # No master password - create a fresh vault
        # --------------------------------------------------------------
        if not stored_hash:
            log.info("No master password set - creating a new vault.")
            pwd = cls._prompt_new_password()
            salt = CryptoHelper.generate_salt()
            vault_dict["masterSalt"] = salt
            vault_dict["masterHash"] = CryptoHelper.argon2_hash_password(pwd, salt)
            return pwd

        # --------------------------------------------------------------
        # Vault already has Argon2 data (the normal case)
        # --------------------------------------------------------------
        if stored_salt:
            for _ in range(3):
                pwd = cls._prompt_existing_password()
                if CryptoHelper.argon2_verify_password(pwd, stored_hash):
                    return pwd
                log.warning("Wrong password.")
            _log_and_exit(logging.ERROR, "Too many failed attempts - aborting.")

        # --------------------------------------------------------------
        # Hash present but missing salt ⇒ obsolete SHA-256 vault.
        # --------------------------------------------------------------
        _log_and_exit(
            logging.ERROR,
            "Vault contains an obsolete SHA-256 master-password hash. "
            "All vaults must have been upgraded to Argon2id (masterSalt present). "
            "Create a new vault or run the migration script."
        )

# ----------------------------------------------------------------------
# Vault I/O - migration, atomic write (logging added)
# ----------------------------------------------------------------------
class VaultIO:
    """
    Low-level persistence helpers that read/write the JSON vault file,
    perform atomic updates and normalise base64 fields.
    """

    @staticmethod
    def _atomic_write(path: Path, data: Any) -> None:
        """
        Write *data* to *path* atomically.

        The function creates a temporary file in the same directory,
        dumps the JSON, flushes and calls ``os.fsync`` to ensure the data
        reaches disk, then atomically renames the temporary file over the
        target.

        Parameters
        ----------
        path:
            Destination path for the vault file.
        data:
            JSON-serialisable Python object (normally a dict).
        """
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=str(path.parent),
            encoding="utf-8",
        )
        try:
            json.dump(data, tmp, indent=4, sort_keys=True)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        shutil.move(tmp.name, str(path))

    @staticmethod
    def _normalise_b64(value: Any) -> str:
        """
        Normalise a field that is expected to be base64-encoded.

        The function accepts a ``list`` of bytes, a ``bytes`` object or a
        ``str`` that may have missing padding, and always returns a correctly
        padded URL-safe base64 string.

        Parameters
        ----------
        value:
            The value to normalise (list, bytes/bytearray, or str).

        Returns
        -------
        str
            URL-safe base64 representation.
        """
        if isinstance(value, list):
            raw = bytes(value)
        elif isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
        elif isinstance(value, str):
            try:
                raw = _b64_url_decode(value)
            except Exception:
                # Already a proper token - just ensure correct padding.
                return _b64_url_encode(_b64_url_decode(value + "=" * (-len(value) % 4)))
        else:
            raise TypeError(f"Unsupported type for encrypted field: {type(value)}")
        return _b64_url_encode(raw)

    @classmethod
    def load(cls, path: Path) -> MutableMapping[str, Any]:
        """
        Load the vault file from *path*, creating a skeleton if the file does
        not exist.

        The loader also makes sure every entry contains correctly padded base64
        strings and extracts a deterministic payload (used later for integrity
        verification).

        Parameters
        ----------
        path:
            Location of the JSON vault file.

        Returns
        -------
        dict
            In-memory representation of the vault (may be an empty skeleton).

        Raises
        ------
        VaultError
            If the file cannot be read or is not valid JSON.
        """
        if not path.exists():
            log.debug("Vault file %s not found - creating new skeleton.", path)
            return {
                "masterHash": "",
                "masterSalt": "",
                "hmacSalt": "",
                "hmac": "",
                "passwords": [],
            }

        try:
            with path.open("r", encoding="utf-8") as f:
                data: MutableMapping[str, Any] = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"Could not read vault file '{path}': {exc}") from exc

        for field in ("masterSalt", "hmacSalt", "hmac"):
            data.setdefault(field, "")

        for entry in data.get("passwords", []):
            if "pwd" in entry:
                entry["pwd"] = cls._normalise_b64(entry["pwd"])
            if "salt" in entry:
                entry["salt"] = cls._normalise_b64(entry["salt"])

        if data.get("hmac"):
            payload = json.dumps(
                {k: v for k, v in data.items() if k != "hmac"},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            data["_integrity_payload"] = payload

        return data

    @classmethod
    def save(cls, path: Path, vault_dict: MutableMapping[str, Any]) -> None:
        """
        Persist *vault_dict* to *path* using an atomic write.

        Parameters
        ----------
        path:
            Destination file.
        vault_dict:
            The vault data to serialize.
        """
        log.debug("Saving vault to %s (atomic write).", path)
        cls._atomic_write(path, vault_dict)

# ----------------------------------------------------------------------
# Data model - a single credential entry
# ----------------------------------------------------------------------
@dataclass
class VaultEntry:
    """
    Simple data holder for one credential record.

    Attributes
    ----------
    site:
        Human-readable name of the service (e.g. ``example.com``).
    username:
        Login name / identifier for the service.
    pwd:
        Fernet token (URL-safe base64 string) that encrypts the clear-text password.
    salt:
        Per-entry random salt used for key derivation (URL-safe base64 string).
    """
    site: str
    username: str
    pwd: str          # Fernet token (single Base64-URL string)
    salt: str         # per-site salt (Base64-URL)

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "VaultEntry":
        """
        Build a :class:`VaultEntry` from a plain dictionary (as stored in JSON).

        Parameters
        ----------
        data:
            Mapping containing ``site``, ``username``, ``pwd`` and ``salt``.

        Returns
        -------
        VaultEntry
            The constructed instance.
        """
        return cls(
            site=data["site"],
            username=data["username"],
            pwd=data["pwd"],
            salt=data["salt"],
        )

    def to_dict(self) -> Dict[str, str]:
        """
        Convert the entry back to a dictionary suitable for JSON serialization.

        Returns
        -------
        dict
            Mapping with the same keys that :meth:`from_dict` expects.
        """
        return asdict(self)

# ----------------------------------------------------------------------
# High-level Vault class - CRUD & integrity (logging added)
# ----------------------------------------------------------------------
class Vault:
    """
    High-level façade that manages a collection of :class:`VaultEntry`
    objects, providing CRUD operations, integrity verification and
    transparent encryption/decryption of passwords.
    """

    def __init__(self, data: MutableMapping[str, Any]):
        """
        Initialise a :class:`Vault` from the raw dictionary loaded from JSON.

        Parameters
        ----------
        data:
            The parsed JSON content (as returned by :class:`VaultIO`).
        """
        self._data: MutableMapping[str, Any] = data
        self.entries: List[VaultEntry] = [
            VaultEntry.from_dict(e) for e in self._data.get("passwords", [])
        ]

    # ------------------------------------------------------------------
    def _sync_to_dict(self) -> None:
        """
        Write the current list of :class:`VaultEntry` objects back into the
        underlying ``_data`` dictionary.  Called before persisting the vault.
        """
        self._data["passwords"] = [e.to_dict() for e in self.entries]

    # ------------------------------------------------------------------
    def find(self, site: str) -> Optional[VaultEntry]:
        """
        Locate a credential entry by its *site* name (case-insensitive).

        Parameters
        ----------
        site:
            Name of the site to look for.

        Returns
        -------
        VaultEntry | None
            Matching entry or ``None`` when the site is not stored.
        """
        site_lc = site.lower()
        for entry in self.entries:
            if entry.site.lower() == site_lc:
                return entry
        return None

    # ------------------------------------------------------------------
    def add(self, site: str, username: str, password: str, master_pwd: str) -> None:
        """
        Insert a new credential into the vault.

        Parameters
        ----------
        site:
            Service identifier (must be unique).
        username:
            Login name for the service.
        password:
            Clear-text password to be encrypted.
        master_pwd:
            Master password used for encryption.

        Raises
        ------
        VaultError
            If an entry for *site* already exists.
        """
        if self.find(site):
            raise VaultError(f"Site '{site}' already exists - use --change.")
        token, salt = CryptoHelper.encrypt(password, master_pwd)
        self.entries.append(VaultEntry(site, username, token, salt))
        log.info("Added site '%s'.", site)

    # ------------------------------------------------------------------
    def change(
        self,
        site: str,
        master_pwd: str,
        new_username: Optional[str] = None,
        new_password: Optional[str] = None,
    ) -> None:
        """
        Update the username and/or password for an existing *site*.

        Parameters
        ----------
        site:
            Service to modify.
        master_pwd:
            Master password (required for re-encryption of the password).
        new_username:
            New username; if ``None`` the existing one is kept.
        new_password:
            New clear-text password; if ``None`` the existing encrypted value is kept.

        Raises
        ------
        VaultError
            If *site* does not exist.
        """
        entry = self.find(site)
        if entry is None:
            raise VaultError(f"Site '{site}' not found - cannot change.")
        if new_username is not None:
            entry.username = new_username
        if new_password is not None:
            token, salt = CryptoHelper.encrypt(new_password, master_pwd)
            entry.pwd = token
            entry.salt = salt
        log.info("Updated entry for site '%s'.", site)

    # ------------------------------------------------------------------
    def delete(self, site: str) -> None:
        """
        Remove the credential for *site* from the vault.

        Parameters
        ----------
        site:
            Service to delete.

        Raises
        ------
        VaultError
            If *site* does not exist.
        """
        entry = self.find(site)
        if entry is None:
            raise VaultError(f"Site '{site}' not found - cannot delete.")
        self.entries.remove(entry)
        log.info("Deleted site '%s'.", site)

    # ------------------------------------------------------------------
    def list_sites(self) -> List[str]:
        """
        Return an alphabetically sorted list of all stored site names.

        Returns
        -------
        list[str]
            Sorted site identifiers.
        """
        return sorted([e.site for e in self.entries], key=str.lower)

    # ------------------------------------------------------------------
    def get_credentials(self, site: str, master_pwd: str) -> Tuple[str, str]:
        """
        Retrieve the clear-text credentials for *site*.

        Parameters
        ----------
        site:
            Service whose credentials are requested.
        master_pwd:
            Master password required for decryption.

        Returns
        -------
        tuple[str, str]
            ``(username, password)`` where *password* is the decrypted clear-text value.

        Raises
        ------
        VaultError
            If *site* is not found.
        """
        entry = self.find(site)
        if entry is None:
            raise VaultError(f"Site '{site}' not found.")
        password = CryptoHelper.decrypt(entry.pwd, master_pwd, entry.salt)
        return entry.username, password

    # ------------------------------------------------------------------
    def compute_and_store_hmac(self, master_pwd: str) -> None:
        """
        Compute a fresh HMAC tag for the current vault contents and store it
        (together with a new salt if necessary).  The HMAC covers the whole
        JSON payload *except* the ``hmac`` field itself.

        Parameters
        ----------
        master_pwd:
            Master password used to derive the HMAC key.
        """
        if not self._data.get("hmacSalt"):
            self._data["hmacSalt"] = CryptoHelper.generate_salt()

        key = CryptoHelper.derive_hmac_key(master_pwd, self._data["hmacSalt"])
        payload = json.dumps(
            {k: v for k, v in self._data.items() if k != "hmac"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self._data["hmac"] = CryptoHelper.calc_hmac(key, payload)

    def verify_integrity(self, master_pwd: str) -> None:
        """
        Verify the stored HMAC tag against the current payload.  If the tag is
        missing the vault is assumed to be old (no integrity protection) and
        verification is skipped.

        Parameters
        ----------
        master_pwd:
            Master password used to derive the HMAC key.

        Raises
        ------
        VaultError
            If the HMAC verification fails or required fields are missing.
        """
        tag = self._data.get("hmac", "")
        if not tag:
            return  # no integrity tag - old vault or first run

        payload: Optional[bytes] = self._data.get("_integrity_payload")
        if payload is None:
            raise VaultError("Integrity payload missing - corrupted vault.")

        hmac_salt = self._data.get("hmacSalt")
        if not hmac_salt:
            raise VaultError("Vault corrupted - missing HMAC salt.")

        key = CryptoHelper.derive_hmac_key(master_pwd, hmac_salt)
        if not CryptoHelper.verify_hmac(key, payload, tag):
            raise VaultError("Vault integrity check failed - possible tampering.")
        # Discard the temporary payload field now that it has been verified.
        self._data.pop("_integrity_payload", None)

# ----------------------------------------------------------------------
# CLI wrapper - all user messages now go through the logger
# ----------------------------------------------------------------------
class Cli:
    """
    Command-line interface that parses arguments, interacts with the user and
    drives the :class:`Vault` object.  All user-visible output goes through
    either the regular logger (``log``) or the UI-only logger ``ui``.
    """

    def __init__(self) -> None:
        """Create the argument parser."""
        self.parser = self._build_parser()

    @staticmethod
    def _build_parser() -> argparse.ArgumentParser:
        """
        Build and return an :class:`argparse.ArgumentParser` with all supported
        options and sub-commands.

        Returns
        -------
        argparse.ArgumentParser
            Configured parser ready for ``parse_args``.
        """
        parser = argparse.ArgumentParser(
            description="Simple encrypted password manager",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        parser.add_argument("-f", "--file", type=Path, default=DEFAULT_DB,
                            help="Path to the JSON vault file")

        crud = parser.add_mutually_exclusive_group()
        crud.add_argument(
            "-a", "--add",
            nargs="?",
            const="",
            metavar="SITE",
            help="Add a new site. If SITE is omitted you will be asked for it."
        )
        crud.add_argument(
            "-c", "--change",
            metavar="SITE",
            help="Change credentials of a site."
        )
        crud.add_argument("-d", "--delete", metavar="SITE",
                          help="Delete a site.")
        crud.add_argument("-l", "--list", action="store_true",
                          help="List stored sites.")
        crud.add_argument("-p", "--print", metavar="SITE",
                          help="Print credentials for a site.")
        parser.add_argument("-P", "--prompt", action="store_true",
                            help="Force interactive mode (default when no other args).")
        return parser

    # ------------------------------------------------------------------
    # Interactive helpers (still use input()/getpass.getpass() for prompts)
    # ------------------------------------------------------------------
    @staticmethod
    def _prompt_site_name(action: str = "add") -> str:
        """
        Prompt the user for a site name (used in interactive mode).

        Parameters
        ----------
        action:
            Verb describing what the site will be used for (e.g. ``"add"``).

        Returns
        -------
        str
            Non-empty site name entered by the user.
        """
        while True:
            site = input(f"Site name to {action}: ").strip()
            if site:
                return site
            log.warning("Site name cannot be empty - try again.")

    @staticmethod
    def _prompt_username(site: str) -> str:
        """
        Prompt for the username belonging to *site*.

        Parameters
        ----------
        site:
            The service name shown in the prompt.

        Returns
        -------
        str
            Username entered by the user (non-empty).
        """
        while True:
            user = input(f"Username for '{site}': ").strip()
            if user:
                return user
            log.warning("Username cannot be empty.")

    @staticmethod
    def _prompt_password(site: str) -> str:
        """
        Prompt for the password belonging to *site* (masked input).

        Parameters
        ----------
        site:
            The service name shown in the prompt.

        Returns
        -------
        str
            Password entered by the user (non-empty).
        """
        while True:
            pwd = getpass.getpass(f"Password for '{site}': ")
            if pwd:
                return pwd
            log.warning("Password cannot be empty.")

    # ------------------------------------------------------------------
    def run(self, argv: Optional[List[str]] = None) -> int:
        """
        Entry point for the CLI.

        Parameters
        ----------
        argv:
            Optional list of arguments (defaults to ``sys.argv[1:]`` when ``None``).

        Returns
        -------
        int
            Exit status (0 on success, 1 on error - the function itself always
            terminates the process via ``sys.exit`` in case of fatal errors).
        """
        args = self.parser.parse_args(argv)

        try:
            vault_data = VaultIO.load(args.file)
            master_pwd = MasterPasswordManager.ensure_master(vault_data)
            vault = Vault(vault_data)
            vault.verify_integrity(master_pwd)
        except VaultError as exc:
            _log_and_exit(logging.ERROR, str(exc))

        try:
            # --------------------------------------------------------------
            # ADD
            # --------------------------------------------------------------
            if args.add is not None:
                site = args.add
                if site == "":
                    site = self._prompt_site_name("add")
                username = self._prompt_username(site)
                password = self._prompt_password(site)
                vault.add(site, username, password, master_pwd)

            # --------------------------------------------------------------
            # CHANGE
            # --------------------------------------------------------------
            elif args.change:
                site = args.change
                entry = vault.find(site)
                if entry is None:
                    raise VaultError(f"Site '{site}' not found - cannot change.")

                new_user = input(
                    f"Current username is '{entry.username}'. Press <Enter> to keep it "
                    f"or type a new one: "
                ).strip()
                new_user = new_user or None

                # Decrypt only so the user can decide whether to keep it
                _, _ = vault.get_credentials(site, master_pwd)  # we don't need the plain pwd here
                new_pwd = getpass.getpass(
                    "Press <Enter> to keep the existing password, or type a new one: "
                )
                new_pwd = new_pwd or None

                vault.change(site, master_pwd, new_user, new_pwd)

            # --------------------------------------------------------------
            # DELETE
            # --------------------------------------------------------------
            elif args.delete:
                vault.delete(args.delete)

            # --------------------------------------------------------------
            # LIST
            # --------------------------------------------------------------
            elif args.list:
                sites = vault.list_sites()
                if not sites:
                    ui.info("🔎  No sites stored yet.")
                else:
                    ui.info("📋  Stored sites:")
                    for i, s in enumerate(sites, 1):
                        ui.info("  %d. %s", i, s)

            # --------------------------------------------------------------
            # PRINT (single site)
            # --------------------------------------------------------------
            elif args.print:
                username, clear_pwd = vault.get_credentials(args.print, master_pwd)
                ui.info("\n🔐  %s:", args.print)
                ui.info("   Username : %s", username)
                ui.info("   Password : %s\n", clear_pwd)

            # --------------------------------------------------------------
            # INTERACTIVE (default)
            # --------------------------------------------------------------
            elif args.prompt or len(sys.argv) == 1:
                self._interactive_mode(vault, master_pwd)

            else:
                self.parser.print_help()
                return 0

            # --------------------------------------------------------------
            # Persist changes (if any)
            # --------------------------------------------------------------
            vault._sync_to_dict()
            vault.compute_and_store_hmac(master_pwd)
            VaultIO.save(args.file, vault._data)

        except VaultError as exc:
            _log_and_exit(logging.ERROR, str(exc))
        finally:
            # best-effort wiping of the master password
            master_pwd = ""

        return 0

    # ------------------------------------------------------------------
    # Interactive REPL (still uses input()/getpass.getpass())
    # ------------------------------------------------------------------
    def _interactive_mode(self, vault: Vault, master_pwd: str) -> None:
        """
        Simple text-based REPL that lets the user view, add, change or delete
        entries without supplying command-line switches.

        Parameters
        ----------
        vault:
            Active :class:`Vault` instance.
        master_pwd:
            Master password (used for encryption/decryption inside the loop).
        """
        while True:
            sites = vault.list_sites()
            if sites:
                ui.info("\n📋  Stored sites:")
                for i, s in enumerate(sites, 1):
                    ui.info("  %d. %s", i, s)
            else:
                log.info("\n🔎  Vault empty - add a site with the **A** command.")

            ui.info(
                "\nCommands:  <number> - view site   A - add   C - change   D - delete   Q - quit"
            )
            choice = input("Your choice: ").strip()

            # ----- Quit -------------------------------------------------------
            if choice.upper() == "Q":
                break

            # ----- Add --------------------------------------------------------
            if choice.upper() == "A":
                site = self._prompt_site_name("add")
                username = self._prompt_username(site)
                password = self._prompt_password(site)
                vault.add(site, username, password, master_pwd)
                continue

            # ----- Change -----------------------------------------------------
            if choice.upper() == "C":
                if not sites:
                    log.warning("Nothing to change - the vault is empty.")
                    continue
                idx = self._prompt_number("change", len(sites))
                site = sites[idx]
                entry = vault.find(site)
                assert entry is not None

                new_user = input(
                    f"Current username is '{entry.username}'. Press <Enter> to keep it "
                    f"or type a new one: "
                ).strip()
                new_user = new_user or None

                # Show current password (decrypt) only to let the user decide
                _, _ = vault.get_credentials(site, master_pwd)
                new_pwd = getpass.getpass(
                    "Press <Enter> to keep the existing password, or type a new one: "
                )
                new_pwd = new_pwd or None

                vault.change(site, master_pwd, new_user, new_pwd)
                continue

            # ----- Delete -----------------------------------------------------
            if choice.upper() == "D":
                if not sites:
                    log.warning("Nothing to delete - the vault is empty.")
                    continue
                idx = self._prompt_number("delete", len(sites))
                site = sites[idx]
                confirm = input(f"Are you sure you want to delete '{site}'? (y/N): ").strip().lower()
                if confirm == "y":
                    vault.delete(site)
                else:
                    log.info("Deletion aborted.")
                continue

            # ----- View (numeric) ---------------------------------------------
            if not choice.isdigit():
                log.warning("Invalid input - type a number, A, C, D or Q.")
                continue
            num = int(choice) - 1
            if num < 0 or num >= len(sites):
                log.warning("Number out of range.")
                continue
            site = sites[num]
            username, clear_pwd = vault.get_credentials(site, master_pwd)
            ui.info("\n🔐  %s:", site)
            ui.info("   Username : %s", username)
            ui.info("   Password : %s\n", clear_pwd)
            input("Press <Enter> to continue …")

    @staticmethod
    def _prompt_number(action: str, max_idx: int) -> int:
        """
        Prompt the user for a numeric index between 1 and *max_idx*.

        Parameters
        ----------
        action:
            Verb used in the prompt (e.g. ``"change"`` or ``"delete"``).
        max_idx:
            Upper bound (inclusive) for the valid range.

        Returns
        -------
        int
            Zero-based index selected by the user.

        Raises
        ------
        VaultError
            If the user enters ``Q`` to cancel the operation.
        """
        while True:
            raw = input(f"Enter the number of the site to {action} (or Q to cancel): ").strip()
            if raw.upper() == "Q":
                raise VaultError("User cancelled.")
            if not raw.isdigit():
                log.warning("Please type a number.")
                continue
            idx = int(raw) - 1
            if 0 <= idx < max_idx:
                return idx
            log.warning("Number out of range.")

# ----------------------------------------------------------------------
# Entry-point
# ----------------------------------------------------------------------
def main() -> None:
    """
    Entrypoint used by ``python -m vault`` or the shebang.

    Exits the process with the status code returned by :meth:`Cli.run`.
    """
    sys.exit(Cli().run())

if __name__ == "__main__":
    main()
