import os
import json
import base64
import getpass
import secrets
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Dict, Optional

logger = logging.getLogger(__name__)

VAULT_VERSION = "2.0"
ITERATIONS    = 480_000
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DATA_DIR      = os.path.join(BASE_DIR, "data")
ENC_FILE      = os.path.join(DATA_DIR, "vault.enc")
SALT_FILE     = os.path.join(DATA_DIR, "salt.bin")
MAX_ATTEMPTS  = 3


# ---------- Key derivation ----------

def _generate_salt() -> bytes:
    return secrets.token_bytes(32)


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ---------- Vault I/O ----------

class _Vault:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.salt = self._load_or_create_salt()

    def _load_or_create_salt(self) -> bytes:
        if os.path.exists(SALT_FILE):
            with open(SALT_FILE, "rb") as f:
                return f.read()
        salt = _generate_salt()
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        logger.debug("New salt generated and saved.")
        return salt

    def save(self, data: Dict, key: bytes):
        payload = json.dumps({"version": VAULT_VERSION, "data": data}).encode()
        encrypted = Fernet(key).encrypt(payload)
        with open(ENC_FILE, "wb") as f:
            f.write(encrypted)
        logger.debug("Vault saved.")

    def load(self, key: bytes) -> Optional[Dict]:
        if not os.path.exists(ENC_FILE):
            return None
        try:
            with open(ENC_FILE, "rb") as f:
                encrypted = f.read()
            decrypted = json.loads(Fernet(key).decrypt(encrypted).decode())
            if decrypted.get("version") != VAULT_VERSION:
                logger.warning("Vault version mismatch.")
                return None
            return decrypted["data"]
        except Exception:
            return None


# ---------- Password Manager ----------

class PasswordManager:
    def __init__(self):
        self._vault = _Vault()

    # -- helpers --

    def _prompt_new_master(self) -> bytes:
        while True:
            pwd     = getpass.getpass("  New master password : ")
            confirm = getpass.getpass("  Confirm password    : ")
            if pwd == confirm:
                return _derive_key(pwd, self._vault.salt)
            print("  Passwords do not match. Try again.")

    def _authenticate(self) -> Optional[tuple]:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            pwd  = getpass.getpass(f"  Master password ({attempt}/{MAX_ATTEMPTS}): ")
            key  = _derive_key(pwd, self._vault.salt)
            data = self._vault.load(key)
            if data is not None:
                return data, key
            print("  Incorrect password.")
        return None

    # -- menu actions --

    def _list_entries(self, data: Dict):
        if not data:
            print("\n  Vault is empty.")
            return
        print(f"\n  {'Service':<20} {'Username':<20}")
        print(f"  {'-'*20} {'-'*20}")
        for service, creds in data.items():
            print(f"  {service:<20} {creds['username']:<20}")

    def _show_password(self, data: Dict):
        service = input("  Service name: ").strip()
        if service not in data:
            print("  Service not found.")
            return
        confirm = getpass.getpass("  Confirm master password to reveal: ")
        key_check = _derive_key(confirm, self._vault.salt)
        if self._vault.load(key_check) is None:
            print("  Incorrect password. Access denied.")
            return
        print(f"\n  Username : {data[service]['username']}")
        print(f"  Password : {data[service]['password']}")

    def _add_entry(self, data: Dict, key: bytes):
        service  = input("  Service name : ").strip()
        username = input("  Username     : ").strip()
        password = getpass.getpass("  Password     : ")
        if not service:
            print("  Service name cannot be empty.")
            return
        data[service] = {"username": username, "password": password}
        self._vault.save(data, key)
        print("  Entry added.")
        logger.info("Entry added for service '%s'.", service)

    def _delete_entry(self, data: Dict, key: bytes):
        service = input("  Service to delete: ").strip()
        if service not in data:
            print("  Service not found.")
            return
        confirm = input(f"  Delete '{service}'? [y/N]: ").strip().lower()
        if confirm == "y":
            del data[service]
            self._vault.save(data, key)
            print("  Entry deleted.")
            logger.info("Entry deleted for service '%s'.", service)

    def _change_master(self, data: Dict):
        new_key = self._prompt_new_master()
        self._vault.save(data, new_key)
        print("  Master password updated.")
        logger.info("Master password changed.")

    # -- main loop --

    def run(self):
        print("\n" + "=" * 50)
        print("  Secure Password Vault")
        print("=" * 50)

        if not os.path.exists(ENC_FILE):
            print("\n  First-time setup.")
            key = self._prompt_new_master()
            self._vault.save({}, key)
            print("  Vault created.\n")

        result = self._authenticate()
        if result is None:
            print("\n  Too many failed attempts. Vault locked.")
            return

        data, key = result
        print("  Access granted.\n")

        while True:
            print("\n  1. List entries")
            print("  2. Reveal password")
            print("  3. Add entry")
            print("  4. Delete entry")
            print("  5. Change master password")
            print("  6. Exit")

            choice = input("\n  Option: ").strip()

            if choice == "1":
                self._list_entries(data)
            elif choice == "2":
                self._show_password(data)
            elif choice == "3":
                self._add_entry(data, key)
            elif choice == "4":
                self._delete_entry(data, key)
            elif choice == "5":
                self._change_master(data)
            elif choice == "6":
                print("  Vault locked.")
                break
            else:
                print("  Invalid option.")


def run_password_manager():
    PasswordManager().run()
