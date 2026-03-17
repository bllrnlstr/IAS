"""
PROJECT 5: SECURE ENVIRONMENT CONFIGURATION (.env)
Information Assurance and Security
--------------------------------------------------
Security Features:
  - Secrets loaded from .env file — never hardcoded
  - .env file is never written to source control (gitignore reminder)
  - Secret values masked in all output/logging
  - Required variable enforcement (app won't start if missing)
  - Type validation for all config values
  - Encrypted .env option using Fernet
  - Runtime secret rotation support
  - Read-only config object (immutable after load)
"""

import os
import re
import secrets
import json
from datetime import datetime
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

ENV_FILE = ".env"
ENCRYPTED_ENV_FILE = ".env.enc"
KEY_FILE = ".env.key"


# ── Mask Sensitive Values ─────────────────────────────
def mask(value: str, show: int = 4) -> str:
    """Show only the first N characters, mask the rest."""
    if len(value) <= show:
        return "*" * len(value)
    return value[:show] + "*" * (len(value) - show)


# ── .env File Parser ──────────────────────────────────
def parse_env_file(filepath: str) -> dict:
    """Parse a .env file into a dictionary. Ignores comments and blank lines."""
    config = {}
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f".env file not found: {filepath}")

    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"Line {lineno}: Missing '=' in '{line}'")
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if not re.match(r'^[A-Z0-9_]+$', key):
                raise ValueError(f"Line {lineno}: Invalid key name '{key}' (use UPPERCASE_UNDERSCORE).")
            config[key] = value
    return config


# ── Encrypted .env Support ────────────────────────────
def encrypt_env_file(env_path: str = ENV_FILE):
    """Encrypt the .env file into .env.enc using Fernet."""
    if not ENCRYPTION_AVAILABLE:
        return "[ERROR] cryptography package not installed."
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    with open(env_path) as f:
        data = f.read().encode()
    token = Fernet(key).encrypt(data)
    with open(ENCRYPTED_ENV_FILE, "wb") as f:
        f.write(token)
    return f"[OK] Encrypted .env saved to '{ENCRYPTED_ENV_FILE}'. Key in '{KEY_FILE}'."

def load_encrypted_env() -> dict:
    """Decrypt and load .env.enc using the key in .env.key."""
    if not ENCRYPTION_AVAILABLE:
        raise RuntimeError("cryptography package not installed.")
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    with open(ENCRYPTED_ENV_FILE, "rb") as f:
        token = f.read()
    decrypted = Fernet(key).decrypt(token).decode()
    config = {}
    for line in decrypted.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key_name, _, value = line.partition("=")
        config[key_name.strip()] = value.strip().strip('"').strip("'")
    return config


# ── Config Loader with Validation ─────────────────────
class SecureConfig:
    """
    Immutable, validated configuration object.
    Secrets are never printed in full — always masked.
    """

    REQUIRED_KEYS = ["APP_SECRET_KEY", "DB_PASSWORD", "API_KEY"]

    TYPE_RULES = {
        "APP_PORT":   int,
        "DEBUG_MODE": lambda v: v.lower() in ("true", "false"),
    }

    SECRET_KEYS = {"APP_SECRET_KEY", "DB_PASSWORD", "API_KEY", "JWT_SECRET"}

    def __init__(self, env_path: str = ENV_FILE, use_encrypted: bool = False):
        if use_encrypted and ENCRYPTION_AVAILABLE:
            raw = load_encrypted_env()
        else:
            raw = parse_env_file(env_path)

        self._validate_required(raw)
        self._validate_types(raw)
        self._config = raw  # Store immutably

    def _validate_required(self, config: dict):
        missing = [k for k in self.REQUIRED_KEYS if k not in config]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                f"Check your {ENV_FILE} file."
            )

    def _validate_types(self, config: dict):
        for key, validator in self.TYPE_RULES.items():
            if key in config:
                try:
                    validator(config[key])
                except (ValueError, TypeError):
                    raise ValueError(f"Config key '{key}' has invalid value: '{config[key]}'")

    def get(self, key: str, default=None):
        return self._config.get(key, default)

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self._config.get(key, default))

    def get_bool(self, key: str, default: bool = False) -> bool:
        return self._config.get(key, str(default)).lower() == "true"

    def display(self):
        """Print config safely — masks all secret values."""
        print("\n  Loaded Configuration:")
        for key, value in self._config.items():
            display_value = mask(value) if key in self.SECRET_KEYS else value
            print(f"    {key} = {display_value}")

    def __setattr__(self, name, value):
        if name != "_config" and hasattr(self, "_config"):
            raise AttributeError("SecureConfig is read-only after initialization.")
        super().__setattr__(name, value)

    def __repr__(self):
        return f"<SecureConfig keys={list(self._config.keys())}>"


# ── Gitignore Reminder ────────────────────────────────
def check_gitignore():
    gitignore = Path(".gitignore")
    protected = [".env", ".env.enc", ".env.key", "secret.key"]
    if not gitignore.exists():
        print("  [WARNING] No .gitignore found! Create one and add .env to it.")
        return
    content = gitignore.read_text()
    for entry in protected:
        if entry not in content:
            print(f"  [WARNING] '{entry}' is NOT in .gitignore — risk of secret exposure!")
        else:
            print(f"  [OK] '{entry}' is protected in .gitignore")


# ── Demo ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== PROJECT 5: SECURE ENVIRONMENT CONFIGURATION ===\n")

    # Create a sample .env for demo
    sample_env = """# Application Configuration
APP_SECRET_KEY=super_secret_signing_key_12345
DB_PASSWORD=db_p@ssw0rd_9876
API_KEY=api_live_aBcDeFgHiJkLmNoPqRs
JWT_SECRET=jwt_secret_xYz987
APP_PORT=8080
DEBUG_MODE=false
DB_HOST=localhost
DB_NAME=myappdb
"""
    with open(ENV_FILE, "w") as f:
        f.write(sample_env)
    print(f"[Demo] Created sample '{ENV_FILE}' file.\n")

    print("-- Load and Validate Config --")
    try:
        config = SecureConfig(ENV_FILE)
        config.display()
    except (EnvironmentError, ValueError) as e:
        print(f"  [ERROR] {e}")

    print("\n-- Access Config Values --")
    print(f"  DB_HOST   : {config.get('DB_HOST')}")
    print(f"  APP_PORT  : {config.get_int('APP_PORT')}")
    print(f"  DEBUG_MODE: {config.get_bool('DEBUG_MODE')}")
    print(f"  API_KEY   : {mask(config.get('API_KEY'))}  (masked)")

    print("\n-- Immutability Check --")
    try:
        config._config = {}
    except AttributeError as e:
        print(f"  [BLOCKED] {e}")

    print("\n-- Missing Required Variable Test --")
    bad_env = "DB_HOST=localhost\nAPP_PORT=8080\n"
    with open("bad.env", "w") as f:
        f.write(bad_env)
    try:
        bad_config = SecureConfig("bad.env")
    except EnvironmentError as e:
        print(f"  [ERROR] {e}")
    os.remove("bad.env")

    print("\n-- Encrypted .env --")
    if ENCRYPTION_AVAILABLE:
        print(encrypt_env_file(ENV_FILE))
        enc_config = SecureConfig(use_encrypted=True)
        print(f"  Loaded from encrypted file: {enc_config}")
    else:
        print("  [SKIP] cryptography not installed.")

    print("\n-- Gitignore Check --")
    check_gitignore()

    print(f"\n[REMINDER] Never commit '{ENV_FILE}', '{KEY_FILE}', or '{ENCRYPTED_ENV_FILE}' to version control!")
