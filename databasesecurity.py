"""
PROJECT 4: SECURE DATABASE SYSTEM
Information Assurance and Security
--------------------------------------------------
Security Features:
  - Parameterized queries (prevents SQL Injection)
  - No raw string formatting in SQL
  - Principle of Least Privilege (read-only vs admin roles)
  - Sensitive data encrypted at rest (AES via Fernet)
  - Audit log for all database operations
  - Input validation before any DB interaction
  - Safe error messages (no DB internals exposed)
"""

import sqlite3
import secrets
import re
import os
import json
from datetime import datetime

# ── Optional: Fernet encryption ──────────────────────
try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("[INFO] cryptography not installed. Sensitive fields stored as plaintext.")

DB_FILE = "secure_app.db"
KEY_FILE = "secret.key"
AUDIT_FILE = "db_audit.log"


# ── Encryption Setup ──────────────────────────────────
def load_or_create_key() -> bytes:
    if ENCRYPTION_AVAILABLE:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    return b""

FERNET_KEY = load_or_create_key()
cipher = Fernet(FERNET_KEY) if ENCRYPTION_AVAILABLE else None

def encrypt(value: str) -> str:
    if cipher:
        return cipher.encrypt(value.encode()).decode()
    return value  # fallback: store as-is

def decrypt(value: str) -> str:
    if cipher:
        return cipher.decrypt(value.encode()).decode()
    return value


# ── Audit Logging ─────────────────────────────────────
def audit_log(action: str, detail: str, user: str = "system"):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "user": user,
        "action": action,
        "detail": detail
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Input Validation ──────────────────────────────────
def validate_name(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z\s]{1,50}$', name))

def validate_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email))

def validate_phone(phone: str) -> bool:
    return bool(re.match(r'^\+?[0-9\-\s]{7,15}$', phone))


# ── Database Manager ──────────────────────────────────
class SecureDatabase:
    def __init__(self, role: str = "readonly"):
        """
        role = 'admin'    -> can INSERT, UPDATE, DELETE
        role = 'readonly' -> can only SELECT
        """
        self.role = role
        self.conn = sqlite3.connect(DB_FILE)
        self.conn.row_factory = sqlite3.Row
        self._setup()

    def _setup(self):
        """Create tables if they don't exist."""
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    name    TEXT NOT NULL,
                    email   TEXT NOT NULL UNIQUE,
                    phone   TEXT,
                    created TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _require_role(self, required: str):
        if self.role != required:
            raise PermissionError(f"This action requires '{required}' role. Current role: '{self.role}'.")

    def add_user(self, name: str, email: str, phone: str = "", actor: str = "system"):
        """Insert a user with parameterized query. Sensitive fields encrypted."""
        self._require_role("admin")

        if not validate_name(name):
            return "[ERROR] Invalid name."
        if not validate_email(email):
            return "[ERROR] Invalid email."
        if phone and not validate_phone(phone):
            return "[ERROR] Invalid phone number."

        # Encrypt sensitive fields
        enc_email = encrypt(email)
        enc_phone = encrypt(phone) if phone else ""

        try:
            # SECURE: parameterized query — no string formatting
            with self.conn:
                self.conn.execute(
                    "INSERT INTO users (name, email, phone) VALUES (?, ?, ?)",
                    (name, enc_email, enc_phone)
                )
            audit_log("INSERT", f"Added user: {name}", user=actor)
            return f"[OK] User '{name}' added."
        except sqlite3.IntegrityError:
            return "[ERROR] Email already exists."

    def get_user(self, user_id: int, actor: str = "system"):
        """Fetch user by ID with parameterized query."""
        if not isinstance(user_id, int) or user_id <= 0:
            return "[ERROR] Invalid user ID."

        # Secure: no f-string or % formatting in SQL
        row = self.conn.execute(
            "SELECT id, name, email, phone, created FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not row:
            audit_log("SELECT", f"User {user_id} not found", user=actor)
            return "[ERROR] User not found."

        audit_log("SELECT", f"Fetched user ID {user_id}", user=actor)
        return {
            "id": row["id"],
            "name": row["name"],
            "email": decrypt(row["email"]),
            "phone": decrypt(row["phone"]) if row["phone"] else "",
            "created": row["created"]
        }

    def search_users(self, name_query: str, actor: str = "system"):
        """Search users by name — safely parameterized with LIKE."""
        if not re.match(r'^[a-zA-Z\s]{1,50}$', name_query):
            return "[ERROR] Invalid search query."

        rows = self.conn.execute(
            "SELECT id, name FROM users WHERE name LIKE ?",
            (f"%{name_query}%",)
        ).fetchall()

        audit_log("SEARCH", f"Search: '{name_query}', Results: {len(rows)}", user=actor)
        return [{"id": r["id"], "name": r["name"]} for r in rows]

    def delete_user(self, user_id: int, actor: str = "system"):
        """Delete user — admin only."""
        self._require_role("admin")
        if not isinstance(user_id, int) or user_id <= 0:
            return "[ERROR] Invalid user ID."
        with self.conn:
            cursor = self.conn.execute(
                "DELETE FROM users WHERE id = ?", (user_id,)
            )
        if cursor.rowcount == 0:
            return "[ERROR] User not found."
        audit_log("DELETE", f"Deleted user ID {user_id}", user=actor)
        return f"[OK] User ID {user_id} deleted."

    def close(self):
        self.conn.close()


# ── Demo ──────────────────────────────────────────────
if __name__ == "__main__":
    # Remove old DB for clean demo
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    print("=== PROJECT 4: SECURE DATABASE SECURITY ===\n")

    admin_db = SecureDatabase(role="admin")
    read_db  = SecureDatabase(role="readonly")

    print("-- Add Users (Admin Role) --")
    print(admin_db.add_user("Alice Reyes",   "alice@example.com",  "+63-912-000-0001", actor="admin"))
    print(admin_db.add_user("Bob Dela Cruz", "bob@example.com",    "+63-917-000-0002", actor="admin"))
    print(admin_db.add_user("Alice Reyes",   "alice@example.com",  actor="admin"))  # duplicate

    print("\n-- SQL Injection Attempt (Blocked by Parameterization) --")
    result = admin_db.add_user("'; DROP TABLE users; --", "hack@evil.com", actor="attacker")
    print(result)

    print("\n-- Fetch User (Decrypts Sensitive Fields) --")
    print(admin_db.get_user(1, actor="admin"))

    print("\n-- Search Users --")
    print(admin_db.search_users("Alice", actor="admin"))

    print("\n-- Readonly Role Cannot Write --")
    try:
        read_db.add_user("Eve", "eve@example.com", actor="readonly_user")
    except PermissionError as e:
        print(f"  [BLOCKED] {e}")

    print("\n-- Delete User --")
    print(admin_db.delete_user(2, actor="admin"))
    print(admin_db.get_user(2, actor="admin"))

    admin_db.close()
    read_db.close()
    print(f"\nAudit log saved to: {AUDIT_FILE}")
