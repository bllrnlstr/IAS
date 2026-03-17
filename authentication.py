

import hashlib
import secrets
import re
import time
import json
import os
from datetime import datetime, timedelta

# ── Config ────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300       # 5 minutes
SESSION_EXPIRY = 1800       # 30 minutes
DB_FILE = "auth_db.json"


# ── Password Hashing ──────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(32)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored: str) -> bool:
    salt, hashed = stored.split(":", 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == hashed


# ── Validation ────────────────────────────────────────
def validate_username(username: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_password(password: str) -> tuple:
    if len(password) < 8:
        return False, "At least 8 characters required."
    if not re.search(r'[A-Z]', password):
        return False, "Needs an uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Needs a lowercase letter."
    if not re.search(r'\d', password):
        return False, "Needs a digit."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Needs a special character."
    return True, "Strong password."


# ── Storage ───────────────────────────────────────────
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as f:
            return json.load(f)
    return {"users": {}, "sessions": {}}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


# ── Auth System ───────────────────────────────────────
class AuthSystem:
    def __init__(self):
        self.db = load_db()
        self.attempts = {}  # {username: [timestamps]}

    def _locked(self, username):
        now = time.time()
        recent = [t for t in self.attempts.get(username, []) if now - t < LOCKOUT_SECONDS]
        self.attempts[username] = recent
        if len(recent) >= MAX_LOGIN_ATTEMPTS:
            return True, int(LOCKOUT_SECONDS - (now - recent[0]))
        return False, 0

    def register(self, username, password):
        username = username.strip()
        if not validate_username(username):
            return "[ERROR] Username must be 3-20 alphanumeric/underscore chars."
        ok, msg = validate_password(password)
        if not ok:
            return f"[ERROR] {msg}"
        if username in self.db["users"]:
            return "[ERROR] Username already taken."
        self.db["users"][username] = {
            "hash": hash_password(password),
            "created": datetime.utcnow().isoformat()
        }
        save_db(self.db)
        return f"[OK] User '{username}' registered."

    def login(self, username, password):
        username = username.strip()
        locked, wait = self._locked(username)
        if locked:
            return f"[LOCKED] Too many attempts. Try again in {wait}s."
        user = self.db["users"].get(username)
        if not user or not verify_password(password, user["hash"]):
            self.attempts.setdefault(username, []).append(time.time())
            left = MAX_LOGIN_ATTEMPTS - len(self.attempts[username])
            return f"[ERROR] Wrong credentials. {max(0, left)} attempt(s) left."
        self.attempts[username] = []
        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(seconds=SESSION_EXPIRY)).isoformat()
        self.db["sessions"][token] = {"user": username, "expires": expires}
        save_db(self.db)
        return f"[OK] Logged in as '{username}'.\nToken: {token}\nExpires: {expires}"

    def validate_session(self, token):
        s = self.db["sessions"].get(token)
        if not s:
            return "[ERROR] Invalid token."
        if datetime.utcnow() > datetime.fromisoformat(s["expires"]):
            del self.db["sessions"][token]
            save_db(self.db)
            return "[ERROR] Session expired."
        return f"[OK] Active session for '{s['user']}'"

    def logout(self, token):
        if token in self.db["sessions"]:
            del self.db["sessions"][token]
            save_db(self.db)
            return "[OK] Logged out. Token invalidated."
        return "[ERROR] Token not found."


# ── Demo ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== PROJECT 1: SECURE AUTHENTICATION ===\n")
    auth = AuthSystem()

    print("-- Registration --")
    print(auth.register("alice_sec", "Hello@1234"))
    print(auth.register("alice_sec", "Hello@1234"))   # duplicate
    print(auth.register("bob", "weakpass"))            # weak password

    print("\n-- Login --")
    result = auth.login("alice_sec", "Hello@1234")
    print(result)

    token = None
    for line in result.split("\n"):
        if "Token:" in line:
            token = line.split(": ", 1)[1].strip()

    print("\n-- Session Validation --")
    if token:
        print(auth.validate_session(token))
        print(auth.logout(token))
        print(auth.validate_session(token))   # after logout

    print("\n-- Lockout Demo (wrong password x6) --")
    for i in range(6):
        print(auth.login("alice_sec", "wrongpass"))
