
import logging
import secrets
import re
import os
import traceback
from datetime import datetime
from functools import wraps


LOG_FILE = "secure_errors.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("SecureApp")


# ── Sanitize Log Input (Prevent Log Injection) ────────
def sanitize_log(value: str) -> str:
    """Remove newlines and control chars to prevent log injection."""
    return re.sub(r'[\r\n\t\x00-\x1f]', ' ', str(value))


# ── Secure Error Response ─────────────────────────────
def secure_error_response(error_id: str, user_message: str) -> dict:
    """Return a safe, generic response for the user."""
    return {
        "success": False,
        "error_id": error_id,
        "message": user_message,
        "timestamp": datetime.utcnow().isoformat()
    }


# ── Centralized Error Handler ─────────────────────────
def handle_error(exc: Exception, context: str = "General") -> dict:
    """
    Log detailed error internally, return only safe info to user.
    The user NEVER sees stack traces or system details.
    """
    error_id = secrets.token_hex(8).upper()  # e.g. "A3F2B1C9"
    safe_context = sanitize_log(context)
    tb = sanitize_log(traceback.format_exc())

    # Log full details server-side only
    logger.error(
        f"[{error_id}] Context: {safe_context} | "
        f"Type: {type(exc).__name__} | "
        f"Message: {sanitize_log(str(exc))} | "
        f"Traceback: {tb}"
    )

    # Map exception types to generic user messages
    user_message = classify_error(exc)
    print(f"  [LOG -> {LOG_FILE}] Error {error_id}: {type(exc).__name__} in '{safe_context}'")
    return secure_error_response(error_id, user_message)


def classify_error(exc: Exception) -> str:
    """Return a safe, generic message based on exception type."""
    error_map = {
        ValueError:       "Invalid input provided. Please check your data.",
        TypeError:        "An unexpected data format was received.",
        FileNotFoundError:"The requested resource could not be found.",
        PermissionError:  "You do not have permission to perform this action.",
        ZeroDivisionError:"A calculation error occurred.",
        KeyError:         "A required piece of information is missing.",
        AttributeError:   "An internal processing error occurred.",
        ConnectionError:  "Unable to connect to the service. Try again later.",
        TimeoutError:     "The request timed out. Please try again.",
    }
    for exc_type, message in error_map.items():
        if isinstance(exc, exc_type):
            return message
    return "An unexpected error occurred. Please contact support."


# ── Decorator for Automatic Error Handling ────────────
def secure_handler(func):
    """Wrap a function to automatically catch and handle errors securely."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return {"success": True, "data": func(*args, **kwargs)}
        except Exception as e:
            return handle_error(e, context=func.__name__)
    return wrapper


# ── Example Application Functions ─────────────────────
@secure_handler
def divide(a, b):
    return a / b  # Will raise ZeroDivisionError if b=0

@secure_handler
def get_user(user_id: str):
    users = {"101": "Alice", "102": "Bob"}
    if user_id not in users:
        raise KeyError(f"User '{user_id}' not found in database.")
    return users[user_id]

@secure_handler
def read_config(path: str):
    # Prevent path traversal
    if ".." in path or path.startswith("/"):
        raise PermissionError(f"Access denied to path: {path}")
    with open(path) as f:  # Will raise FileNotFoundError if missing
        return f.read()

@secure_handler
def parse_age(value: str):
    age = int(value)  # Will raise ValueError for non-numeric
    if age < 0 or age > 150:
        raise ValueError(f"Age {age} is out of valid range.")
    return age


# ── Demo ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== PROJECT 3: SECURE ERROR HANDLING ===\n")
    print(f"(Full error details are logged to '{LOG_FILE}')\n")

    print("-- Division --")
    print(f"  10 / 2  = {divide(10, 2)}")
    print(f"  10 / 0  = {divide(10, 0)}")

    print("\n-- User Lookup --")
    print(f"  ID 101  = {get_user('101')}")
    print(f"  ID 999  = {get_user('999')}")

    print("\n-- File Read --")
    print(f"  config.txt      = {read_config('config.txt')}")
    print(f"  Path traversal  = {read_config('../../etc/passwd')}")

    print("\n-- Age Parsing --")
    print(f"  '25'  = {parse_age('25')}")
    print(f"  'abc' = {parse_age('abc')}")
    print(f"  '999' = {parse_age('999')}")

    print(f"\n-- Log Injection Prevention --")
    malicious = "normal input\nFAKE LOG ENTRY | CRITICAL | hacked"
    print(f"  Raw input    : {repr(malicious)}")
    print(f"  Sanitized    : {repr(sanitize_log(malicious))}")

    print(f"\nAll internal error details saved to: {LOG_FILE}")
