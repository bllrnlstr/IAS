

import re
import html
import ipaddress


# ── SQL Injection Detection ───────────────────────────
SQL_PATTERNS = [
    r"(--|\#)",
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b",
    r"('|\"|;|\\)",
    r"\bOR\b.+?=.+?",
    r"\bAND\b.+?=.+?",
    r"xp_cmdshell",
    r"SLEEP\s*\(",
    r"BENCHMARK\s*\(",
]

def detect_sql_injection(value: str) -> bool:
    for p in SQL_PATTERNS:
        if re.search(p, value, re.IGNORECASE):
            return True
    return False


# ── XSS Detection ────────────────────────────────────
XSS_PATTERNS = [
    r"<\s*script.*?>",
    r"javascript\s*:",
    r"on\w+\s*=",
    r"<\s*iframe.*?>",
    r"<\s*img.*?onerror.*?>",
    r"eval\s*\(",
    r"document\.(cookie|write|location)",
    r"window\.(location|open)",
]

def detect_xss(value: str) -> bool:
    for p in XSS_PATTERNS:
        if re.search(p, value, re.IGNORECASE):
            return True
    return False


# ── Command Injection Detection ───────────────────────
CMD_PATTERNS = [
    r"[;&|`$]",
    r"\.\./",
    r"\b(cat|ls|rm|wget|curl|bash|sh|python|perl|nc|netcat)\b",
    r">(>)?|<",
]

def detect_command_injection(value: str) -> bool:
    for p in CMD_PATTERNS:
        if re.search(p, value, re.IGNORECASE):
            return True
    return False


# ── Safe Output Encoding ──────────────────────────────
def safe_encode(value: str) -> str:
    return html.escape(value, quote=True)


# ── Field Validators ──────────────────────────────────
def validate_email(email: str) -> tuple:
    email = email.strip()
    if len(email) > 254:
        return False, "Email too long."
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email format."
    if detect_sql_injection(email) or detect_xss(email):
        return False, "Malicious content detected."
    return True, email

def validate_integer(value: str, min_val=None, max_val=None) -> tuple:
    try:
        num = int(value)
    except (ValueError, TypeError):
        return False, "Not a valid integer."
    if min_val is not None and num < min_val:
        return False, f"Value must be >= {min_val}."
    if max_val is not None and num > max_val:
        return False, f"Value must be <= {max_val}."
    return True, num

def validate_name(name: str, max_len=50) -> tuple:
    name = name.strip()
    if not name:
        return False, "Name cannot be empty."
    if len(name) > max_len:
        return False, f"Name too long (max {max_len})."
    if not re.match(r"^[a-zA-Z\s'\-]+$", name):
        return False, "Name contains invalid characters."
    if detect_sql_injection(name) or detect_xss(name) or detect_command_injection(name):
        return False, "Malicious content detected."
    return True, safe_encode(name)

def validate_ip_address(ip: str) -> tuple:
    try:
        return True, str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return False, "Invalid IP address."

def validate_url(url: str) -> tuple:
    url = url.strip()
    if len(url) > 2048:
        return False, "URL too long."
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return False, "URL must start with http:// or https://"
    if re.search(r'javascript:', url, re.IGNORECASE) or detect_xss(url):
        return False, "Malicious content detected in URL."
    return True, url

def validate_free_text(text: str, max_len=500) -> tuple:
    text = text.strip()
    if len(text) > max_len:
        return False, f"Exceeds {max_len} character limit."
    if detect_sql_injection(text):
        return False, "Potential SQL injection detected."
    if detect_xss(text):
        return False, "Potential XSS attack detected."
    if detect_command_injection(text):
        return False, "Potential command injection detected."
    return True, safe_encode(text)


# ── Demo ──────────────────────────────────────────────
def test(label, func, *args):
    ok, result = func(*args)
    print(f"  {'[OK]' if ok else '[BLOCKED]'} {label}: {result}")

if __name__ == "__main__":
    print("=== PROJECT 2: SECURE INPUT VALIDATION ===\n")

    print("-- Email --")
    test("Valid email",        validate_email, "user@example.com")
    test("SQL in email",       validate_email, "admin'--@test.com")
    test("XSS in email",       validate_email, "<script>@evil.com")

    print("\n-- Name --")
    test("Valid name",         validate_name, "Maria Santos")
    test("SQL injection",      validate_name, "Robert'); DROP TABLE users;--")
    test("Command injection",  validate_name, "Alice; rm -rf /")

    print("\n-- Integer --")
    test("Valid age",          validate_integer, "25", 1, 120)
    test("Out of range",       validate_integer, "200", 1, 120)
    test("Not a number",       validate_integer, "abc")

    print("\n-- IP Address --")
    test("Valid IPv4",         validate_ip_address, "192.168.1.1")
    test("Invalid IP",         validate_ip_address, "999.999.0.1")

    print("\n-- URL --")
    test("Valid HTTPS URL",    validate_url, "https://www.example.com")
    test("Javascript URL",     validate_url, "javascript:alert(1)")

    print("\n-- Free Text --")
    test("Normal comment",     validate_free_text, "Great product!")
    test("SQL injection",      validate_free_text, "1' OR '1'='1")
    test("XSS attempt",        validate_free_text, "<img src=x onerror=alert(1)>")

    print("\n-- Safe Encoding --")
    raw = '<script>alert("XSS")</script>'
    print(f"  Raw    : {raw}")
    print(f"  Encoded: {safe_encode(raw)}")
