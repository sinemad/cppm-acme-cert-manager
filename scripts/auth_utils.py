"""
auth_utils.py – Authentication utilities for the CPPM cert manager web UI.

Shared between status_server.py (web) and cppm_acme_manager_users.py (CLI).
Credentials are stored as bcrypt hashes in an htpasswd-format file on the
persistent volume so they survive container rebuilds.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

# ── Paths (all on the persistent volume) ─────────────────────────────────────
HTPASSWD_FILE       = Path(os.environ.get("HTPASSWD_FILE",       "/data/certs/admin.htpasswd"))
SESSION_SECRET_FILE = Path(os.environ.get("SESSION_SECRET_FILE", "/data/certs/.session-secret"))
SESSION_LIFETIME    = int(os.environ.get("SESSION_LIFETIME_HOURS", "8")) * 3600

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


# ── Session secret ────────────────────────────────────────────────────────────

def load_session_secret() -> bytes:
    """Load or generate the 32-byte HMAC session-signing secret."""
    if SESSION_SECRET_FILE.exists():
        return SESSION_SECRET_FILE.read_bytes()
    secret = secrets.token_bytes(32)
    SESSION_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_SECRET_FILE.write_bytes(secret)
    SESSION_SECRET_FILE.chmod(0o600)
    return secret


# ── Session tokens ────────────────────────────────────────────────────────────

def make_session_token(username: str, secret: bytes) -> str:
    """Return a URL-safe base64 token: base64(username|timestamp|hmac)."""
    ts = str(int(time.time()))
    payload = f"{username}|{ts}"
    sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def verify_session_token(token: str, secret: bytes) -> Optional[str]:
    """Verify signature and expiry. Returns username or None."""
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.split("|")
        if len(parts) != 3:
            return None
        username, ts_str, sig = parts
        payload = f"{username}|{ts_str}"
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if time.time() - int(ts_str) > SESSION_LIFETIME:
            return None
        return username
    except Exception:
        return None


# ── Credential store ──────────────────────────────────────────────────────────

def load_users() -> dict:
    """Return {username: bcrypt_hash} from the htpasswd file."""
    if not HTPASSWD_FILE.exists():
        return {}
    users = {}
    for line in HTPASSWD_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            u, h = line.split(":", 1)
            users[u.strip()] = h.strip()
    return users


def verify_password(password: str, hashed: str) -> bool:
    """Check plaintext password against a bcrypt hash from the htpasswd file."""
    if not HAS_BCRYPT:
        return False
    try:
        # htpasswd uses $2y$ prefix; Python bcrypt uses $2b$ — they are equivalent
        normalised = hashed.replace("$2y$", "$2b$").encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), normalised)
    except Exception:
        return False


def save_user(username: str, password: str) -> None:
    """Add or update a user in the htpasswd file. Raises ValueError on bad input."""
    if not HAS_BCRYPT:
        raise RuntimeError("py3-bcrypt not installed — rebuild the Docker image.")
    if not _USERNAME_RE.match(username):
        raise ValueError(
            f"Invalid username '{username}'. "
            "Use letters, digits, hyphens, or underscores (1–64 chars)."
        )
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    # rounds=10 is the bcrypt default and takes ~100 ms on modern hardware.
    # rounds=12 takes ~400 ms but can reach several seconds on low-power devices,
    # which stalls the single-threaded HTTP server for the duration of the hash.
    # Admin credential hashing happens rarely enough that 10 rounds is sufficient.
    _rounds = int(os.environ.get("BCRYPT_ROUNDS", "10"))
    hashed = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=_rounds)
    ).decode("utf-8")
    users = load_users()
    users[username] = hashed
    _write_htpasswd(users)


def delete_user(username: str) -> bool:
    """Remove a user. Returns True if found and removed."""
    users = load_users()
    if username not in users:
        return False
    del users[username]
    if users:
        _write_htpasswd(users)
    else:
        HTPASSWD_FILE.unlink(missing_ok=True)
    return True


def needs_setup() -> bool:
    """True when no admin users have been created yet."""
    return not load_users()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _write_htpasswd(users: dict) -> None:
    HTPASSWD_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{u}:{h}" for u, h in sorted(users.items())]
    HTPASSWD_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    HTPASSWD_FILE.chmod(0o600)
