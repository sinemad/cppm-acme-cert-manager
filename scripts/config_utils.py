"""
config_utils.py — ClearPass server / ACME mapping configuration storage.

One JSON file on the persistent volume holds all server entries.  Each entry
maps a ClearPass Policy Manager server to its ACME certificate authority and
DNS provider configuration, making it possible to manage certificates for
multiple independent ClearPass deployments from a single container instance.

File location: /data/certs/servers.json  (chmod 600 — contains secrets)
"""

import json
import os
import shlex
import uuid
from pathlib import Path
from typing import Optional

SERVERS_FILE = Path(os.environ.get("SERVERS_FILE", "/data/certs/servers.json"))

_REQUIRED = {
    "label", "cppm_host", "cppm_client_id", "cppm_client_secret",
    "domain", "acme_email", "acme_server", "dns_provider",
}

_FIELD_LABELS = {
    "label":             "Label",
    "cppm_host":         "ClearPass Host",
    "cppm_client_id":    "Client ID",
    "cppm_client_secret":"Client Secret",
    "domain":            "Domain",
    "acme_email":        "ACME Email",
    "acme_server":       "ACME Server",
    "dns_provider":      "DNS Provider",
}


# ── Read / write ──────────────────────────────────────────────────────────────

def load_servers() -> list:
    """Return list of server config dicts. Returns [] on missing or corrupt file."""
    if not SERVERS_FILE.exists():
        return []
    try:
        data = json.loads(SERVERS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_server(server_id: str) -> Optional[dict]:
    """Return a copy of the entry with the given ID, or None."""
    for s in load_servers():
        if s.get("id") == server_id:
            return dict(s)
    return None


# ── Validation ────────────────────────────────────────────────────────────────

def validate_server(entry: dict) -> None:
    """Raises ValueError on missing or invalid fields."""
    for field in _REQUIRED:
        if not str(entry.get(field, "")).strip():
            label = _FIELD_LABELS.get(field, field)
            raise ValueError(f"{label} is required.")
    try:
        port = int(entry.get("cppm_callback_port", 8765))
        if not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("Callback port must be a number between 1 and 65535.")
    cert_types = entry.get("cert_types") or []
    if not any(t in cert_types for t in ("ecc", "rsa")):
        raise ValueError("At least one certificate type (ECC or RSA) must be selected.")


# ── CRUD ──────────────────────────────────────────────────────────────────────

def _check_duplicate_host(host: str, exclude_id: str = None) -> None:
    """Raise ValueError if another entry already uses the same cppm_host."""
    host = host.strip().lower()
    for s in load_servers():
        if s.get("id") == exclude_id:
            continue
        if s.get("cppm_host", "").strip().lower() == host:
            label = s.get("label") or s.get("cppm_host", "")
            raise ValueError(
                f"A server entry for '{s.get('cppm_host', '')}' already exists "
                f"('{label}'). Each ClearPass host must be unique."
            )


def add_server(entry: dict) -> str:
    """Validate, check for duplicate host, and append. Returns the assigned server ID."""
    validate_server(entry)
    _check_duplicate_host(entry.get("cppm_host", ""))
    entry = dict(entry)
    entry["id"] = str(uuid.uuid4())
    servers = load_servers()
    servers.append(entry)
    _write(servers)
    return entry["id"]


def update_server(server_id: str, entry: dict) -> bool:
    """Replace the existing entry with the given ID. Returns True if found."""
    validate_server(entry)
    _check_duplicate_host(entry.get("cppm_host", ""), exclude_id=server_id)
    servers = load_servers()
    for i, s in enumerate(servers):
        if s.get("id") == server_id:
            entry = dict(entry)
            entry["id"] = server_id
            servers[i] = entry
            _write(servers)
            return True
    return False


def delete_server(server_id: str) -> bool:
    """Remove the entry with the given ID. Returns True if found."""
    servers = load_servers()
    filtered = [s for s in servers if s.get("id") != server_id]
    if len(filtered) == len(servers):
        return False
    if filtered:
        _write(filtered)
    else:
        SERVERS_FILE.unlink(missing_ok=True)
    return True


# ── Migration ─────────────────────────────────────────────────────────────────

def migrate_from_env() -> Optional[str]:
    """
    One-time backwards-compatibility migration.

    If servers.json is empty/missing AND the container environment contains a
    recognisable single-server configuration (DOMAIN + CPPM_HOST at minimum),
    create the first server entry automatically so the cert pipeline has
    something to work with on the first start after upgrading.

    Returns a human-readable status string if migration occurred, None if
    servers are already configured or there is nothing to migrate.
    """
    if load_servers():
        return None

    domain   = os.environ.get("DOMAIN",    "").strip()
    cppm_host = os.environ.get("CPPM_HOST", "").strip()
    if not domain or not cppm_host:
        return None

    entry = {
        "label":                f"ClearPass ({cppm_host})",
        "cppm_host":            cppm_host,
        "cppm_client_id":       os.environ.get("CPPM_CLIENT_ID",       ""),
        "cppm_client_secret":   os.environ.get("CPPM_CLIENT_SECRET",   ""),
        "cppm_verify_ssl":      os.environ.get("CPPM_VERIFY_SSL", "false").lower() == "true",
        "cppm_cert_passphrase": os.environ.get("CPPM_CERT_PASSPHRASE", ""),
        "cppm_callback_host":   os.environ.get("CPPM_CALLBACK_HOST",   ""),
        "cppm_callback_port":   os.environ.get("CPPM_CALLBACK_PORT",   "8765"),
        "domain":               domain,
        "acme_email":           os.environ.get("ACME_EMAIL",           ""),
        "acme_server":          os.environ.get("ACME_SERVER",          "letsencrypt"),
        "dns_provider":         os.environ.get("DNS_PROVIDER",         "cloudflare"),
        "dns_credentials": {k: v for k, v in {
            "CF_Token":               os.environ.get("CF_Token",               ""),
            "CF_Account_ID":          os.environ.get("CF_Account_ID",          ""),
            "CF_Zone_ID":             os.environ.get("CF_Zone_ID",             ""),
            "CF_Key":                 os.environ.get("CF_Key",                 ""),
            "CF_Email":               os.environ.get("CF_Email",               ""),
            "PORKBUN_API_KEY":        os.environ.get("PORKBUN_API_KEY",        ""),
            "PORKBUN_SECRET_API_KEY": os.environ.get("PORKBUN_SECRET_API_KEY", ""),
            "AWS_ACCESS_KEY_ID":      os.environ.get("AWS_ACCESS_KEY_ID",      ""),
            "AWS_SECRET_ACCESS_KEY":  os.environ.get("AWS_SECRET_ACCESS_KEY",  ""),
            "AWS_DEFAULT_REGION":     os.environ.get("AWS_DEFAULT_REGION",     "us-east-1"),
            "DO_API_KEY":             os.environ.get("DO_API_KEY",             ""),
            "GD_Key":                 os.environ.get("GD_Key",                 ""),
            "GD_Secret":              os.environ.get("GD_Secret",              ""),
        }.items() if v},
    }

    server_id = str(uuid.uuid4())
    entry["id"] = server_id
    _write([entry])
    return f"'{entry['label']}' migrated from .env (ID: {server_id})"


# ── Shell environment export ───────────────────────────────────────────────────

def get_server_shell_env(server_id: str) -> Optional[str]:
    """
    Return a shell-sourceable string of 'export KEY=VALUE' lines for the
    given server entry, suitable for eval in bash scripts.

    All values are quoted with shlex.quote so special characters in passwords
    are handled correctly.  Returns None if the server ID is not found.
    """
    s = get_server(server_id)
    if not s:
        return None

    creds = s.get("dns_credentials") or {}

    trust_excl = s.get("trust_exclusions") or []
    env: dict[str, str] = {
        "DOMAIN":               str(s.get("domain",               "")),
        "ACME_EMAIL":           str(s.get("acme_email",           "")),
        "ACME_SERVER":          str(s.get("acme_server",          "letsencrypt")),
        "DNS_PROVIDER":         str(s.get("dns_provider",         "")),
        "CPPM_HOST":            str(s.get("cppm_host",            "")),
        "CPPM_CLIENT_ID":       str(s.get("cppm_client_id",       "")),
        "CPPM_CLIENT_SECRET":   str(s.get("cppm_client_secret",   "")),
        "CPPM_VERIFY_SSL":      "true" if s.get("cppm_verify_ssl") else "false",
        "CPPM_CERT_PASSPHRASE": str(s.get("cppm_cert_passphrase", "")),
        "CPPM_CALLBACK_HOST":   str(s.get("cppm_callback_host",   "")),
        "CPPM_CALLBACK_PORT":   str(s.get("cppm_callback_port",   "8765")),
        "TRUST_EXCLUSIONS":     "\n".join(str(p) for p in trust_excl if p),
        "ISSUE_ECC":            "true" if "ecc" in (s.get("cert_types") or ["ecc", "rsa"]) else "false",
        "ISSUE_RSA":            "true" if "rsa" in (s.get("cert_types") or ["ecc", "rsa"]) else "false",
    }
    # DNS credential keys are already named as env vars in servers.json
    for k, v in creds.items():
        env[k] = str(v)

    lines = [f"export {k}={shlex.quote(v)}" for k, v in env.items()]
    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _write(servers: list) -> None:
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SERVERS_FILE.write_text(json.dumps(servers, indent=2), encoding="utf-8")
    SERVERS_FILE.chmod(0o600)
