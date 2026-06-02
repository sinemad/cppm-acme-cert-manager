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


# ── Internal helpers ──────────────────────────────────────────────────────────

def _write(servers: list) -> None:
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SERVERS_FILE.write_text(json.dumps(servers, indent=2), encoding="utf-8")
    SERVERS_FILE.chmod(0o600)
