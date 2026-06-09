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
import re
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
        "cert_types": ["ecc", "rsa"],
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


# ── Per-server directory ──────────────────────────────────────────────────────

def server_cert_dir(server: dict) -> Path:
    """Return the per-server directory path under the data volume root.

    Named by the sanitized ClearPass hostname so the layout is human-readable:
      /data/certs/cppm.example.com/
      /data/certs/cppm-lab.example.com/
    """
    host = str(server.get("cppm_host", "")).strip()
    safe = re.sub(r"[^\w.\-]", "_", host).strip("._-") or "default"
    return SERVERS_FILE.parent / safe


# ── Shell environment export ───────────────────────────────────────────────────

def get_server_env_dict(server_id: str) -> Optional[dict]:
    """Return the per-server environment as a plain Python dict.

    Returns None if the server ID is not found.
    """
    s = get_server(server_id)
    if not s:
        return None

    creds = s.get("dns_credentials") or {}
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
        "ISSUE_ECC":            "true" if "ecc" in (s.get("cert_types") or ["ecc", "rsa"]) else "false",
        "ISSUE_RSA":            "true" if "rsa" in (s.get("cert_types") or ["ecc", "rsa"]) else "false",
        "SERVER_CERT_DIR":      str(server_cert_dir(s)),
        "SERVER_LOG_DIR":       str(server_cert_dir(s) / ".logs"),
        "STATUS_LOG":           str(server_cert_dir(s) / "status.log"),
        "SERVER_ID":            str(s.get("id", "")),
    }
    for k, v in creds.items():
        env[k] = str(v)
    return env


def get_server_shell_env(server_id: str) -> Optional[str]:
    """Return a shell-sourceable 'export KEY=VALUE' string for the given server.

    Returns None if the server ID is not found.
    """
    env = get_server_env_dict(server_id)
    if env is None:
        return None
    lines = [f"export {k}={shlex.quote(v)}" for k, v in env.items()]
    return "\n".join(lines)


# ── Notification config ───────────────────────────────────────────────────────

def get_server_notifications(server_id: str) -> dict:
    """Return the notifications block for a server, or an empty default."""
    s = get_server(server_id)
    if not s:
        return {"expiry_warning_days": 14, "channels": []}
    return s.get("notifications") or {"expiry_warning_days": 14, "channels": []}


def update_server_notifications(server_id: str, notifications: dict) -> bool:
    """Replace the notifications block for a server. Returns True if found."""
    servers = load_servers()
    for i, s in enumerate(servers):
        if s.get("id") == server_id:
            servers[i]["notifications"] = notifications
            _write(servers)
            return True
    return False


# ── Traefik integration ───────────────────────────────────────────────────────

_TRAEFIK_CONFIG_FILE = SERVERS_FILE.parent / "traefik.json"
_TRAEFIK_DYNAMIC_DIR = SERVERS_FILE.parent / "traefik" / "dynamic"

# Translate stored acme.sh-style credential names to Lego/Traefik env names.
# Mirrors _DNS_ENV_REMAP in lego_provider.py — keep in sync.
_TRAEFIK_DNS_REMAP: dict = {
    "CF_Token":           "CF_DNS_API_TOKEN",
    "CF_Key":             "CF_API_KEY",
    "CF_Email":           "CF_API_EMAIL",
    "DO_API_KEY":         "DO_AUTH_TOKEN",
    "GD_Key":             "GODADDY_API_KEY",
    "GD_Secret":          "GODADDY_API_SECRET",
    "AWS_DEFAULT_REGION": "AWS_REGION",
}
_TRAEFIK_DNS_DROP: frozenset = frozenset({"CF_Zone_ID", "CF_Account_ID"})


def get_traefik_config() -> dict:
    """Return the Traefik integration config, or empty defaults if not yet configured."""
    default: dict = {
        "enabled":      False,
        "host":         "",
        "email":        "",
        "challenge":    "http",
        "dns_provider": "cloudflare",
        "dns_credentials": {},
    }
    if not _TRAEFIK_CONFIG_FILE.exists():
        return default
    try:
        data = json.loads(_TRAEFIK_CONFIG_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default
        return {**default, **data}
    except Exception:
        return default


def save_traefik_config(cfg: dict) -> None:
    """Persist Traefik config and rewrite the dynamic routing file."""
    _TRAEFIK_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Write dynamic config first: if it fails, traefik.json is unchanged and
    # the two files stay consistent.
    _write_traefik_dynamic(cfg)
    _TRAEFIK_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    _TRAEFIK_CONFIG_FILE.chmod(0o600)


def _write_traefik_dynamic(cfg: dict) -> None:
    """Write (or clear) the Traefik file-provider dynamic routing config."""
    _TRAEFIK_DYNAMIC_DIR.mkdir(parents=True, exist_ok=True)
    dyn_file = _TRAEFIK_DYNAMIC_DIR / "cppm.yml"
    if not cfg.get("enabled") or not str(cfg.get("host", "")).strip():
        dyn_file.write_text(
            "# Managed by cppm-acme-cert-manager — Traefik disabled\n{}\n",
            encoding="utf-8",
        )
        return
    import datetime as _dt
    host = str(cfg["host"]).strip()
    ts   = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    content = "\n".join([
        "# Managed by cppm-acme-cert-manager — do not edit manually",
        f"# Updated: {ts}",
        "",
        "http:",
        "  routers:",
        "    cppm-ui:",
        f'      rule: "Host(`{host}`)"',
        "      entryPoints:",
        "        - websecure",
        "      tls:",
        "        certResolver: letsencrypt",
        "      service: cppm-ui",
        "",
        "  services:",
        "    cppm-ui:",
        "      loadBalancer:",
        "        servers:",
        '          - url: "http://cppm-acme-cert-manager:8080"',
        "",
    ])
    dyn_file.write_text(content, encoding="utf-8")


def generate_traefik_compose(cfg: dict) -> str:
    """Return a populated docker-compose.traefik.yml content string."""
    email     = str(cfg.get("email", "")).strip()
    challenge = cfg.get("challenge", "http")
    dns_prov  = cfg.get("dns_provider", "cloudflare")
    raw_creds = cfg.get("dns_credentials") or {}

    creds = {
        _TRAEFIK_DNS_REMAP.get(k, k): str(v)
        for k, v in raw_creds.items()
        if k not in _TRAEFIK_DNS_DROP and str(v).strip()
    }

    lines = [
        "# Auto-generated by cppm-acme-cert-manager",
        "# Apply with:",
        "#   docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d",
        "",
        "networks:",
        "  traefik_net:",
        "    driver: bridge",
        "",
        "services:",
        "",
        "  traefik:",
        "    image: traefik:v3.3",
        "    container_name: traefik",
        "    restart: unless-stopped",
        "    command:",
        '      - "--api.insecure=false"',
        '      - "--providers.file.directory=/etc/traefik/dynamic"',
        '      - "--providers.file.watch=true"',
        '      - "--entrypoints.web.address=:80"',
        '      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"',
        '      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"',
        '      - "--entrypoints.websecure.address=:443"',
        f'      - "--certificatesresolvers.letsencrypt.acme.email={email}"',
        '      - "--certificatesresolvers.letsencrypt.acme.storage=/acme/acme.json"',
    ]

    if challenge == "dns":
        lines += [
            '      - "--certificatesresolvers.letsencrypt.acme.dnschallenge=true"',
            f'      - "--certificatesresolvers.letsencrypt.acme.dnschallenge.provider={dns_prov}"',
        ]
        if creds:
            lines.append("    environment:")
            for k, v in sorted(creds.items()):
                lines.append(f'      {k}: "{v}"')
    else:
        lines += [
            '      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"',
            '      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"',
        ]

    lines += [
        "    ports:",
        '      - "80:80"',
        '      - "443:443"',
        "    volumes:",
        "      - traefik_acme:/acme",
        "      - ${CPPM_DATA_PATH:-/opt/cppm-certs}/traefik/dynamic:/etc/traefik/dynamic:ro",
        "    networks:",
        "      - traefik_net",
        "    logging:",
        '      driver: "json-file"',
        "      options:",
        '        max-size: "10m"',
        '        max-file: "3"',
        "",
        "  cppm-acme-cert-manager:",
        "    networks:",
        "      - traefik_net",
        "",
        "volumes:",
        "  traefik_acme:",
        "    driver: local",
        "    driver_opts:",
        "      type: none",
        "      o: bind",
        "      device: /opt/traefik-acme",
        "",
    ]
    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _write(servers: list) -> None:
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SERVERS_FILE.write_text(json.dumps(servers, indent=2), encoding="utf-8")
    SERVERS_FILE.chmod(0o600)
