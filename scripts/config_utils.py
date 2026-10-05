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

# ClearPass fields are always required: they are what the tool monitors and uploads to.
_REQUIRED = {"label", "cppm_host", "cppm_client_id", "cppm_client_secret"}

# ACME / DNS fields are optional as a group. All blank = ClearPass-only
# monitoring (warning, not an error). Partly filled or invalid = error, because
# the certificate pipeline would fail.
_LE_DNS_FIELDS = ("domain", "acme_email", "acme_server", "dns_provider")

# DNS credential options per provider, matching entrypoint.sh validate_dns_creds.
# Any one option with all its keys filled in is enough.
_DNS_CREDENTIAL_OPTIONS = {
    "cloudflare":   [("CF_Token",), ("CF_Key", "CF_Email")],
    "porkbun":      [("PORKBUN_API_KEY", "PORKBUN_SECRET_API_KEY")],
    "route53":      [("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")],
    "digitalocean": [("DO_API_KEY",)],
    "godaddy":      [("GD_Key", "GD_Secret")],
}
_DNS_PROVIDER_ALIASES = {"cf": "cloudflare", "aws": "route53", "r53": "route53",
                         "do": "digitalocean", "gd": "godaddy"}

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

def certificate_targets(entry: dict) -> list[str]:
    """Return normalized ClearPass targets, including legacy config values."""
    targets = set(entry.get("cert_types") or [])
    if "ecc" in targets:
        targets.add("https_ecc")
    if "rsa" in targets:
        targets.update(("radius", "radsec"))
    return [t for t in ("https_ecc", "https_rsa", "radius", "radsec") if t in targets]


def san_dns_names(entry: dict) -> list[str]:
    """Return up to ten normalized optional SAN DNS names."""
    primary = str(entry.get("domain", "")).strip().lower()
    values = entry.get("san_dns") or []
    if isinstance(values, str):
        values = values.replace(",", "\n").splitlines()
    result: list[str] = []
    for value in values:
        name = str(value).strip().lower()
        if name and name != primary and name not in result:
            result.append(name)
    return result[:10]

def le_dns_configured(entry: dict) -> bool:
    """True if any ACME / DNS field is filled in."""
    return any(str(entry.get(f, "")).strip() for f in _LE_DNS_FIELDS)


def le_dns_problems(entry: dict) -> list[str]:
    """Return errors for a partly filled or invalid ACME / DNS setup.

    Called only when le_dns_configured() is true. Checks shape and required
    credentials, not live API access.
    """
    problems = []
    for field in _LE_DNS_FIELDS:
        if not str(entry.get(field, "")).strip():
            problems.append(f"{_FIELD_LABELS.get(field, field)} is required when ACME / DNS is set up.")
    if problems:
        return problems

    email = str(entry.get("acme_email", "")).strip()
    if "@" not in email:
        problems.append("ACME Email must be an email address.")
    acme = str(entry.get("acme_server", "")).strip()
    if acme not in ("letsencrypt", "zerossl") and not acme.startswith("https://"):
        problems.append("ACME Server must be 'letsencrypt', 'zerossl', or an https:// URL.")

    provider = str(entry.get("dns_provider", "")).strip().lower()
    provider = _DNS_PROVIDER_ALIASES.get(provider, provider)
    creds = entry.get("dns_credentials") or {}
    if provider not in _DNS_CREDENTIAL_OPTIONS:
        # Unknown providers are allowed; credentials can't be pre-checked.
        return problems
    options = _DNS_CREDENTIAL_OPTIONS[provider]
    if not any(all(str(creds.get(k, "")).strip() for k in opt) for opt in options):
        wanted = " or ".join(" + ".join(opt) for opt in options)
        problems.append(f"DNS credentials for {provider} are incomplete: need {wanted}.")
    return problems


def validate_server(entry: dict) -> None:
    """Raises ValueError on missing or invalid fields."""
    for field in _REQUIRED:
        if not str(entry.get(field, "")).strip():
            label = _FIELD_LABELS.get(field, field)
            raise ValueError(f"{label} is required.")
    if le_dns_configured(entry):
        problems = le_dns_problems(entry)
        if problems:
            raise ValueError(" ".join(problems))
    try:
        port = int(entry.get("cppm_callback_port", 8765))
        if not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("Callback port must be a number between 1 and 65535.")
    cert_types = certificate_targets(entry)
    valid_types = {"https_ecc", "https_rsa", "radius", "radsec"}
    if not any(t in cert_types for t in valid_types):
        raise ValueError("At least one ClearPass certificate target must be selected.")


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


def _inherit_certificate_profile(entry: dict, exclude_id: str = None) -> dict:
    """Fill shared ACME fields from an existing explicit certificate profile."""
    profile_id = str(entry.get("certificate_id", "")).strip()
    if not profile_id:
        return entry
    for existing in load_servers():
        if existing.get("id") == exclude_id:
            continue
        if str(existing.get("certificate_id", "")).strip() != profile_id:
            continue
        merged = dict(entry)
        for field in (
            "domain", "san_dns", "acme_email", "acme_server",
            "dns_provider", "dns_credentials", "cert_types",
        ):
            if field in existing:
                value = existing[field]
                merged[field] = dict(value) if field == "dns_credentials" else (
                    list(value) if isinstance(value, list) else value
                )
        return merged
    return entry


def add_server(entry: dict) -> str:
    """Validate, check for duplicate host, and append. Returns the assigned server ID."""
    entry = _inherit_certificate_profile(dict(entry))
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
    entry = _inherit_certificate_profile(dict(entry), exclude_id=server_id)
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
        "certificate_id": re.sub(r"[^\w.\-]", "_", domain).strip("._-") or "certificate",
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
        "cert_types": ["https_ecc", "https_rsa", "radius", "radsec"],
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
    """Return the shared certificate directory, or legacy target directory.

    Named by the sanitized ClearPass hostname so the layout is human-readable:
    /data/certs/certificates/prod-example/
      /data/certs/cppm-lab.example.com/
    """
    certificate_id = str(server.get("certificate_id", "")).strip()
    if certificate_id:
        safe = re.sub(r"[^\w.\-]", "_", certificate_id).strip("._-") or "certificate"
        return SERVERS_FILE.parent / "certificates" / safe

    host = str(server.get("cppm_host", "")).strip()
    safe = re.sub(r"[^\w.\-]", "_", host).strip("._-") or "default"
    return SERVERS_FILE.parent / safe


def certificate_id(server: dict) -> str:
    """Return the shared certificate profile ID, or the legacy target ID."""
    configured = str(server.get("certificate_id", "")).strip()
    if configured:
        return configured
    host = str(server.get("cppm_host", "")).strip()
    return re.sub(r"[^\w.\-]", "_", host).strip("._-") or "default"


def certificate_members(profile_id: str) -> list[dict]:
    """Return all ClearPass targets attached to a certificate profile."""
    return [s for s in load_servers() if certificate_id(s) == profile_id]


def list_certificate_profiles() -> list[dict]:
    """Return one representative server entry per distinct *explicit* certificate
    profile ID (the value typed into the Certificate Profile ID field — this is
    what _inherit_certificate_profile matches on, not the host-based fallback)."""
    profiles: list[dict] = []
    seen: set[str] = set()
    for server in load_servers():
        profile_id = str(server.get("certificate_id", "")).strip()
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        profiles.append(server)
    return profiles


def certificate_owner_ids() -> list[str]:
    """Return one target ID per certificate profile for ACME work."""
    owners: list[str] = []
    seen: set[str] = set()
    for server in load_servers():
        profile_id = certificate_id(server)
        if profile_id not in seen and server.get("id"):
            seen.add(profile_id)
            owners.append(str(server["id"]))
    return owners


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
        "CERTIFICATE_ID":       certificate_id(s),
        "DOMAIN":               str(s.get("domain",               "")),
        "SAN_DNS":              "|".join(san_dns_names(s)),
        "ACME_EMAIL":           str(s.get("acme_email",           "")),
        "ACME_SERVER":          str(s.get("acme_server",          "letsencrypt")),
        "DNS_PROVIDER":         str(s.get("dns_provider",         "")),
        "CPPM_HOST":            str(s.get("cppm_host",            "")),
        "CPPM_CLUSTER_MODE":    "true" if s.get("cppm_cluster_mode") else "false",
        "CPPM_CLIENT_ID":       str(s.get("cppm_client_id",       "")),
        "CPPM_CLIENT_SECRET":   str(s.get("cppm_client_secret",   "")),
        "CPPM_VERIFY_SSL":      "true" if s.get("cppm_verify_ssl") else "false",
        "CPPM_CERT_PASSPHRASE": str(s.get("cppm_cert_passphrase", "")),
        "CPPM_CALLBACK_HOST":   str(s.get("cppm_callback_host",   "")),
        "CPPM_CALLBACK_PORT":   str(s.get("cppm_callback_port",   "8765")),
        "ISSUE_ECC":            "true" if "https_ecc" in certificate_targets(s) else "false",
        "ISSUE_RSA":            "true" if any(t in certificate_targets(s) for t in ("https_rsa", "radius", "radsec")) else "false",
        "UPLOAD_HTTPS_ECC":     "true" if "https_ecc" in certificate_targets(s) else "false",
        "UPLOAD_HTTPS_RSA":     "true" if "https_rsa" in certificate_targets(s) else "false",
        "UPLOAD_RADIUS":        "true" if "radius" in certificate_targets(s) else "false",
        "UPLOAD_RADSEC":        "true" if "radsec" in certificate_targets(s) else "false",
        "SERVER_CERT_DIR":      str(server_cert_dir(s)),
        "SERVER_LOG_DIR":       str(server_cert_dir(s) / "logs"),
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

_TRAEFIK_CONFIG_FILE  = SERVERS_FILE.parent / "traefik.json"
_TRAEFIK_COMPOSE_FILE = SERVERS_FILE.parent / "docker-compose.traefik.yml"
_TRAEFIK_DYNAMIC_DIR  = SERVERS_FILE.parent / "traefik" / "dynamic"
_TRAEFIK_LOG_DIR      = SERVERS_FILE.parent / "traefik" / "logs"
_TRAEFIK_LOG_FILE     = _TRAEFIK_LOG_DIR / "traefik.log"

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
    """Persist Traefik config, rewrite the dynamic routing file, and write the compose overlay."""
    _TRAEFIK_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Write dynamic config first: if it fails, traefik.json is unchanged and
    # the two files stay consistent.
    _write_traefik_dynamic(cfg)
    _TRAEFIK_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    _TRAEFIK_CONFIG_FILE.chmod(0o600)
    # Keep the compose overlay in sync — write when enabled, remove when disabled
    # so the user can run one command without managing a separate file.
    if cfg.get("enabled") and cfg.get("host"):
        _TRAEFIK_LOG_DIR.mkdir(parents=True, exist_ok=True)
        _TRAEFIK_COMPOSE_FILE.write_text(generate_traefik_compose(cfg), encoding="utf-8")
    else:
        _TRAEFIK_COMPOSE_FILE.unlink(missing_ok=True)


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
        '      - "--log.filePath=/traefik-logs/traefik.log"',
        '      - "--log.level=INFO"',
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
        "      - ${CPPM_DATA_PATH:-/opt/cppm-certs}/traefik/logs:/traefik-logs",
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
        "",
    ]
    return "\n".join(lines)


def get_traefik_log(lines: int = 150) -> list:
    """Return the last N lines of the Traefik log file, newest last."""
    if not _TRAEFIK_LOG_FILE.exists():
        return []
    try:
        text = _TRAEFIK_LOG_FILE.read_text(encoding="utf-8", errors="replace")
        return text.splitlines()[-lines:]
    except Exception:
        return []


# ── Internal helpers ──────────────────────────────────────────────────────────

def _write(servers: list) -> None:
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SERVERS_FILE.write_text(json.dumps(servers, indent=2), encoding="utf-8")
    SERVERS_FILE.chmod(0o600)
