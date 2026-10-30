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

from dns_utils import DEFAULT_PUBLIC_RESOLVERS, parse_resolvers

SERVERS_FILE = Path(os.environ.get("SERVERS_FILE", "/data/certs/servers.json"))

# ClearPass fields are always required: they are what the tool monitors and uploads to.
_REQUIRED = {"label", "certificate_id", "cppm_host", "cppm_client_id", "cppm_client_secret"}

# Linux SSH targets need either a private key or a password, checked
# separately below since _REQUIRED_BY_TYPE only expresses "must be non-blank".
_REQUIRED_SSH = {"label", "certificate_id", "ssh_host", "ssh_user", "remote_cert_dir"}

# Required fields per target_type. "clearpass" is the only implemented type
# today; this map is the seam future target types (New Central, Mist, a
# generic Linux target, ...) hang their own required fields off of.
_REQUIRED_BY_TYPE = {"clearpass": _REQUIRED, "linux_ssh": _REQUIRED_SSH}

# ACME / DNS fields are optional as a group. All blank = ClearPass-only
# monitoring (warning, not an error). Partly filled or invalid = error, because
# the certificate pipeline would fail. DNS credential completeness is checked
# separately via the referenced DNS Credential (see le_dns_problems).
_LE_DNS_FIELDS = ("domain", "acme_email", "acme_server")

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
    "certificate_id":    "Certificate Profile ID",
    "cppm_host":         "ClearPass Host",
    "cppm_client_id":    "Client ID",
    "cppm_client_secret":"Client Secret",
    "domain":            "Domain",
    "acme_email":        "ACME Email",
    "acme_server":       "ACME Server",
    "dns_provider":      "DNS Provider",
    "dns_credential_id": "DNS Credential",
    "ssh_host":          "SSH Host",
    "ssh_user":          "SSH User",
    "remote_cert_dir":   "Remote Certificate Directory",
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

def _resolve_target_fields(entry: dict) -> dict:
    """Return entry with target_config flattened over its top-level fields.

    A target's type-specific config (today: ClearPass's cppm_*/cert_types
    fields) can live either as flat legacy fields, the way every existing
    servers.json entry stores them, or nested under a "target_config" dict,
    the way new entries will. This lets every reader work from one flat view
    without a migration step, and without the shape of one target_type
    leaking into another's.
    """
    resolved = dict(entry)
    resolved.update(entry.get("target_config") or {})
    return resolved


# Public alias — other modules (status_server.py, cppm_acme_manager_servers.py)
# need the same flattening to read a server entry regardless of target_type.
resolve_target_fields = _resolve_target_fields


def certificate_targets(entry: dict) -> list[str]:
    """Return normalized ClearPass targets, including legacy config values."""
    entry = _resolve_target_fields(entry)
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

def acme_dns_resolvers(entry: dict) -> list[str]:
    """Return the resolvers Lego should use for DNS-01 checks, as host:port.

    Empty unless split-horizon DNS is enabled, in which case it's the custom
    list or, if none is given, the default public resolvers. An empty result
    means Lego uses the container's own resolvers (Docker ``dns:``).
    Raises ValueError if a custom resolver is invalid.
    """
    if not entry.get("split_horizon_dns"):
        return []
    return parse_resolvers(entry.get("split_horizon_resolvers") or []) or list(DEFAULT_PUBLIC_RESOLVERS)


def le_dns_configured(entry: dict) -> bool:
    """True if any ACME / DNS field is filled in."""
    return bool(str(entry.get("dns_credential_id", "")).strip()) or \
        any(str(entry.get(f, "")).strip() for f in _LE_DNS_FIELDS)


def le_dns_problems(entry: dict) -> list[str]:
    """Return errors for a partly filled or invalid ACME / DNS setup.

    Called only when le_dns_configured() is true. Checks shape and required
    credentials (resolved through the referenced DNS Credential), not live
    API access.
    """
    problems = []
    for field in _LE_DNS_FIELDS:
        if not str(entry.get(field, "")).strip():
            problems.append(f"{_FIELD_LABELS.get(field, field)} is required when ACME / DNS is set up.")
    dns_credential_id = str(entry.get("dns_credential_id", "")).strip()
    if not dns_credential_id:
        problems.append("A DNS Credential is required when ACME / DNS is set up.")
    if problems:
        return problems

    email = str(entry.get("acme_email", "")).strip()
    if "@" not in email:
        problems.append("ACME Email must be an email address.")
    acme = str(entry.get("acme_server", "")).strip()
    if acme not in ("letsencrypt", "zerossl") and not acme.startswith("https://"):
        problems.append("ACME Server must be 'letsencrypt', 'zerossl', or an https:// URL.")

    credential = get_dns_credential(dns_credential_id)
    if credential is None:
        problems.append(f"DNS Credential '{dns_credential_id}' not found.")
        return problems
    provider = str(credential.get("dns_provider", "")).strip().lower()
    provider = _DNS_PROVIDER_ALIASES.get(provider, provider)
    creds = credential.get("dns_credentials") or {}
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
    resolved = _resolve_target_fields(entry)
    target_type = str(resolved.get("target_type", "clearpass") or "clearpass")
    required = _REQUIRED_BY_TYPE.get(target_type, _REQUIRED)
    for field in required:
        if not str(resolved.get(field, "")).strip():
            label = _FIELD_LABELS.get(field, field)
            raise ValueError(f"{label} is required.")
    if target_type == "linux_ssh":
        if not str(resolved.get("ssh_private_key", "")).strip() \
                and not str(resolved.get("ssh_password", "")).strip():
            raise ValueError("Either a private key or a password is required.")
    if le_dns_configured(resolved):
        problems = le_dns_problems(resolved)
        if problems:
            raise ValueError(" ".join(problems))
    try:
        acme_dns_resolvers(resolved)
    except ValueError as exc:
        raise ValueError(f"Split-horizon DNS resolvers: {exc}.") from None
    if target_type == "clearpass":
        try:
            port = int(resolved.get("cppm_callback_port", 8765))
            if not 1 <= port <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Callback port must be a number between 1 and 65535.")
        cert_types = certificate_targets(resolved)
        valid_types = {"https_ecc", "https_rsa", "radius", "radsec"}
        if not any(t in cert_types for t in valid_types):
            raise ValueError("At least one ClearPass certificate target must be selected.")


# ── CRUD ──────────────────────────────────────────────────────────────────────

def _check_duplicate_host(entry: dict, exclude_id: str = None) -> None:
    """Raise ValueError if another entry already targets the same host.

    Clearpass entries are deduped on cppm_host, linux_ssh entries on ssh_host
    — each target_type's uniqueness key is a property of its own fields, so
    an empty host of one type never collides with an empty host of another.
    """
    resolved = _resolve_target_fields(entry)
    target_type = str(resolved.get("target_type", "clearpass") or "clearpass")
    host_field = "ssh_host" if target_type == "linux_ssh" else "cppm_host"
    host = str(resolved.get(host_field, "")).strip().lower()
    if not host:
        return
    for s in load_servers():
        if s.get("id") == exclude_id:
            continue
        s = _resolve_target_fields(s)
        other_type = str(s.get("target_type", "clearpass") or "clearpass")
        if other_type != target_type:
            continue
        if s.get(host_field, "").strip().lower() == host:
            label = s.get("label") or s.get(host_field, "")
            raise ValueError(
                f"A server entry for '{s.get(host_field, '')}' already exists "
                f"('{label}'). Each {_FIELD_LABELS.get(host_field, host_field)} must be unique."
            )


# The cert-identity fields a certificate profile shares across every target
# that references it, regardless of target_type. DNS vendor credentials are
# NOT part of this bundle — they live in their own reusable DNS Credential
# entity (see "DNS Credentials" below) and are referenced by dns_credential_id,
# since the same DNS vendor account can be shared across profiles that can
# never share an identity (different domains/targets). Used both to pull
# these fields into a newly saved entry (_inherit_certificate_profile) and to
# push an edited value out to every entry sharing a profile
# (update_certificate_profile).
_SHARED_PROFILE_FIELDS = (
    "domain", "san_dns", "acme_email", "acme_server", "dns_credential_id",
    "cert_types", "split_horizon_dns", "split_horizon_resolvers",
    "eab_kid", "eab_hmac_key",
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
        for field in _SHARED_PROFILE_FIELDS:
            if field in existing:
                value = existing[field]
                merged[field] = list(value) if isinstance(value, list) else value
        return merged
    return entry


def add_server(entry: dict) -> str:
    """Validate, check for duplicate host, and append. Returns the assigned server ID."""
    entry = _inherit_certificate_profile(dict(entry))
    validate_server(entry)
    _check_duplicate_host(entry)
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
    _check_duplicate_host(entry, exclude_id=server_id)
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

def _slugify_certificate_id(value: str, default: str = "certificate") -> str:
    """Sanitize a free-form string into a safe certificate_id / directory-name token."""
    safe = re.sub(r"[^\w.\-]", "_", str(value)).strip("._-")
    return safe or default


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
        "certificate_id": _slugify_certificate_id(domain),
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
        return SERVERS_FILE.parent / "certificates" / _slugify_certificate_id(certificate_id)

    host = str(_legacy_host(server)).strip()
    return SERVERS_FILE.parent / _slugify_certificate_id(host, default="default")


def _legacy_host(server: dict) -> str:
    """Return the target-type-appropriate host used as a fallback directory key."""
    resolved = _resolve_target_fields(server)
    target_type = str(resolved.get("target_type", "clearpass") or "clearpass")
    if target_type == "linux_ssh":
        return str(resolved.get("ssh_host", ""))
    return str(resolved.get("cppm_host", ""))


def certificate_id(server: dict) -> str:
    """Return the shared certificate profile ID, or the legacy target ID."""
    configured = str(server.get("certificate_id", "")).strip()
    if configured:
        return configured
    host = str(_legacy_host(server)).strip()
    return _slugify_certificate_id(host, default="default")


def certificate_members(profile_id: str) -> list[dict]:
    """Return all ClearPass targets attached to a certificate profile."""
    return [s for s in load_servers() if certificate_id(s) == profile_id]


def backfill_certificate_ids() -> int:
    """Assign an explicit certificate_id to every entry that's missing one.

    certificate_id is now a required field (see validate_server), but
    entries written before that requirement existed may still have it
    blank. Uses the same host-based fallback certificate_id() already
    computes for cert-directory/trust-sync grouping, so this only makes
    that existing (implicit) grouping explicit — it doesn't change which
    entries are considered part of the same certificate. Run once at
    container startup (entrypoint.sh), before anything reads servers.json.
    """
    servers = load_servers()
    updated = list(servers)
    changed = 0
    for i, s in enumerate(servers):
        if str(s.get("certificate_id", "")).strip():
            continue
        merged = dict(s)
        merged["certificate_id"] = certificate_id(s)
        updated[i] = merged
        changed += 1
    if changed:
        _write(updated)
    return changed


def list_certificate_profiles() -> list[dict]:
    """Return one representative server entry per distinct *explicit* certificate
    profile ID (the value typed into the Certificate Profile ID field — this is
    what _inherit_certificate_profile matches on, not the host-based fallback).

    Entries are resolved (target_config flattened) so callers can read a
    profile's host/label the same way regardless of target_type."""
    profiles: list[dict] = []
    seen: set[str] = set()
    for server in load_servers():
        profile_id = str(server.get("certificate_id", "")).strip()
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        profiles.append(_resolve_target_fields(server))
    return profiles


def list_profile_members(profile_id: str) -> list[dict]:
    """Return every (resolved) entry whose explicit certificate_id matches.

    Same matching rule as _inherit_certificate_profile — the typed-in
    certificate_id field, not the host-based fallback certificate_members()
    uses for cert-directory/trust-sync purposes."""
    profile_id = str(profile_id).strip()
    if not profile_id:
        return []
    return [
        _resolve_target_fields(s) for s in load_servers()
        if str(s.get("certificate_id", "")).strip() == profile_id
    ]


def update_certificate_profile(profile_id: str, fields: dict) -> int:
    """Apply shared ACME/DNS fields to every entry sharing profile_id.

    All-or-nothing: every affected entry is validated with the merged fields
    before anything is written, so one entry's required fields (e.g. a
    clearpass sibling's cert_types) can't be silently broken by an edit made
    through the profile rather than through that entry. Returns the number
    of entries updated. Raises ValueError if the profile doesn't exist or if
    any affected entry would fail validation.
    """
    profile_id = str(profile_id).strip()
    servers = load_servers()
    indices = [i for i, s in enumerate(servers)
               if str(s.get("certificate_id", "")).strip() == profile_id]
    if not indices:
        raise ValueError("Certificate profile not found.")

    updated = list(servers)
    for i in indices:
        merged = dict(updated[i])
        for field in _SHARED_PROFILE_FIELDS:
            if field in fields:
                value = fields[field]
                merged[field] = list(value) if isinstance(value, list) else value
        validate_server(merged)
        updated[i] = merged

    _write(updated)
    return len(indices)


def delete_certificate_profile(profile_id: str) -> int:
    """Detach every entry sharing profile_id (clears certificate_id on each).

    Each entry keeps whatever ACME/DNS values it last had — this only stops
    them being linked, it does not delete any server entry."""
    profile_id = str(profile_id).strip()
    servers = load_servers()
    indices = [i for i, s in enumerate(servers)
               if str(s.get("certificate_id", "")).strip() == profile_id]
    if not indices:
        return 0
    updated = list(servers)
    for i in indices:
        merged = dict(updated[i])
        merged["certificate_id"] = ""
        updated[i] = merged
    _write(updated)
    return len(indices)


# Shared ID-format validator for both Certificate Profile IDs and DNS
# Credential IDs — same allowed charset, same rename/collision semantics.
_ID_PATTERN = re.compile(r"[A-Za-z0-9_.\-]+")
_CERT_ID_PATTERN = _ID_PATTERN  # back-compat alias


def rename_certificate_profile(old_id: str, new_id: str) -> int:
    """Rename a certificate profile's ID across every entry sharing it.

    Also moves the on-disk certificate directory (Lego account storage,
    issued certs, logs — see server_cert_dir()) so already-issued
    certificates survive the rename instead of looking "missing" to the
    pipeline and triggering a fresh issuance. Raises ValueError if new_id is
    invalid, collides with a different existing profile (by raw ID or by
    slugified directory name), or old_id doesn't match any entry. Returns
    the number of entries renamed (0 if new_id == old_id).
    """
    old_id = str(old_id).strip()
    new_id = str(new_id).strip()
    if not new_id:
        raise ValueError("Certificate Profile ID is required.")
    if not _CERT_ID_PATTERN.fullmatch(new_id):
        raise ValueError(
            "Certificate Profile ID may only contain letters, numbers, '.', '_', and '-'."
        )
    if new_id == old_id:
        return 0

    servers = load_servers()
    indices = [i for i, s in enumerate(servers)
               if str(s.get("certificate_id", "")).strip() == old_id]
    if not indices:
        raise ValueError("Certificate profile not found.")

    other_ids = {
        str(s.get("certificate_id", "")).strip() for s in servers
    } - {old_id}
    if new_id in other_ids:
        raise ValueError(f"'{new_id}' is already used by another certificate profile.")
    new_slug = _slugify_certificate_id(new_id)
    if new_slug in {_slugify_certificate_id(pid) for pid in other_ids if pid}:
        raise ValueError(
            f"'{new_id}' resolves to the same certificate directory as an existing profile."
        )

    old_dir = SERVERS_FILE.parent / "certificates" / _slugify_certificate_id(old_id)
    new_dir = SERVERS_FILE.parent / "certificates" / new_slug
    moved = False
    if old_dir.exists():
        if new_dir.exists():
            raise ValueError(f"Target certificate directory already exists: {new_dir}")
        new_dir.parent.mkdir(parents=True, exist_ok=True)
        old_dir.rename(new_dir)
        moved = True

    updated = list(servers)
    for i in indices:
        merged = dict(updated[i])
        merged["certificate_id"] = new_id
        updated[i] = merged
    try:
        _write(updated)
    except Exception:
        if moved:
            new_dir.rename(old_dir)
        raise
    return len(indices)


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


# ── DNS Credentials ───────────────────────────────────────────────────────────
#
# A DNS Credential is a reusable (provider, auth fields) pair, referenced by
# Certificate Profiles / server entries via dns_credential_id. Unlike a
# Certificate Profile it has no on-disk directory of its own — it's a pure
# credential reference — so renaming/deleting it never touches the filesystem.

DNS_CREDENTIALS_FILE = SERVERS_FILE.parent / "dns_credentials.json"


def load_dns_credentials() -> dict:
    """Return {dns_credential_id: {"dns_provider": ..., "dns_credentials": {...}}}."""
    if not DNS_CREDENTIALS_FILE.exists():
        return {}
    try:
        data = json.loads(DNS_CREDENTIALS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_dns_credentials(creds: dict) -> None:
    DNS_CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    DNS_CREDENTIALS_FILE.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    DNS_CREDENTIALS_FILE.chmod(0o600)


def list_dns_credentials() -> list[dict]:
    """Return every DNS Credential as a dict with its id included."""
    return [
        {"id": cred_id, **cred}
        for cred_id, cred in sorted(load_dns_credentials().items())
    ]


def get_dns_credential(dns_credential_id: str) -> Optional[dict]:
    """Return the {"dns_provider", "dns_credentials"} dict for an id, or None."""
    dns_credential_id = str(dns_credential_id).strip()
    if not dns_credential_id:
        return None
    creds = load_dns_credentials()
    cred = creds.get(dns_credential_id)
    return dict(cred) if cred is not None else None


def dns_credential_owner_ids(dns_credential_id: str) -> list[str]:
    """Return every certificate_id (profile or legacy) referencing this credential."""
    dns_credential_id = str(dns_credential_id).strip()
    owners: list[str] = []
    seen: set[str] = set()
    for server in load_servers():
        if str(server.get("dns_credential_id", "")).strip() != dns_credential_id:
            continue
        profile_id = certificate_id(server)
        if profile_id not in seen:
            seen.add(profile_id)
            owners.append(profile_id)
    return owners


def _validate_dns_credential_fields(dns_provider: str, dns_credentials: dict) -> None:
    provider = str(dns_provider).strip().lower()
    provider = _DNS_PROVIDER_ALIASES.get(provider, provider)
    if not provider:
        raise ValueError("DNS Provider is required.")
    options = _DNS_CREDENTIAL_OPTIONS.get(provider)
    if options is None:
        # Unknown providers are allowed; credentials can't be pre-checked.
        return
    creds = dns_credentials or {}
    if not any(all(str(creds.get(k, "")).strip() for k in opt) for opt in options):
        wanted = " or ".join(" + ".join(opt) for opt in options)
        raise ValueError(f"DNS credentials for {provider} are incomplete: need {wanted}.")


def add_dns_credential(dns_credential_id: str, dns_provider: str, dns_credentials: dict) -> str:
    """Create a new DNS Credential. Raises ValueError on invalid id/fields or collision."""
    dns_credential_id = str(dns_credential_id).strip()
    if not dns_credential_id:
        raise ValueError("DNS Credential ID is required.")
    if not _ID_PATTERN.fullmatch(dns_credential_id):
        raise ValueError("DNS Credential ID may only contain letters, numbers, '.', '_', and '-'.")
    _validate_dns_credential_fields(dns_provider, dns_credentials)
    creds = load_dns_credentials()
    if dns_credential_id in creds:
        raise ValueError(f"'{dns_credential_id}' is already used by another DNS Credential.")
    creds[dns_credential_id] = {
        "dns_provider": str(dns_provider).strip().lower(),
        "dns_credentials": dict(dns_credentials or {}),
    }
    _write_dns_credentials(creds)
    return dns_credential_id


def update_dns_credential(dns_credential_id: str, fields: dict) -> None:
    """Update an existing DNS Credential's provider/credentials in place.

    Raises ValueError if the credential doesn't exist or the merged fields
    fail validation.
    """
    dns_credential_id = str(dns_credential_id).strip()
    creds = load_dns_credentials()
    existing = creds.get(dns_credential_id)
    if existing is None:
        raise ValueError("DNS Credential not found.")
    merged = dict(existing)
    if "dns_provider" in fields:
        merged["dns_provider"] = str(fields["dns_provider"]).strip().lower()
    if "dns_credentials" in fields:
        merged["dns_credentials"] = dict(fields["dns_credentials"] or {})
    _validate_dns_credential_fields(merged.get("dns_provider", ""), merged.get("dns_credentials", {}))
    creds[dns_credential_id] = merged
    _write_dns_credentials(creds)


def delete_dns_credential(dns_credential_id: str) -> int:
    """Delete a DNS Credential, detaching it (clears dns_credential_id) from
    every referencing server entry — same semantics as
    delete_certificate_profile. Returns the number of entries detached
    (0 if the credential didn't exist)."""
    dns_credential_id = str(dns_credential_id).strip()
    creds = load_dns_credentials()
    if dns_credential_id not in creds:
        return 0
    del creds[dns_credential_id]
    _write_dns_credentials(creds)

    servers = load_servers()
    updated = list(servers)
    detached = 0
    for i, s in enumerate(servers):
        if str(s.get("dns_credential_id", "")).strip() != dns_credential_id:
            continue
        merged = dict(s)
        merged["dns_credential_id"] = ""
        updated[i] = merged
        detached += 1
    if detached:
        _write(updated)
    return detached


def rename_dns_credential(old_id: str, new_id: str) -> int:
    """Rename a DNS Credential's ID, rewriting dns_credential_id on every
    referencing server entry. Simpler than rename_certificate_profile since
    there's no on-disk directory to move. Returns the number of entries
    rewritten (0 if new_id == old_id). Raises ValueError if new_id is
    invalid, collides with an existing credential, or old_id doesn't exist.
    """
    old_id = str(old_id).strip()
    new_id = str(new_id).strip()
    if not new_id:
        raise ValueError("DNS Credential ID is required.")
    if not _ID_PATTERN.fullmatch(new_id):
        raise ValueError("DNS Credential ID may only contain letters, numbers, '.', '_', and '-'.")
    if new_id == old_id:
        return 0

    creds = load_dns_credentials()
    if old_id not in creds:
        raise ValueError("DNS Credential not found.")
    if new_id in creds:
        raise ValueError(f"'{new_id}' is already used by another DNS Credential.")

    creds[new_id] = creds.pop(old_id)
    _write_dns_credentials(creds)

    servers = load_servers()
    updated = list(servers)
    renamed = 0
    for i, s in enumerate(servers):
        if str(s.get("dns_credential_id", "")).strip() != old_id:
            continue
        merged = dict(s)
        merged["dns_credential_id"] = new_id
        updated[i] = merged
        renamed += 1
    if renamed:
        _write(updated)
    return renamed


def migrate_dns_credentials_from_servers() -> int:
    """One-time, idempotent startup migration: extract embedded dns_provider/
    dns_credentials fields out of servers.json entries into the DNS
    Credentials store, replacing them with a dns_credential_id reference.

    Entries that already have dns_credential_id (or neither legacy field)
    are left alone. Entries with an identical (provider, credentials) pair
    are deduped onto the same new DNS Credential rather than creating one
    per entry. Run once at container startup (entrypoint.sh), right after
    backfill_certificate_ids(), before anything else reads servers.json.
    """
    servers = load_servers()
    creds = load_dns_credentials()
    # Map a dedup key to the credential id created/reused for it in this pass.
    by_key: dict[tuple, str] = {}
    for cred_id, cred in creds.items():
        key = (
            str(cred.get("dns_provider", "")).strip().lower(),
            tuple(sorted((cred.get("dns_credentials") or {}).items())),
        )
        by_key.setdefault(key, cred_id)

    updated = list(servers)
    changed = 0
    for i, s in enumerate(servers):
        if str(s.get("dns_credential_id", "")).strip():
            continue
        provider = str(s.get("dns_provider", "")).strip()
        if not provider:
            continue
        cred_fields = s.get("dns_credentials") or {}
        key = (provider.lower(), tuple(sorted(cred_fields.items())))
        cred_id = by_key.get(key)
        if cred_id is None:
            base = _slugify_certificate_id(provider.lower(), default="dns-credential")
            cred_id = base
            n = 2
            while cred_id in creds:
                cred_id = f"{base}-{n}"
                n += 1
            creds[cred_id] = {
                "dns_provider": provider.lower(),
                "dns_credentials": dict(cred_fields),
            }
            by_key[key] = cred_id

        merged = dict(s)
        merged["dns_credential_id"] = cred_id
        merged.pop("dns_provider", None)
        merged.pop("dns_credentials", None)
        updated[i] = merged
        changed += 1

    if changed:
        _write_dns_credentials(creds)
        _write(updated)
    return changed


# ── Shell environment export ───────────────────────────────────────────────────

def get_server_env_dict(server_id: str) -> Optional[dict]:
    """Return the per-server environment as a plain Python dict.

    Returns None if the server ID is not found.
    """
    s = get_server(server_id)
    if not s:
        return None

    s = _resolve_target_fields(s)
    credential = get_dns_credential(s.get("dns_credential_id", "")) or {}
    dns_provider = str(credential.get("dns_provider", ""))
    creds = credential.get("dns_credentials") or {}
    target_type = str(s.get("target_type", "clearpass") or "clearpass")
    is_ssh = target_type == "linux_ssh"
    env: dict[str, str] = {
        "CERTIFICATE_ID":       certificate_id(s),
        "TARGET_TYPE":          target_type,
        "DOMAIN":               str(s.get("domain",               "")),
        "SAN_DNS":              "|".join(san_dns_names(s)),
        "ACME_EMAIL":           str(s.get("acme_email",           "")),
        "ACME_SERVER":          str(s.get("acme_server",          "letsencrypt")),
        "EAB_KID":              str(s.get("eab_kid",              "")),
        "EAB_HMAC_KEY":         str(s.get("eab_hmac_key",         "")),
        "DNS_PROVIDER":         dns_provider,
        "CPPM_HOST":            str(s.get("cppm_host",            "")),
        "CPPM_CLUSTER_MODE":    "true" if s.get("cppm_cluster_mode") else "false",
        "CPPM_CLIENT_ID":       str(s.get("cppm_client_id",       "")),
        "CPPM_CLIENT_SECRET":   str(s.get("cppm_client_secret",   "")),
        "CPPM_VERIFY_SSL":      "true" if s.get("cppm_verify_ssl") else "false",
        "CPPM_CERT_PASSPHRASE": str(s.get("cppm_cert_passphrase", "")),
        "CPPM_CALLBACK_HOST":   str(s.get("cppm_callback_host",   "")),
        "CPPM_CALLBACK_PORT":   str(s.get("cppm_callback_port",   "8765")),
        # Linux SSH targets always issue (and deploy) the ECC cert only —
        # matches the fixed fullchain.pem/privkey.pem layout. ClearPass
        # entries keep deriving flags from the selected cert_types.
        "ISSUE_ECC":            "true" if (is_ssh or "https_ecc" in certificate_targets(s)) else "false",
        "ISSUE_RSA":            "false" if is_ssh else ("true" if any(t in certificate_targets(s) for t in ("https_rsa", "radius", "radsec")) else "false"),
        "UPLOAD_HTTPS_ECC":     "true" if "https_ecc" in certificate_targets(s) else "false",
        "UPLOAD_HTTPS_RSA":     "true" if "https_rsa" in certificate_targets(s) else "false",
        "UPLOAD_RADIUS":        "true" if "radius" in certificate_targets(s) else "false",
        "UPLOAD_RADSEC":        "true" if "radsec" in certificate_targets(s) else "false",
        "ACME_DNS_RESOLVERS":   ",".join(acme_dns_resolvers(s)),
        "SERVER_CERT_DIR":      str(server_cert_dir(s)),
        "SERVER_LOG_DIR":       str(server_cert_dir(s) / "logs"),
        "STATUS_LOG":           str(server_cert_dir(s) / "status.log"),
        "SERVER_ID":            str(s.get("id", "")),
        "SSH_HOST":             str(s.get("ssh_host",          "")),
        "SSH_PORT":             str(s.get("ssh_port",          "22")),
        "SSH_USER":             str(s.get("ssh_user",          "")),
        "REMOTE_CERT_DIR":      str(s.get("remote_cert_dir",   "")),
        "RELOAD_COMMAND":       str(s.get("reload_command",    "")),
        "SSH_PRIVATE_KEY":      str(s.get("ssh_private_key",   "")),
        "SSH_PASSWORD":         str(s.get("ssh_password",      "")),
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
        "    image: traefik:v3.7",
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
