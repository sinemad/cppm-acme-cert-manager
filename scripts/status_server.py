#!/usr/bin/env python3
"""
status_server.py - Authenticated web dashboard and configuration interface.

Starts an HTTP server on STATUS_PORT (default 8080) with:
  - Session-based authentication (bcrypt htpasswd credentials, HMAC-signed cookies)
  - First-time setup wizard shown automatically when no admin users exist
  - Admin user management page (add, change password, delete)
  - Certificate status dashboard (auto-refreshes every 30 s)
  - JSON status API at /api/status (requires auth)

CLI management:
  docker exec -it cppm-acme-cert-manager cppm-users --help
  docker exec -it cppm-acme-cert-manager cppm-servers --help

Started as a background process by entrypoint.sh before exec supercronic.
"""

import datetime
import json
import logging
import os
import sys
import threading
import time
import traceback
import zoneinfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

sys.path.insert(0, "/opt/cppm")
from auth_utils import (
    HAS_BCRYPT, SESSION_LIFETIME, HTPASSWD_FILE,
    load_session_secret, make_session_token, verify_session_token,
    load_users, verify_password, save_user, delete_user, needs_setup,
)
from config_utils import (
    load_servers, get_server, add_server, update_server, delete_server,
)

# ── Version ───────────────────────────────────────────────────────────────────
def _read_version() -> str:
    for p in (
        Path("/opt/cppm/VERSION"),
        Path(__file__).parent / "VERSION",
        Path(__file__).parent.parent / "VERSION",
    ):
        try:
            return p.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return "unknown"

_APP_VERSION = _read_version()

# ── Configuration from environment ───────────────────────────────────────────
CERT_DIR    = Path(os.environ.get("CERT_DIR", "/data/certs"))
STATUS_PORT = int(os.environ.get("STATUS_PORT", "8080"))
TZ_NAME     = os.environ.get("TZ", "UTC")
STATUS_LOG  = CERT_DIR / "status.log"
COOKIE_NAME = "cppm_session"
# When False (default) the dashboard and /api/status are publicly readable.
# Set to true to require authentication even for the read-only status page.
REQUIRE_AUTH_FOR_STATUS = os.environ.get("REQUIRE_AUTH_FOR_STATUS", "false").lower() == "true"

_SESSION_SECRET: bytes = b""

# ── Module logger ─────────────────────────────────────────────────────────────
# Writes to stdout, which entrypoint.sh redirects to .logs/status_server.log
# and which also appears in `docker compose logs`.
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [status_server] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
    force=True,
)
_log = logging.getLogger("status_server")


def _init_session_secret() -> None:
    global _SESSION_SECRET
    _SESSION_SECRET = load_session_secret()


def _tz() -> datetime.tzinfo:
    try:
        return zoneinfo.ZoneInfo(TZ_NAME)
    except Exception:
        return datetime.timezone.utc


# ── Certificate parsing ───────────────────────────────────────────────────────

def parse_cert(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    pem_bytes = path.read_bytes()
    result = {"exists": True, "pem": pem_bytes.decode("utf-8", errors="replace")}
    if not HAS_CRYPTOGRAPHY:
        return result
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        try:
            not_before = cert.not_valid_before_utc
            not_after  = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after  = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        now      = datetime.datetime.now(datetime.timezone.utc)
        days_left = (not_after - now).days
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = cert.subject.rfc4514_string()
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in san_ext.value]
        except Exception:
            pass
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            issuer_cn = cert.issuer.rfc4514_string()
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            issuer_org = ""
        pub = cert.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_size, key_curve = "ECDSA", pub.key_size, pub.curve.name
        elif isinstance(pub, rsa.RSAPublicKey):
            key_type, key_size, key_curve = "RSA", pub.key_size, None
        else:
            key_type, key_size, key_curve = type(pub).__name__, getattr(pub, "key_size", 0), None
        result.update({
            "cn": cn, "san": sans, "issuer_cn": issuer_cn, "issuer_org": issuer_org,
            "serial": format(cert.serial_number, "x").upper(),
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_left": days_left, "key_type": key_type, "key_size": key_size,
            "key_curve": key_curve,
        })
    except Exception as e:
        result["parse_error"] = str(e)
    return result


def parse_log(max_entries: int = 40) -> list:
    if not STATUS_LOG.exists():
        return []
    entries = []
    try:
        lines = STATUS_LOG.read_text(errors="replace").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|", 3)]
            if len(parts) == 4:
                entries.append({"ts": parts[0], "level": parts[1],
                                 "category": parts[2], "message": parts[3]})
            if len(entries) >= max_entries:
                break
    except Exception:
        pass
    return entries


def next_check_info() -> dict:
    tz  = _tz()
    now = datetime.datetime.now(tz)
    candidates = []
    for d in range(3):
        for h in (2, 14):
            dt = datetime.datetime(now.year, now.month, now.day, h, 0, 0, tzinfo=tz) \
                 + datetime.timedelta(days=d)
            if dt > now:
                candidates.append(dt)
    candidates.sort()
    if not candidates:
        return {}
    nxt   = candidates[0]
    delta = nxt - now
    secs  = int(delta.total_seconds())
    h, r  = divmod(secs, 3600)
    m     = r // 60
    return {
        "next_dt": nxt.isoformat(),
        "next_utc": nxt.astimezone(datetime.timezone.utc).isoformat(),
        "until": f"{h}h {m}m" if h else f"{m}m",
        "schedule": "02:00 and 14:00 daily",
        "threshold": "≤30 days remaining",
    }


def build_server_status(server: dict) -> dict:
    """Build the full status dict for a single server configuration entry."""
    tz     = _tz()
    domain = server.get("domain", "")
    return {
        "id":              server.get("id", ""),
        "label":           server.get("label", domain),
        "cppm_host":       server.get("cppm_host", ""),
        "dns_provider":    server.get("dns_provider", ""),
        "acme_server":     server.get("acme_server", ""),
        "domain":          domain,
        "callback_host":   server.get("cppm_callback_host", ""),
        "callback_port":   str(server.get("cppm_callback_port", "8765")),
        "certs": {
            "ecc": parse_cert(CERT_DIR / f"{domain}.ecc.cer"),
            "rsa": parse_cert(CERT_DIR / f"{domain}.rsa.cer"),
        },
        "schedule":    next_check_info(),
        "activity":    parse_log(40),
        "server_time": datetime.datetime.now(tz).isoformat(),
    }


def build_all_status() -> list:
    """Return status for every server configured in servers.json."""
    return [build_server_status(s) for s in load_servers()]


# ── Health checks ────────────────────────────────────────────────────────────
# Results are cached for _HEALTH_TTL seconds so the dashboard never hammers
# external APIs.  Checks run in the calling thread (ThreadingHTTPServer handles
# concurrency), protected by a lock to avoid duplicate simultaneous checks.

_health_lock:  threading.Lock = threading.Lock()
_health_cache: dict           = {}
_HEALTH_TTL                   = 120  # seconds


def _check_cppm(server: dict = None) -> dict:
    """Attempt an OAuth client_credentials exchange to verify CPPM connectivity."""
    if not server:
        return {"status": "unknown", "message": "Not configured"}
    host          = server.get("cppm_host", "")
    client_id     = server.get("cppm_client_id", "")
    client_secret = server.get("cppm_client_secret", "")
    verify_ssl    = bool(server.get("cppm_verify_ssl", False))
    if not host:
        return {"status": "unknown", "message": "Not configured"}
    try:
        import requests as _req
        import urllib3
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = _req.post(
            f"https://{host}/api/oauth",
            data={"grant_type": "client_credentials",
                  "client_id": client_id,
                  "client_secret": client_secret},
            timeout=10, verify=verify_ssl,
        )
        if r.status_code == 200:
            return {"status": "ok", "message": "Connected"}
        if r.status_code in (400, 401):
            return {"status": "warn", "message": f"Auth error (HTTP {r.status_code})"}
        return {"status": "warn", "message": f"HTTP {r.status_code}"}
    except Exception as exc:
        n = type(exc).__name__
        if "ConnectionError" in n or "ConnectTimeout" in n:
            return {"status": "error", "message": "Unreachable"}
        if "Timeout" in n:
            return {"status": "error", "message": "Timeout"}
        return {"status": "error", "message": n}


def _check_dns(server: dict = None) -> dict:
    """Check DNS provider API connectivity using the configured credentials."""
    if not server:
        return {"status": "unknown", "message": "Not configured"}
    provider = server.get("dns_provider", "")
    _creds   = server.get("dns_credentials") or {}
    def g(k): return _creds.get(k, "")

    if not provider:
        return {"status": "unknown", "message": "Not configured"}
    try:
        import requests as _req
        if provider == "cloudflare":
            token = g("CF_Token")
            if token:
                r = _req.get(
                    "https://api.cloudflare.com/client/v4/user/tokens/verify",
                    headers={"Authorization": f"Bearer {token}"}, timeout=10,
                )
                d = r.json()
                if r.status_code == 200 and d.get("success"):
                    return {"status": "ok", "message": "Token valid"}
                errs = d.get("errors", [])
                msg  = errs[0].get("message", f"HTTP {r.status_code}") if errs else f"HTTP {r.status_code}"
                return {"status": "warn", "message": msg}
            key   = g("CF_Key")
            email = g("CF_Email")
            if not key:
                return {"status": "unknown", "message": "No credentials set"}
            r = _req.get(
                "https://api.cloudflare.com/client/v4/user",
                headers={"X-Auth-Key": key, "X-Auth-Email": email}, timeout=10,
            )
            d = r.json()
            if r.status_code == 200 and d.get("success"):
                return {"status": "ok", "message": "Global key valid"}
            return {"status": "warn", "message": f"HTTP {r.status_code}"}

        if provider == "porkbun":
            api_key = g("PORKBUN_API_KEY")
            secret  = g("PORKBUN_SECRET_API_KEY")
            if not api_key:
                return {"status": "unknown", "message": "No credentials set"}
            r = _req.post(
                "https://api.porkbun.com/api/json/v3/ping",
                json={"apikey": api_key, "secretapikey": secret}, timeout=10,
            )
            d = r.json()
            if d.get("status") == "SUCCESS":
                return {"status": "ok", "message": "Connected"}
            return {"status": "warn", "message": d.get("message", f"HTTP {r.status_code}")}

        if provider == "digitalocean":
            token = g("DO_API_KEY")
            if not token:
                return {"status": "unknown", "message": "No credentials set"}
            r = _req.get(
                "https://api.digitalocean.com/v2/account",
                headers={"Authorization": f"Bearer {token}"}, timeout=10,
            )
            if r.status_code == 200:
                return {"status": "ok", "message": "Connected"}
            return {"status": "warn", "message": f"HTTP {r.status_code}"}

        if provider == "godaddy":
            key    = g("GD_Key")
            secret = g("GD_Secret")
            if not key:
                return {"status": "unknown", "message": "No credentials set"}
            r = _req.get(
                "https://api.godaddy.com/v1/domains?limit=1",
                headers={"Authorization": f"sso-key {key}:{secret}"}, timeout=10,
            )
            if r.status_code == 200:
                return {"status": "ok", "message": "Connected"}
            return {"status": "warn", "message": f"HTTP {r.status_code}"}

        if provider == "route53":
            r = _req.get("https://route53.amazonaws.com/", timeout=10)
            return ({"status": "ok",   "message": "Endpoint reachable"}
                    if r.status_code < 500
                    else {"status": "warn", "message": f"HTTP {r.status_code}"})

        return {"status": "unknown", "message": f"No check for '{provider}'"}

    except Exception as exc:
        n = type(exc).__name__
        if "ConnectionError" in n or "ConnectTimeout" in n:
            return {"status": "error", "message": "Unreachable"}
        if "Timeout" in n:
            return {"status": "error", "message": "Timeout"}
        return {"status": "error", "message": n}


def _check_callback(server: dict = None) -> dict:
    """Verify the PKCS12 callback HTTP service port is bindable and externally reachable.

    Spins up a transient HTTP server on the configured callback port, then
    attempts an HTTP GET to http://{callback_host}:{port}/ from inside the
    container.  A successful round-trip confirms Docker port-mapping is working
    and ClearPass will be able to fetch PKCS12 files during uploads.
    """
    if not server:
        return {"status": "unknown", "message": "Not configured"}
    callback_host = (server.get("cppm_callback_host") or "").strip()
    try:
        callback_port = int(server.get("cppm_callback_port") or 8765)
    except (ValueError, TypeError):
        return {"status": "error", "message": "Invalid port number"}
    if not callback_host:
        _log.debug("callback-check [%s]: callback host not configured",
                   server.get("label") or server.get("cppm_host", "?"))
        return {"status": "unknown", "message": "Callback host not set"}

    label = server.get("label") or server.get("cppm_host", "?")
    url   = f"http://{callback_host}:{callback_port}/"
    _log.debug("callback-check [%s]: probing %s", label, url)

    import socket as _sock
    import errno as _errno
    import http.server, socketserver, threading

    # Step 1 — test whether the port is currently bindable
    probe = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    probe.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    try:
        probe.bind(("0.0.0.0", callback_port))
    except OSError as e:
        probe.close()
        if e.errno in (_errno.EADDRINUSE,):
            _log.warning("callback-check [%s]: port %d in use (errno EADDRINUSE) — "
                         "upload in progress or port conflict", label, callback_port)
            return {"status": "warn",
                    "message": f"Port {callback_port} in use — upload in progress or port conflict"}
        _log.error("callback-check [%s]: cannot bind port %d — %s (errno %s)",
                   label, callback_port, e, e.errno)
        return {"status": "error",
                "message": f"Cannot bind port {callback_port}: {e}"}
    probe.close()
    _log.debug("callback-check [%s]: port %d is bindable", label, callback_port)

    # Step 2 — spin up a minimal HTTP server and try reaching it via the external URL
    class _PingHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *_):
            pass

    httpd = None
    try:
        httpd = socketserver.TCPServer(("0.0.0.0", callback_port), _PingHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        import requests as _req
        r = _req.get(url, timeout=4)
        if r.status_code == 200 and r.text.strip() == "ok":
            _log.debug("callback-check [%s]: round-trip OK — %s", label, url)
            return {"status": "ok", "message": f"Reachable at {url}"}
        _log.warning("callback-check [%s]: unexpected HTTP %d from %s",
                     label, r.status_code, url)
        return {"status": "warn",
                "message": f"Unexpected response HTTP {r.status_code} from {url}"}
    except Exception as exc:
        n = type(exc).__name__
        if any(k in n for k in ("ConnectionError", "ConnectTimeout", "Timeout")):
            _log.warning("callback-check [%s]: port %d bound but %s unreachable — "
                         "%s: %s — verify Docker port mapping",
                         label, callback_port, url, n, exc)
            return {"status": "warn",
                    "message": (f"Port {callback_port} open but {url} unreachable "
                                f"— check Docker port mapping")}
        _log.error("callback-check [%s]: unexpected error — %s: %s",
                   label, n, exc)
        return {"status": "error", "message": str(exc)[:100]}
    finally:
        if httpd:
            httpd.shutdown()


def _build_health() -> dict:
    """Return cached per-server health status, refreshing if the TTL has expired.

    All CPPM and DNS checks run concurrently so latency equals the slowest
    single check rather than the sum of all checks.
    """
    now = time.time()
    with _health_lock:
        if _health_cache.get("ts", 0) + _HEALTH_TTL > now:
            return _health_cache["data"]

    servers = load_servers()

    if not servers:
        return {"servers": {}, "checked_at": datetime.datetime.now(_tz()).isoformat()}

    # Flatten into (server_id, check_type, server_dict) tasks
    tasks = [(s.get("id", ""), t, s) for s in servers for t in ("cppm", "dns", "callback")]

    from concurrent.futures import ThreadPoolExecutor, as_completed
    per_server: dict = {}
    with ThreadPoolExecutor(max_workers=max(len(tasks), 1)) as pool:
        fut_map = {}
        for sid, check_type, s in tasks:
            fn = (_check_cppm if check_type == "cppm"
                  else _check_dns if check_type == "dns"
                  else _check_callback)
            fut_map[pool.submit(fn, s)] = (sid, check_type)
        for fut in as_completed(fut_map):
            sid, check_type = fut_map[fut]
            per_server.setdefault(sid, {})
            try:
                per_server[sid][check_type] = fut.result()
            except Exception:
                per_server[sid][check_type] = {"status": "error", "message": "Check failed"}

    result = {
        "servers":    per_server,
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    with _health_lock:
        _health_cache["data"] = result
        _health_cache["ts"]   = time.time()
    return result


# ── Settings helpers ─────────────────────────────────────────────────────────

# DNS credential keys per provider — used both to build form fields and to
# extract only the relevant keys from the POST body.
_DNS_CRED_FIELDS: dict = {
    "cloudflare":   ["CF_Token", "CF_Account_ID", "CF_Zone_ID", "CF_Key", "CF_Email"],
    "porkbun":      ["PORKBUN_API_KEY", "PORKBUN_SECRET_API_KEY"],
    "route53":      ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"],
    "digitalocean": ["DO_API_KEY"],
    "godaddy":      ["GD_Key", "GD_Secret"],
}


def _parse_server_form(f: dict) -> dict:
    """Convert POST form data into a server config dict."""
    provider  = f.get("dns_provider", "cloudflare")
    cred_keys = _DNS_CRED_FIELDS.get(provider, [])
    return {
        "label":                f.get("label", "").strip(),
        "cppm_host":            f.get("cppm_host", "").strip(),
        "cppm_client_id":       f.get("cppm_client_id", "").strip(),
        "cppm_client_secret":   f.get("cppm_client_secret", ""),
        "cppm_verify_ssl":      f.get("cppm_verify_ssl", "") == "true",
        "cppm_cert_passphrase": f.get("cppm_cert_passphrase", ""),
        "cppm_callback_host":   f.get("cppm_callback_host", "").strip(),
        "cppm_callback_port":   f.get("cppm_callback_port", "8765").strip() or "8765",
        "domain":               f.get("domain", "").strip(),
        "acme_email":           f.get("acme_email", "").strip(),
        "acme_server":          f.get("acme_server", "letsencrypt"),
        "dns_provider":         provider,
        "dns_credentials":      {k: f.get(k, "") for k in cred_keys},
        "trust_exclusions":     [
            line.strip()
            for line in f.get("trust_exclusions", "").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ],
        "cert_types": [t for t in ("ecc", "rsa")
                       if f.get(f"issue_{t}") == "true"] or ["ecc", "rsa"],
    }


def _default_server_from_env() -> dict:
    """Return a blank server entry with only structural defaults (no env var pre-fill)."""
    return {
        "id":                   None,
        "label":                "",
        "cppm_host":            "",
        "cppm_client_id":       "",
        "cppm_client_secret":   "",
        "cppm_verify_ssl":      False,
        "cppm_cert_passphrase": "",
        "cppm_callback_host":   "",
        "cppm_callback_port":   "8765",
        "domain":               "",
        "acme_email":           "",
        "acme_server":          "letsencrypt",
        "dns_provider":         "cloudflare",
        "dns_credentials":      {},
        "trust_exclusions":     [],
        "cert_types":           ["ecc", "rsa"],
    }


# ── Shared CSS ────────────────────────────────────────────────────────────────

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--card:#1e293b;--border:#334155;--border2:#475569;
  --accent:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;--info:#818cf8;
  --text:#e2e8f0;--muted:#94a3b8;--subtle:#64748b;
  --radius:0.75rem;--shadow:0 4px 24px rgba(0,0,0,.4);
}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6;min-height:100vh}

/* ── Navigation ── */
.nav{display:flex;align-items:center;justify-content:space-between;padding:0.6rem 1.5rem;background:#0d1526;border-bottom:1px solid var(--border)}
.nav-brand{font-size:0.9rem;font-weight:700;color:var(--accent)}
.nav-links{display:flex;align-items:center;gap:0.25rem}
.nav-link{padding:0.3rem 0.75rem;border-radius:0.4rem;font-size:0.8rem;color:var(--muted);text-decoration:none;transition:all .15s}
.nav-link:hover{color:var(--text);background:rgba(255,255,255,.06)}
.nav-link.active{color:var(--text);background:rgba(56,189,248,.1)}
.nav-sep{width:1px;height:16px;background:var(--border);margin:0 0.25rem}
.nav-user{font-size:0.78rem;color:var(--subtle);padding:0.3rem 0.5rem}
.nav-logout{color:var(--muted)}

/* ── Dashboard layout ── */
.app{max-width:1200px;margin:0 auto;padding:1.5rem}
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;padding:1rem 1.5rem;background:var(--card);border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}
.hdr-left{display:flex;align-items:center;gap:1rem}
.hdr-logo{font-size:1rem;font-weight:700;color:var(--accent);letter-spacing:-.01em}
.hdr-domain{font-size:0.8rem;color:var(--muted);font-family:monospace;background:rgba(56,189,248,.08);padding:0.15rem 0.5rem;border-radius:4px;border:1px solid rgba(56,189,248,.15)}
.hdr-right{display:flex;align-items:center;gap:0.6rem;font-size:0.78rem;color:var(--subtle)}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--subtle);transition:background .3s}
.pulse.active{background:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.2)}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;margin-bottom:1rem}
@media(max-width:700px){.grid-2{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow)}
.card-title{font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:0.85rem}
.cert-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow);border-left:3px solid var(--subtle);transition:border-color .3s}
.cert-card.ok{border-left-color:var(--ok)}.cert-card.warn{border-left-color:var(--warn)}.cert-card.danger{border-left-color:var(--danger)}
.cert-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.cert-title{font-size:0.85rem;font-weight:600}
.badge{font-size:0.68rem;padding:0.18rem 0.55rem;border-radius:999px;font-weight:600}
.badge-ok{background:rgba(34,197,94,.15);color:var(--ok)}.badge-warn{background:rgba(245,158,11,.15);color:var(--warn)}.badge-danger{background:rgba(239,68,68,.15);color:var(--danger)}.badge-none{background:rgba(100,116,139,.12);color:var(--subtle)}
.days-num{font-size:2.8rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.days-num.ok{color:var(--ok)}.days-num.warn{color:var(--warn)}.days-num.danger{color:var(--danger)}.days-num.none{color:var(--subtle)}
.days-label{font-size:0.72rem;color:var(--muted);margin-top:0.1rem}
.meta{margin-top:0.85rem;display:flex;flex-direction:column;gap:0.28rem}
.row{display:flex;gap:0.5rem;font-size:0.78rem}
.row .lbl{color:var(--muted);min-width:68px;flex-shrink:0}
.row .val{font-family:monospace;font-size:0.75rem;word-break:break-all}
.actions{margin-top:1rem}
.btn{display:inline-flex;align-items:center;gap:0.35rem;padding:0.38rem 0.85rem;border-radius:0.4rem;font-size:0.78rem;font-weight:500;border:none;cursor:pointer;transition:all .15s}
.btn-primary{background:rgba(56,189,248,.12);color:var(--accent);border:1px solid rgba(56,189,248,.25)}
.btn-primary:hover{background:rgba(56,189,248,.22)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border2)}
.btn-ghost:hover{color:var(--text);border-color:var(--muted)}
.btn-danger{background:rgba(239,68,68,.1);color:var(--danger);border:1px solid rgba(239,68,68,.25)}
.btn-danger:hover{background:rgba(239,68,68,.2)}
.big-val{font-size:1.6rem;font-weight:700;color:var(--accent);line-height:1}
.sub-val{font-size:0.78rem;color:var(--muted);margin-top:0.2rem;margin-bottom:0.85rem}
.log-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow)}
.log-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem}
.log-count{font-size:0.72rem;color:var(--subtle)}
.log-table{width:100%;border-collapse:collapse}
.log-table tr:hover td{background:rgba(255,255,255,.025)}
.log-table td{padding:0.32rem 0.5rem;border-bottom:1px solid rgba(51,65,85,.5);vertical-align:top}
.log-table td.ts{white-space:nowrap;color:var(--muted);font-family:monospace;font-size:0.72rem;padding-right:0.75rem}
.log-table td.lvl-cell{white-space:nowrap;width:64px}
.log-table td.cat{white-space:nowrap;color:var(--subtle);font-size:0.72rem;padding-right:0.75rem}
.log-table td.msg{color:var(--text);font-size:0.78rem}
.lvl{display:inline-block;padding:0.08rem 0.4rem;border-radius:3px;font-size:0.68rem;font-weight:600}
.lvl-ok{background:rgba(34,197,94,.13);color:var(--ok)}.lvl-warn{background:rgba(245,158,11,.13);color:var(--warn)}.lvl-failed{background:rgba(239,68,68,.13);color:var(--danger)}.lvl-info{background:rgba(129,140,248,.13);color:var(--info)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:200;display:none;align-items:center;justify-content:center;padding:1rem}
.overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius);width:100%;max-width:680px;max-height:90vh;overflow-y:auto;box-shadow:0 24px 64px rgba(0,0,0,.7)}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--card);z-index:1}
.modal-title{font-size:0.9rem;font-weight:600}
.modal-x{background:none;border:none;color:var(--muted);font-size:1.1rem;cursor:pointer;line-height:1;padding:0.25rem}
.modal-x:hover{color:var(--text)}
.modal-body{padding:1.25rem}
.detail-grid{display:grid;grid-template-columns:auto 1fr;gap:0.38rem 1rem;font-size:0.82rem;align-items:baseline}
.detail-grid .dl{color:var(--muted);white-space:nowrap}
.detail-grid .dv{font-family:monospace;font-size:0.78rem;word-break:break-all}
.pem-section{margin-top:1.25rem}
.pem-hdr{font-size:0.72rem;color:var(--muted);margin-bottom:0.4rem;display:flex;align-items:center;justify-content:space-between}
.pem-pre{background:#0a0f1a;border:1px solid var(--border);border-radius:0.4rem;padding:0.75rem;font-family:monospace;font-size:0.68rem;overflow-x:auto;white-space:pre;color:var(--muted);max-height:280px;overflow-y:auto;line-height:1.5}
.empty{text-align:center;padding:2.5rem;color:var(--subtle);font-size:0.85rem}

/* ── Auth pages (login / setup) ── */
.auth-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.auth-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:2rem 2.5rem;width:100%;max-width:400px;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.auth-logo{font-size:1rem;font-weight:700;color:var(--accent);margin-bottom:1.5rem}
.auth-title{font-size:1.2rem;font-weight:600;margin-bottom:0.5rem}
.auth-desc{font-size:0.82rem;color:var(--muted);margin-bottom:1.25rem;line-height:1.5}
.field{margin-bottom:1rem}
.field label{display:block;font-size:0.78rem;font-weight:500;color:var(--muted);margin-bottom:0.35rem}
.field label .hint{font-weight:400;color:var(--subtle)}
.field input{width:100%;background:#0f172a;border:1px solid var(--border2);border-radius:0.4rem;padding:0.5rem 0.75rem;color:var(--text);font-size:0.85rem;outline:none;transition:border-color .15s}
.field input:focus{border-color:var(--accent)}
.btn-submit{width:100%;padding:0.55rem;background:var(--accent);color:#0f172a;border:none;border-radius:0.4rem;font-size:0.9rem;font-weight:600;cursor:pointer;margin-top:0.5rem;transition:opacity .15s}
.btn-submit:hover{opacity:.9}
.flash{padding:0.6rem 0.9rem;border-radius:0.4rem;font-size:0.8rem;margin-bottom:1rem}
.flash-err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:var(--danger)}
.flash-ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:var(--ok)}
.auth-cli{margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border);font-size:0.72rem;color:var(--subtle)}
.auth-cli code{display:block;margin-top:0.35rem;font-family:monospace;background:#0a0f1a;padding:0.35rem 0.5rem;border-radius:3px;color:var(--muted);word-break:break-all}

/* ── User management page ── */
.page-hdr{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:1.25rem}
.page-title{font-size:1rem;font-weight:600}
.user-table{width:100%;border-collapse:collapse}
.user-table th{text-align:left;font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)}
.user-table td{padding:0.5rem 0.5rem;border-bottom:1px solid rgba(51,65,85,.4);font-size:0.82rem;vertical-align:middle}
.user-table td.you{color:var(--muted);font-size:0.72rem}
.form-row{display:flex;gap:0.5rem;align-items:flex-end}
.form-row .field{flex:1;margin-bottom:0}
.form-row .btn{flex-shrink:0;height:2.1rem}
.form-inline input{width:100%;background:#0f172a;border:1px solid var(--border2);border-radius:0.4rem;padding:0.4rem 0.6rem;color:var(--text);font-size:0.8rem;outline:none}
.form-inline input:focus{border-color:var(--accent)}

/* ── Settings page ── */
.settings-table{width:100%;border-collapse:collapse}
.settings-table th{text-align:left;font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)}
.settings-table td{padding:0.6rem 0.5rem;border-bottom:1px solid rgba(51,65,85,.4);font-size:0.82rem;vertical-align:middle}
.form-section-title{font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:0.85rem;padding-bottom:0.4rem;border-bottom:1px solid var(--border)}
.form-2col{display:grid;grid-template-columns:1fr 1fr;gap:0 1rem}
@media(max-width:640px){.form-2col{grid-template-columns:1fr}}
.field select{width:100%;background:#0f172a;border:1px solid var(--border2);border-radius:0.4rem;padding:0.4rem 0.6rem;color:var(--text);font-size:0.85rem;outline:none;transition:border-color .15s}
.field select:focus{border-color:var(--accent)}

/* ── Trust exclusions page ── */
.excl-card{margin-bottom:0.75rem}
.excl-provider{font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:0.75rem;padding-bottom:0.4rem;border-bottom:1px solid var(--border)}
.excl-row{display:flex;align-items:baseline;gap:0.7rem;padding:0.32rem 0;cursor:pointer;font-size:0.82rem;line-height:1.4}
.excl-row input[type=checkbox]{accent-color:var(--accent);cursor:pointer;flex-shrink:0;margin-top:0.2rem}
.excl-cn{font-family:monospace;min-width:16rem;color:var(--text);transition:color .15s,text-decoration .15s}
.excl-desc{color:var(--muted);font-size:0.75rem;transition:opacity .15s}
.excl-row.excl-excluded .excl-cn{text-decoration:line-through;color:var(--subtle)}
.excl-row.excl-excluded .excl-desc{opacity:0.45}

/* ── Overview table ── */
.overview-table{width:100%;border-collapse:collapse}
.overview-table th{text-align:left;font-size:0.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:0.6rem 0.85rem;border-bottom:2px solid var(--border)}
.overview-table td{padding:0.75rem 0.85rem;border-bottom:1px solid rgba(51,65,85,.4);vertical-align:middle}
.server-row{cursor:pointer;transition:background .12s}
.server-row:hover td{background:rgba(255,255,255,.022)}
.srv-label{font-weight:600;font-size:0.85rem;margin-bottom:0.18rem}
.srv-host{font-family:monospace;font-size:0.75rem;color:var(--muted);display:flex;align-items:center;gap:0.3rem}
.mini-cert{border-left:3px solid var(--subtle);padding:0.28rem 0.55rem;border-radius:0 0.3rem 0.3rem 0;display:inline-block;min-width:88px}
.mini-cert.ok{border-left-color:var(--ok)}.mini-cert.warn{border-left-color:var(--warn)}.mini-cert.danger{border-left-color:var(--danger)}.mini-cert.none{border-left-color:var(--subtle)}
.mini-days{font-size:1.5rem;font-weight:800;line-height:1;letter-spacing:-.02em}
.mini-days.ok{color:var(--ok)}.mini-days.warn{color:var(--warn)}.mini-days.danger{color:var(--danger)}.mini-days.none{color:var(--subtle)}
.mini-label{font-size:0.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:0.1rem}
.mini-exp{font-size:0.68rem;color:var(--subtle);margin-top:0.12rem}
.mini-svc{font-size:0.62rem;color:var(--muted);background:rgba(148,163,184,.08);border-radius:3px;padding:0.05rem 0.35rem;margin-top:0.25rem;display:inline-block;border:1px solid rgba(148,163,184,.15)}
.sched-next{font-size:1.05rem;font-weight:700;color:var(--accent);line-height:1}
.sched-label{font-size:0.68rem;color:var(--muted);margin-top:0.15rem}
.sched-sub{font-size:0.65rem;color:var(--subtle);margin-top:0.1rem}
@media(max-width:900px){.overview-table th:nth-child(5),.overview-table td:nth-child(5){display:none}}
@media(max-width:700px){.overview-table th:nth-child(4),.overview-table td:nth-child(4){display:none}}

/* ── Status dots (health indicators) ── */
.sdot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:0.3rem;vertical-align:middle;flex-shrink:0;cursor:default}
.sdot.ok{background:var(--ok);box-shadow:0 0 0 2px rgba(34,197,94,.2)}
.sdot.warn{background:var(--warn);box-shadow:0 0 0 2px rgba(245,158,11,.2)}
.sdot.error{background:var(--danger);box-shadow:0 0 0 2px rgba(239,68,68,.2)}
.sdot.unknown,.sdot.checking{background:var(--subtle)}
@keyframes sdot-pulse{0%,100%{opacity:.55}50%{opacity:1}}
.sdot.checking{animation:sdot-pulse 1.2s ease-in-out infinite}
"""


# ── Page builders ─────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _nav(username: str = "", active: str = "dashboard") -> str:
    """
    Navigation bar rendered server-side.

    username = ""  and no users configured → Setup button (first-time)
    username = ""  and users exist          → Sign In button (public view)
    username = "<user>"                     → full authenticated nav
    """
    def _link(href, label, key):
        cls = " active" if active == key else ""
        return f'<a href="{href}" class="nav-link{cls}">{label}</a>'

    if username:
        right = (
            _link("/", "Dashboard", "dashboard")
            + _link("/settings", "Servers", "settings")
            + _link("/admin/users", "Users", "users")
            + '<span class="nav-sep"></span>'
            + f'<span class="nav-user">{_esc(username)}</span>'
            + '<a href="/logout" class="nav-link nav-logout">Sign&nbsp;Out</a>'
        )
    elif needs_setup():
        right = '<a href="/setup" class="nav-link">Setup</a>'
    else:
        right = '<a href="/login" class="nav-link">Sign In</a>'

    return f"""<nav class="nav">
  <span class="nav-brand">ClearPass ACME Certificate Manager</span>
  <div class="nav-links">{right}</div>
</nav>"""


def _base(title: str, body: str, nav_user: str = "", active: str = "",
          show_nav: bool = False) -> str:
    # show_nav=True renders the nav bar.  nav_user="" produces the public nav
    # (Sign In or Setup link); a non-empty nav_user produces the authenticated nav.
    # Login and setup pages pass show_nav=False (default) to omit the nav entirely.
    nav = _nav(nav_user, active) if show_nav else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)} — ClearPass ACME Certificate Manager</title>
<style>{_CSS}</style>
</head>
<body>
{nav}
{body}
<footer style="text-align:center;padding:1.5rem 1rem;font-size:0.68rem;color:var(--subtle)">
  ClearPass ACME Certificate Manager v{_esc(_APP_VERSION)}
</footer>
</body>
</html>"""


def _login_page(error: str = "", username_val: str = "") -> str:
    err_html = f'<div class="flash flash-err">{_esc(error)}</div>' if error else ""
    return _base("Sign In", f"""
<div class="auth-wrap">
  <div class="auth-card">
    <div class="auth-logo">ClearPass ACME Certificate Manager</div>
    <h1 class="auth-title">Sign In</h1>
    {err_html}
    <form method="POST" action="/login">
      <div class="field">
        <label>Username</label>
        <input type="text" name="username" value="{_esc(username_val)}"
               autocomplete="username" autofocus required>
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" name="password"
               autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-submit">Sign In</button>
    </form>
  </div>
</div>""")


def _setup_page(error: str = "") -> str:
    err_html = f'<div class="flash flash-err">{_esc(error)}</div>' if error else ""
    cli_cmd  = "docker exec -it cppm-acme-cert-manager cppm-users add admin"
    return _base("First-Time Setup", f"""
<div class="auth-wrap">
  <div class="auth-card">
    <div class="auth-logo">ClearPass ACME Certificate Manager</div>
    <h1 class="auth-title">First-Time Setup</h1>
    <p class="auth-desc">No admin users are configured yet. Create the initial
    administrator account to secure access to this interface.</p>
    {err_html}
    <form method="POST" action="/setup">
      <div class="field">
        <label>Username</label>
        <input type="text" name="username" autocomplete="username" autofocus
               pattern="[a-zA-Z0-9_-]{{1,64}}" title="Letters, digits, hyphens, underscores" required>
      </div>
      <div class="field">
        <label>Password <span class="hint">(min 8 characters)</span></label>
        <input type="password" name="password" autocomplete="new-password"
               minlength="8" required>
      </div>
      <div class="field">
        <label>Confirm Password</label>
        <input type="password" name="confirm" autocomplete="new-password" required>
      </div>
      <button type="submit" class="btn-submit">Create Admin Account</button>
    </form>
    <div class="auth-cli">
      Or create the first user from the CLI:
      <code>{_esc(cli_cmd)}</code>
    </div>
  </div>
</div>""")


def _users_page(users: dict, current_user: str,
                flash_type: str = "", flash_msg: str = "") -> str:
    flash_html = ""
    if flash_msg:
        flash_html = f'<div class="flash flash-{_esc(flash_type)}">{_esc(flash_msg)}</div>'

    user_rows = ""
    for uname in sorted(users):
        is_you = uname == current_user
        you_label = '<span class="you">(you)</span>' if is_you else ""
        if is_you:
            delete_btn = '<span style="color:var(--subtle);font-size:0.72rem">cannot delete self</span>'
        else:
            # Two-step inline confirmation — no confirm() dialog, no popup blocker issues.
            # Clicking Delete reveals "Sure? Yes / No" in-place; No hides it again.
            safe_id = _esc(uname).replace(" ", "_")
            delete_btn = (
                f'<button type="button" class="btn btn-danger" id="del-btn-{safe_id}"'
                f' onclick="showDelConfirm(\'{safe_id}\')">Delete</button>'
                f'<span id="del-conf-{safe_id}" style="display:none;align-items:center;gap:0.4rem">'
                f'<span style="font-size:0.75rem;color:var(--muted)">Delete {_esc(uname)}?</span>'
                f'<form method="POST" action="/admin/users/delete" style="display:inline">'
                f'<input type="hidden" name="username" value="{_esc(uname)}">'
                f'<button type="submit" class="btn btn-danger">Yes</button></form>'
                f'<button type="button" class="btn btn-ghost"'
                f' onclick="hideDelConfirm(\'{safe_id}\')">No</button>'
                f'</span>'
            )
        user_rows += f"""<tr>
          <td>{_esc(uname)} {you_label}</td>
          <td style="text-align:right">{delete_btn}</td>
        </tr>"""

    user_options = "\n".join(
        f'<option value="{_esc(u)}">{_esc(u)}</option>'
        for u in sorted(users)
    )

    cli_add = "docker exec -it cppm-acme-cert-manager cppm-users add &lt;username&gt;"
    cli_pw  = "docker exec -it cppm-acme-cert-manager cppm-users passwd &lt;username&gt;"

    return _base("User Management", f"""
<div class="app">
  <div class="page-hdr">
    <span class="page-title">Admin User Management</span>
  </div>
  {flash_html}

  <div class="card" style="margin-bottom:1rem">
    <div class="card-title">Current Users</div>
    <table class="user-table">
      <thead><tr><th>Username</th><th></th></tr></thead>
      <tbody>{user_rows}</tbody>
    </table>
  </div>

  <div class="grid-2">

    <div class="card">
      <div class="card-title">Add User</div>
      <form method="POST" action="/admin/users/add" class="form-inline">
        <div class="field"><label>Username</label>
          <input type="text" name="username" required
                 pattern="[a-zA-Z0-9_-]{{1,64}}" autocomplete="off"></div>
        <div class="field"><label>Password <span style="color:var(--subtle);font-size:0.7rem">(min 8 chars)</span></label>
          <input type="password" name="password" minlength="8" required></div>
        <div class="field"><label>Confirm Password</label>
          <input type="password" name="confirm" required></div>
        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">Add User</button>
      </form>
    </div>

    <div class="card">
      <div class="card-title">Change Password</div>
      <form method="POST" action="/admin/users/passwd" class="form-inline">
        <div class="field"><label>User</label>
          <select name="username" style="width:100%;background:#0f172a;border:1px solid var(--border2);border-radius:0.4rem;padding:0.4rem 0.6rem;color:var(--text);font-size:0.8rem">
            {user_options}
          </select></div>
        <div class="field"><label>New Password <span style="color:var(--subtle);font-size:0.7rem">(min 8 chars)</span></label>
          <input type="password" name="password" minlength="8" required></div>
        <div class="field"><label>Confirm Password</label>
          <input type="password" name="confirm" required></div>
        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">Update Password</button>
      </form>
    </div>

  </div>

  <div class="card" style="margin-top:0">
    <div class="card-title">CLI Alternatives</div>
    <div style="display:flex;flex-direction:column;gap:0.5rem">
      <div style="font-size:0.78rem;color:var(--muted)">Add user:</div>
      <code style="font-family:monospace;font-size:0.72rem;background:#0a0f1a;padding:0.4rem 0.6rem;border-radius:3px;color:var(--muted)">{cli_add}</code>
      <div style="font-size:0.78rem;color:var(--muted);margin-top:0.25rem">Change password:</div>
      <code style="font-family:monospace;font-size:0.72rem;background:#0a0f1a;padding:0.4rem 0.6rem;border-radius:3px;color:var(--muted)">{cli_pw}</code>
    </div>
  </div>
</div>
<script>
function showDelConfirm(id) {{
  document.getElementById('del-btn-' + id).style.display = 'none';
  var c = document.getElementById('del-conf-' + id);
  c.style.display = 'inline-flex';
}}
function hideDelConfirm(id) {{
  document.getElementById('del-btn-' + id).style.display = '';
  document.getElementById('del-conf-' + id).style.display = 'none';
}}
</script>""", nav_user=current_user, active="users", show_nav=True)


def _overview_page(username: str = "") -> str:
    """Multi-server overview. Rows rendered server-side — no JS fetch required."""
    # Pre-warm health cache in background so dots are likely ready when the
    # browser fires loadHealth() a moment after the page arrives.
    threading.Thread(target=_build_health, daemon=True).start()

    try:
        servers = build_all_status()
    except Exception:
        _log.error("overview: build_all_status failed:\n%s", traceback.format_exc())
        servers = []

    rows = _overview_rows(servers)
    body = f"""
<div class="app">
<div class="page-hdr" style="margin-bottom:1rem">
  <span class="page-title">Certificate Manager Overview</span>
  <div style="display:flex;align-items:center;gap:0.75rem">
    <span class="pulse" id="pulse"></span>
    <span id="last-updated" style="font-size:0.75rem;color:var(--muted)">Live</span>
  </div>
</div>
<div class="card" style="padding:0;overflow:hidden">
  <table class="overview-table">
    <thead><tr>
      <th>ClearPass Server</th>
      <th>DNS &amp; ACME Provider</th>
      <th>ECC Certificate</th>
      <th>RSA Certificate</th>
      <th>Next Renewal Check</th>
      <th></th>
    </tr></thead>
    <tbody id="servers-body">{rows}</tbody>
  </table>
</div>
</div>"""
    return _base("Dashboard", body + _OVERVIEW_SCRIPT,
                 nav_user=username, active="dashboard", show_nav=True)


def _server_detail_page(server_id: str, username: str = "") -> str:
    """Per-server drill-down (existing dashboard panels, accessed at /server/<id>)."""
    sid_js = f'<script>var SERVER_ID = "{_esc(server_id)}";</script>'
    return _base("Server Details", _DETAIL_BODY + sid_js + _DETAIL_SCRIPT,
                 nav_user=username, active="dashboard", show_nav=True)


# ── Known CA patterns per ACME provider ──────────────────────────────────────

_KNOWN_EXCLUSIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("Let's Encrypt CA Certificate Exclusion", [
        ("ISRG Root X1", "Root CA — RSA trust anchor"),
        ("ISRG Root X2", "Root CA — ECDSA trust anchor"),
        ("R10", "RSA intermediate (2024 batch)"),
        ("R11", "RSA intermediate (2024 batch)"),
        ("R12", "RSA intermediate (2024 batch)"),
        ("R13", "RSA intermediate (2024 batch)"),
        ("R14", "RSA intermediate (2024 batch)"),
        ("E5",  "ECDSA intermediate (2024 batch)"),
        ("E6",  "ECDSA intermediate (2024 batch)"),
        ("E7",  "ECDSA intermediate (2024 batch)"),
        ("E8",  "ECDSA intermediate (2024 batch)"),
        ("E9",  "ECDSA intermediate (2024 batch)"),
        ("E10", "ECDSA intermediate (2024 batch)"),
    ]),
    ("ZeroSSL — Sectigo Chain CA Certificate Exclusion", [
        ("ZeroSSL RSA Domain Secure Site CA",    "RSA intermediate"),
        ("ZeroSSL ECC Domain Secure Site CA",    "ECDSA intermediate"),
        ("USERTrust RSA Certification Authority", "Root CA — RSA"),
        ("USERTrust ECC Certification Authority", "Root CA — ECDSA"),
        ("Sectigo AAA Certificate Services",      "Legacy root (cross-signed)"),
    ]),
    ("Buypass CA Certificate Exclusion", [
        ("Buypass Go SSL",          "Intermediate CA"),
        ("Buypass Class 2 Root CA", "Root CA"),
    ]),
]

_ALL_KNOWN_LOWER: set[str] = {
    p.lower() for _, certs in _KNOWN_EXCLUSIONS for p, _ in certs
}

# Maps acme_server value → index into _KNOWN_EXCLUSIONS
_ACME_PROVIDER_EXCL_IDX: dict[str, int] = {
    "letsencrypt":      0,
    "letsencrypt_test": 0,
    "zerossl":          1,
    "buypass":          2,
}


def _trust_exclusions_page(server: dict, username: str,
                            flash_type: str = "", flash_msg: str = "") -> str:
    """Per-server Trust Exclusions configuration page."""
    sid         = _esc(str(server.get("id", "")))
    label       = _esc(server.get("label") or server.get("cppm_host", ""))
    active_list = server.get("trust_exclusions") or []
    active_lower = {p.lower() for p in active_list}

    flash_html = (
        f'<div class="flash flash-{_esc(flash_type)}">{_esc(flash_msg)}</div>'
        if flash_msg else ""
    )

    acme_server  = server.get("acme_server", "letsencrypt")
    excl_idx     = _ACME_PROVIDER_EXCL_IDX.get(acme_server)
    excl_sections = [_KNOWN_EXCLUSIONS[excl_idx]] if excl_idx is not None else _KNOWN_EXCLUSIONS

    provider_html = ""
    for provider_name, certs in excl_sections:
        rows = "".join(
            f'<label class="excl-row">'
            f'<input type="checkbox" value="{_esc(p)}" onchange="teCbChange(this)"'
            f'{" checked" if p.lower() in active_lower else ""}>'
            f'<span class="excl-cn">{_esc(p)}</span>'
            f'<span class="excl-desc">{_esc(d)}</span>'
            f'</label>'
            for p, d in certs
        )
        provider_html += (
            f'<div class="card excl-card">'
            f'<div class="excl-provider">{_esc(provider_name)}</div>'
            f'{rows}'
            f'</div>'
        )

    te_val = _esc("\n".join(active_list))

    body = f"""
<div class="app">
  <div class="page-hdr">
    <span class="page-title">Trust Exclusions</span>
    <a href="/settings/edit/{sid}" class="btn btn-ghost">&#8592; Back to Edit Server</a>
  </div>
  <div style="font-size:0.82rem;color:var(--muted);margin-bottom:1.25rem">
    Server: <strong style="color:var(--text)">{label}</strong>
  </div>
  {flash_html}
  <div class="card" style="margin-bottom:1rem;font-size:0.82rem;color:var(--muted);line-height:1.65">
    Checked certificates are <strong style="color:var(--text)">excluded</strong> from
    ClearPass trust list management for this server — they will not be verified or
    uploaded even if present in the certificate chain. Leave all unchecked to manage
    all CA certificates automatically (recommended default).
  </div>
  <form method="POST" action="/settings/trust-exclusions/{sid}">
    {provider_html}
    <div class="card excl-card">
      <div class="excl-provider">Active Exclusions</div>
      <p style="font-size:0.78rem;color:var(--muted);margin-bottom:0.6rem;line-height:1.5">
        One CN pattern per line. Case-insensitive partial match against the certificate
        Subject CN — e.g. <code style="font-size:0.75rem;color:var(--accent)">ISRG Root</code>
        matches both ISRG Root X1 and X2. Use the checkboxes above or edit directly.
      </p>
      <textarea id="trust_exclusions" name="trust_exclusions" rows="4"
        style="width:100%;background:#0f172a;border:1px solid var(--border2);
               border-radius:0.4rem;padding:0.5rem 0.75rem;color:var(--text);
               font-family:monospace;font-size:0.82rem;resize:vertical;outline:none;
               transition:border-color .15s"
        onfocus="this.style.borderColor='var(--accent)'"
        onblur="this.style.borderColor=''"
        oninput="teSync()"
        >{te_val}</textarea>
    </div>
    <div style="display:flex;gap:0.75rem;margin-top:1.25rem">
      <button type="submit" class="btn btn-primary">Save Exclusions</button>
      <a href="/settings/edit/{sid}" class="btn btn-ghost">Cancel</a>
    </div>
  </form>
</div>"""

    script = """
<script>
function teSetStrike(cb) {
  cb.closest('.excl-row').classList.toggle('excl-excluded', cb.checked);
}
function teSync() {
  var ta = document.getElementById('trust_exclusions');
  var lines = ta.value.split('\\n').map(function(l){return l.trim();}).filter(Boolean);
  var active = {};
  lines.forEach(function(l){active[l.toLowerCase()] = true;});
  document.querySelectorAll('.excl-row input[type=checkbox]').forEach(function(cb){
    cb.checked = !!active[cb.value.toLowerCase()];
    teSetStrike(cb);
  });
}
function teCbChange(cb) {
  var ta = document.getElementById('trust_exclusions');
  var lines = ta.value.split('\\n').map(function(l){return l.trim();}).filter(Boolean);
  if (cb.checked) {
    if (lines.map(function(l){return l.toLowerCase();}).indexOf(cb.value.toLowerCase()) === -1)
      lines.push(cb.value);
  } else {
    lines = lines.filter(function(l){return l.toLowerCase() !== cb.value.toLowerCase();});
  }
  ta.value = lines.join('\\n');
  teSetStrike(cb);
}
document.addEventListener('DOMContentLoaded', teSync);
</script>"""

    return _base("Trust Exclusions", body + script,
                 nav_user=username, active="settings", show_nav=True)


# ── Settings pages ───────────────────────────────────────────────────────────

def _settings_list_page(servers: list, username: str,
                        flash_type: str = "", flash_msg: str = "") -> str:
    flash_html = ""
    if flash_msg:
        flash_html = f'<div class="flash flash-{_esc(flash_type)}">{_esc(flash_msg)}</div>'

    if not servers:
        rows = ('<tr><td colspan="5"><div class="empty">'
                'No servers configured yet.&nbsp; '
                '<a href="/settings/add" style="color:var(--accent)">Add the first server</a>.'
                '</div></td></tr>')
    else:
        rows = ""
        for s in servers:
            sid    = _esc(str(s.get("id", "")))
            label  = _esc(s.get("label", ""))
            host   = _esc(s.get("cppm_host", ""))
            domain = _esc(s.get("domain", ""))
            prov   = _esc(s.get("dns_provider", ""))
            acme   = _esc(s.get("acme_server", "letsencrypt"))
            del_btn = (
                f'<button type="button" class="btn btn-danger" id="del-btn-{sid}"'
                f' onclick="showDelConfirm(\'{sid}\')">Delete</button>'
                f'<span id="del-conf-{sid}" style="display:none;align-items:center;gap:0.4rem">'
                f'<span style="font-size:0.75rem;color:var(--muted)">Delete {label}?</span>'
                f'<form method="POST" action="/settings/delete" style="display:inline">'
                f'<input type="hidden" name="id" value="{sid}">'
                f'<button type="submit" class="btn btn-danger">Yes</button></form>'
                f'<button type="button" class="btn btn-ghost"'
                f' onclick="hideDelConfirm(\'{sid}\')">No</button>'
                f'</span>'
            )
            rows += (
                f'<tr>'
                f'<td><strong>{label}</strong></td>'
                f'<td style="font-family:monospace;font-size:0.78rem">{host}</td>'
                f'<td style="font-family:monospace;font-size:0.78rem">{domain}</td>'
                f'<td>{prov}</td>'
                f'<td style="text-align:right;white-space:nowrap">'
                f'<a href="/settings/edit/{sid}" class="btn btn-ghost" style="margin-right:0.4rem">Edit</a>'
                f'{del_btn}'
                f'</td>'
                f'</tr>'
            )

    # JS uses raw string to avoid {{ }} escaping
    script = """
<script>
function showDelConfirm(id) {
  document.getElementById('del-btn-' + id).style.display = 'none';
  var c = document.getElementById('del-conf-' + id);
  c.style.display = 'inline-flex';
}
function hideDelConfirm(id) {
  document.getElementById('del-btn-' + id).style.display = '';
  document.getElementById('del-conf-' + id).style.display = 'none';
}
</script>"""

    body = f"""
<div class="app">
  <div class="page-hdr">
    <span class="page-title">ClearPass Servers</span>
    <a href="/settings/add" class="btn btn-primary">&#43; Add Server</a>
  </div>
  {flash_html}
  <div class="card">
    <table class="settings-table">
      <thead><tr>
        <th>Label</th><th>ClearPass Host</th><th>Domain</th><th>DNS Provider</th><th></th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"""
    return _base("Servers", body + script,
                 nav_user=username, active="settings", show_nav=True)


def _settings_form_page(server: dict = None, error: str = "",
                        is_edit: bool = False, username: str = "") -> str:
    if server is None:
        server = _default_server_from_env()

    s       = server
    creds   = s.get("dns_credentials", {})
    sid     = _esc(str(s.get("id", "")))
    action  = f'/settings/edit/{sid}' if is_edit else '/settings/add'
    title   = "Edit Server" if is_edit else "Add Server"
    submit  = "Save Changes" if is_edit else "Add Server"

    err_html = f'<div class="flash flash-err">{_esc(error)}</div>' if error else ""

    # Shorthand helpers (closures over s / creds)
    def fv(k, d=""):  return _esc(str(s.get(k, d)))
    def cv(k, d=""):  return _esc(str(creds.get(k, d)))
    def sel(v, t):    return " selected" if v == t else ""
    def vis(p):       return "" if p == s.get("dns_provider", "cloudflare") else ' style="display:none"'

    acme_srv   = s.get("acme_server", "letsencrypt")
    verify     = " checked" if s.get("cppm_verify_ssl") else ""
    cert_types = s.get("cert_types") or ["ecc", "rsa"]
    chk_ecc    = " checked" if "ecc" in cert_types else ""
    chk_rsa    = " checked" if "rsa" in cert_types else ""
    te_link  = (
        f'<div style="margin-top:0.85rem">'
        f'<a href="/settings/trust-exclusions/{sid}" class="btn btn-ghost">Trust Exclusions</a>'
        f'</div>'
    ) if is_edit else ""

    # Form body — f-string with all interpolated Python values.
    # JavaScript is in a separate raw string appended below (no {{ }} issues).
    form = f"""
<div class="app">
  <div class="page-hdr">
    <span class="page-title">{title}</span>
    <a href="/settings" class="btn btn-ghost">&#8592; Back</a>
  </div>
  {err_html}
  <form method="POST" action="{action}">

    <div class="card" style="margin-bottom:1rem">
      <div class="form-section-title">Server Identity</div>
      <div class="field">
        <label>Label <span class="hint">(friendly name)</span></label>
        <input type="text" name="label" value="{fv('label')}" required
               placeholder="e.g. Production ClearPass">
      </div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <div class="form-section-title">ClearPass Server</div>
      <div class="form-2col">
        <div class="field">
          <label>Host / IP</label>
          <input type="text" name="cppm_host" value="{fv('cppm_host')}" required
                 placeholder="cppm.example.com">
        </div>
        <div class="field">
          <label>Client ID</label>
          <input type="text" name="cppm_client_id" value="{fv('cppm_client_id')}" required
                 autocomplete="off">
        </div>
      </div>
      <div class="form-2col">
        <div class="field">
          <label>Client Secret</label>
          <input type="password" name="cppm_client_secret" value="{fv('cppm_client_secret')}"
                 autocomplete="new-password">
        </div>
        <div class="field">
          <label>Cert Passphrase <span class="hint">(PKCS12 export)</span></label>
          <input type="password" name="cppm_cert_passphrase" value="{fv('cppm_cert_passphrase')}"
                 autocomplete="new-password">
        </div>
      </div>
      <div class="form-2col">
        <div class="field">
          <label>Callback Host <span class="hint">(Docker host LAN IP)</span></label>
          <input type="text" name="cppm_callback_host" value="{fv('cppm_callback_host')}"
                 placeholder="10.0.0.5">
        </div>
        <div class="field">
          <label>Callback Port</label>
          <input type="number" name="cppm_callback_port"
                 value="{fv('cppm_callback_port', '8765')}"
                 min="1" max="65535">
        </div>
      </div>
      <div class="field" style="margin-bottom:0">
        <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer">
          <input type="checkbox" name="cppm_verify_ssl" value="true"{verify}
                 style="width:auto;margin:0">
          Verify SSL (enable after initial certificate install)
        </label>
      </div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <div class="form-section-title">ACME Provider</div>
      <div class="form-2col">
        <div class="field">
          <label>Domain</label>
          <input type="text" name="domain" value="{fv('domain')}" required
                 placeholder="cppm.example.com">
        </div>
        <div class="field">
          <label>ACME Email</label>
          <input type="email" name="acme_email" value="{fv('acme_email')}" required
                 placeholder="admin@example.com">
        </div>
      </div>
      <div class="field">
        <label>Certificate Authority</label>
        <select name="acme_server">
          <option value="letsencrypt"{sel(acme_srv,'letsencrypt')}>Let&apos;s Encrypt</option>
          <option value="letsencrypt_test"{sel(acme_srv,'letsencrypt_test')}>Let&apos;s Encrypt (Staging)</option>
          <option value="zerossl"{sel(acme_srv,'zerossl')}>ZeroSSL</option>
          <option value="buypass"{sel(acme_srv,'buypass')}>Buypass</option>
        </select>
      </div>
      <div class="field" style="margin-bottom:0">
        <label>Certificate Types</label>
        <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;margin-top:0.35rem">
          <input type="checkbox" name="issue_ecc" value="true"{chk_ecc}
                 style="width:auto;margin:0">
          ECC <span class="hint">— HTTPS / Web Interface</span>
        </label>
        <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;margin-top:0.35rem">
          <input type="checkbox" name="issue_rsa" value="true"{chk_rsa}
                 style="width:auto;margin:0">
          RSA <span class="hint">— RADIUS / 802.1x</span>
        </label>
      </div>
      {te_link}
    </div>

    <div class="card" style="margin-bottom:1.5rem">
      <div class="form-section-title">DNS Provider</div>
      <div class="field">
        <label>Provider</label>
        <select name="dns_provider" id="dns_provider" onchange="switchDns(this.value)">
          <option value="cloudflare"{sel(s.get('dns_provider','cloudflare'),'cloudflare')}>Cloudflare</option>
          <option value="porkbun"{sel(s.get('dns_provider',''),'porkbun')}>Porkbun</option>
          <option value="route53"{sel(s.get('dns_provider',''),'route53')}>AWS Route 53</option>
          <option value="digitalocean"{sel(s.get('dns_provider',''),'digitalocean')}>DigitalOcean</option>
          <option value="godaddy"{sel(s.get('dns_provider',''),'godaddy')}>GoDaddy</option>
        </select>
      </div>

      <div id="dns-cloudflare" class="dns-section"{vis('cloudflare')}>
        <div class="form-2col">
          <div class="field">
            <label>API Token <span class="hint">(Zone DNS, scoped — recommended)</span></label>
            <input type="password" name="CF_Token" value="{cv('CF_Token')}"
                   autocomplete="new-password">
          </div>
          <div class="field">
            <label>Zone ID</label>
            <input type="text" name="CF_Zone_ID" value="{cv('CF_Zone_ID')}"
                   autocomplete="off">
          </div>
        </div>
        <div class="form-2col">
          <div class="field">
            <label>Account ID <span class="hint">(optional with token)</span></label>
            <input type="text" name="CF_Account_ID" value="{cv('CF_Account_ID')}"
                   autocomplete="off">
          </div>
          <div class="field" style="opacity:0.65">
            <label>Global API Key <span class="hint">(alternative to token)</span></label>
            <input type="password" name="CF_Key" value="{cv('CF_Key')}"
                   autocomplete="new-password">
          </div>
        </div>
        <div class="field" style="opacity:0.65;margin-bottom:0">
          <label>Account Email <span class="hint">(required with global key only)</span></label>
          <input type="email" name="CF_Email" value="{cv('CF_Email')}"
                 autocomplete="off">
        </div>
      </div>

      <div id="dns-porkbun" class="dns-section"{vis('porkbun')}>
        <div class="form-2col">
          <div class="field">
            <label>API Key</label>
            <input type="password" name="PORKBUN_API_KEY" value="{cv('PORKBUN_API_KEY')}"
                   autocomplete="new-password">
          </div>
          <div class="field">
            <label>Secret API Key</label>
            <input type="password" name="PORKBUN_SECRET_API_KEY"
                   value="{cv('PORKBUN_SECRET_API_KEY')}" autocomplete="new-password">
          </div>
        </div>
      </div>

      <div id="dns-route53" class="dns-section"{vis('route53')}>
        <div class="form-2col">
          <div class="field">
            <label>Access Key ID</label>
            <input type="text" name="AWS_ACCESS_KEY_ID" value="{cv('AWS_ACCESS_KEY_ID')}"
                   autocomplete="off">
          </div>
          <div class="field">
            <label>Secret Access Key</label>
            <input type="password" name="AWS_SECRET_ACCESS_KEY"
                   value="{cv('AWS_SECRET_ACCESS_KEY')}" autocomplete="new-password">
          </div>
        </div>
        <div class="field" style="margin-bottom:0">
          <label>Region</label>
          <input type="text" name="AWS_DEFAULT_REGION"
                 value="{cv('AWS_DEFAULT_REGION', 'us-east-1')}" autocomplete="off">
        </div>
      </div>

      <div id="dns-digitalocean" class="dns-section"{vis('digitalocean')}>
        <div class="field" style="margin-bottom:0">
          <label>API Token</label>
          <input type="password" name="DO_API_KEY" value="{cv('DO_API_KEY')}"
                 autocomplete="new-password">
        </div>
      </div>

      <div id="dns-godaddy" class="dns-section"{vis('godaddy')}>
        <div class="form-2col">
          <div class="field">
            <label>API Key</label>
            <input type="text" name="GD_Key" value="{cv('GD_Key')}" autocomplete="off">
          </div>
          <div class="field">
            <label>API Secret</label>
            <input type="password" name="GD_Secret" value="{cv('GD_Secret')}"
                   autocomplete="new-password">
          </div>
        </div>
      </div>
    </div>

    <div style="display:flex;gap:0.75rem;justify-content:flex-end;margin-bottom:2rem">
      <a href="/settings" class="btn btn-ghost">Cancel</a>
      <button type="submit" class="btn btn-primary">{submit}</button>
    </div>
  </form>
</div>"""

    # JavaScript — separate raw string: no {{ }} escaping needed.
    script = """
<script>
function switchDns(val) {
  document.querySelectorAll('.dns-section').forEach(function(el) {
    var active = el.id === 'dns-' + val;
    el.style.display = active ? '' : 'none';
    el.querySelectorAll('input').forEach(function(inp) {
      inp.disabled = !active;
    });
  });
}
(function() { switchDns(document.getElementById('dns_provider').value); })();

</script>"""

    return _base(title, form + script,
                 nav_user=username, active="settings", show_nav=True)


# ── Overview page (multi-server table) ───────────────────────────────────────
# Rows are rendered server-side in Python so the table is always populated the
# moment the HTML arrives — no JS fetch needed for initial display.

_DNS_DISPLAY = {
    "cloudflare": "Cloudflare", "porkbun": "Porkbun",
    "route53": "AWS Route 53", "digitalocean": "DigitalOcean", "godaddy": "GoDaddy",
}
_ACME_DISPLAY = {
    "letsencrypt":      "Let's Encrypt",
    "letsencrypt_test": "Let's Encrypt (Staging)",
    "zerossl":          "ZeroSSL",
    "buypass":          "Buypass",
}


def _cert_cls(days) -> str:
    if days is None: return "none"
    if days > 30:    return "ok"
    if days > 14:    return "warn"
    return "danger"


def _fmt_expiry(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y")
    except Exception:
        return iso


def _mini_cert(cert: dict, label: str, service: str = "") -> str:
    svc_html = (f'<div class="mini-svc">{_esc(service)}</div>') if service else ""
    if not cert.get("exists"):
        return (f'<div class="mini-cert none"><div class="mini-days none">—</div>'
                f'<div class="mini-label">{_esc(label)}</div>'
                f'<div class="mini-exp">Not found</div>'
                f'{svc_html}</div>')
    d = cert.get("days_left")
    c = _cert_cls(d)
    return (f'<div class="mini-cert {c}">'
            f'<div class="mini-days {c}">{d if d is not None else "—"}</div>'
            f'<div class="mini-label">days &middot; {_esc(label)}</div>'
            f'<div class="mini-exp">{_esc(_fmt_expiry(cert.get("not_after", "")))}</div>'
            f'{svc_html}'
            f'</div>')


def _sched_cell(sc: dict) -> str:
    return (f'<div class="sched-next">{_esc(sc.get("until", "—"))}</div>'
            f'<div class="sched-label">until next check</div>'
            f'<div class="sched-sub">{_esc(sc.get("schedule", "—"))}</div>')


def _overview_rows(servers: list) -> str:
    if not servers:
        return ('<tr><td colspan="6"><div class="empty">No servers configured. '
                '<a href="/settings/add" style="color:var(--accent)">Add a server</a>.'
                '</div></td></tr>')
    rows = []
    for s in servers:
        sid  = _esc(str(s.get("id", "")))
        host = _esc(s.get("cppm_host", ""))
        dns  = _esc(_DNS_DISPLAY.get(s.get("dns_provider", ""), s.get("dns_provider", "")))
        acme = _esc(_ACME_DISPLAY.get(s.get("acme_server", ""), s.get("acme_server", "")))
        ecc  = s.get("certs", {}).get("ecc", {"exists": False})
        rsa  = s.get("certs", {}).get("rsa", {"exists": False})
        raw_sid = str(s.get("id", ""))
        def _dot(kind: str) -> str:
            return (f'<span id="ov-{_esc(raw_sid)}-{kind}" class="sdot checking"'
                    f' title="checking…" style="margin-right:0.2rem"></span>')
        dots = (f'<div style="display:flex;align-items:center;gap:0.4rem;margin-top:0.35rem">'
                f'{_dot("cppm")}<span style="font-size:0.68rem;color:var(--subtle)">CPPM</span>'
                f'<span style="color:var(--border2);margin:0 0.15rem">·</span>'
                f'{_dot("dns")}<span style="font-size:0.68rem;color:var(--subtle)">DNS</span>'
                f'<span style="color:var(--border2);margin:0 0.15rem">·</span>'
                f'{_dot("cb")}<span style="font-size:0.68rem;color:var(--subtle)">Callback</span>'
                f'</div>')
        rows.append(
            f'<tr class="server-row" onclick="window.location.href=\'/server/{sid}\'">'
            f'<td>'
            f'<div class="srv-label">{_esc(s.get("label", "") or s.get("cppm_host", ""))}</div>'
            f'<div class="srv-host">{host}</div>'
            f'{dots}</td>'
            f'<td>'
            f'{dns}'
            f'<div style="font-size:0.65rem;color:var(--subtle);margin-top:0.18rem">{acme}</div>'
            f'</td>'
            f'<td>{_mini_cert(ecc, "ECC", "HTTPS · Web Interface")}</td>'
            f'<td>{_mini_cert(rsa, "RSA", "RADIUS · 802.1X")}</td>'
            f'<td>{_sched_cell(s.get("schedule", {}))}</td>'
            f'<td style="text-align:right">'
            f'<a href="/server/{sid}" class="btn btn-ghost" onclick="event.stopPropagation()">Details &#8594;</a>'
            f'</td></tr>'
        )
    return "".join(rows)

_OVERVIEW_SCRIPT = """
<script>
var REFRESH_MS = 30000;
var HEALTH_MS  = 300000;

function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function cls(d){if(d==null)return'none';if(d>30)return'ok';if(d>14)return'warn';return'danger';}
function fmtDate(iso){if(!iso)return'—';try{return new Date(iso).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});}catch(e){return iso;}}
function dnsLabel(p){var m={cloudflare:'Cloudflare',porkbun:'Porkbun',route53:'AWS Route 53',digitalocean:'DigitalOcean',godaddy:'GoDaddy'};return m[p]||p||'—';}
function acmeLabel(s){var m={letsencrypt:"Let's Encrypt",letsencrypt_test:"Let's Encrypt (Staging)",zerossl:'ZeroSSL',buypass:'Buypass'};return m[s]||s||'—';}

function renderMiniCert(cert,label,svc){
  var svcHtml=svc?'<div class="mini-svc">'+esc(svc)+'</div>':'';
  if(!cert||!cert.exists){return'<div class="mini-cert none"><div class="mini-days none">—</div><div class="mini-label">'+esc(label)+'</div><div class="mini-exp">Not found</div>'+svcHtml+'</div>';}
  var d=cert.days_left,c=cls(d);
  return'<div class="mini-cert '+c+'"><div class="mini-days '+c+'">'+(d!=null?d:'—')+'</div><div class="mini-label">days &middot; '+esc(label)+'</div><div class="mini-exp">'+esc(fmtDate(cert.not_after))+'</div>'+svcHtml+'</div>';
}
function renderSched(sc){sc=sc||{};return'<div class="sched-next">'+esc(sc.until||'—')+'</div><div class="sched-label">until next check</div><div class="sched-sub">'+esc(sc.schedule||'—')+'</div>';}
function ovDot(sid,kind){
  return'<span id="ov-'+esc(sid)+'-'+kind+'" class="sdot checking" title="checking…" style="margin-right:0.2rem"></span>';
}
function renderDots(sid){
  var sep='<span style="color:var(--border2);margin:0 0.15rem">\xb7</span>';
  return'<div style="display:flex;align-items:center;gap:0.4rem;margin-top:0.35rem">'
    +ovDot(sid,'cppm')+'<span style="font-size:0.68rem;color:var(--subtle)">CPPM</span>'+sep
    +ovDot(sid,'dns')+'<span style="font-size:0.68rem;color:var(--subtle)">DNS</span>'+sep
    +ovDot(sid,'cb')+'<span style="font-size:0.68rem;color:var(--subtle)">Callback</span>'
    +'</div>';
}
function renderRow(s){
  var sid=s.id||'';
  var ecc=(s.certs&&s.certs.ecc)||{exists:false};
  var rsa=(s.certs&&s.certs.rsa)||{exists:false};
  return'<tr class="server-row" onclick="window.location.href=\'/server/'+esc(sid)+'\'">'
    +'<td><div class="srv-label">'+esc(s.label||s.cppm_host)+'</div>'
    +'<div class="srv-host">'+esc(s.cppm_host)+'</div>'
    +renderDots(sid)+'</td>'
    +'<td>'+esc(dnsLabel(s.dns_provider))
    +'<div style="font-size:0.65rem;color:var(--subtle);margin-top:0.18rem">'+esc(acmeLabel(s.acme_server))+'</div></td>'
    +'<td>'+renderMiniCert(ecc,'ECC','HTTPS \xb7 Web Interface')+'</td><td>'+renderMiniCert(rsa,'RSA','RADIUS \xb7 802.1X')+'</td>'
    +'<td>'+renderSched(s.schedule)+'</td>'
    +'<td style="text-align:right"><a href="/server/'+esc(sid)+'" class="btn btn-ghost" onclick="event.stopPropagation()">Details &#8594;</a></td></tr>';
}

function applyDot(el,h){var s=h.status||'unknown',m=h.message||'';el.className='sdot '+s;el.title=m?(s+': '+m):s;}
var _ovHealth={};
function applyAllHealthDots(){
  var servers=(_ovHealth&&_ovHealth.servers)||{};
  Object.keys(servers).forEach(function(sid){
    var sh=servers[sid]||{};
    ['cppm','dns','callback'].forEach(function(k){
      var elId='ov-'+sid+'-'+(k==='callback'?'cb':k);
      var el=document.getElementById(elId);
      if(el&&sh[k])applyDot(el,sh[k]);
    });
  });
}
var _healthRetry=0;
async function loadHealth(){
  try{
    var res=await fetch('/api/health');
    if(res.ok){
      _ovHealth=await res.json();
      _healthRetry=0;
      applyAllHealthDots();
    }
  }catch(e){}
  var delay=_healthRetry<3?[5000,10000,30000][_healthRetry]:HEALTH_MS;
  _healthRetry=Math.min(_healthRetry+1,3);
  setTimeout(loadHealth,delay);
}

async function loadStatus(){
  var pulse=document.getElementById('pulse');
  try{
    if(pulse)pulse.classList.add('active');
    var res=await fetch('/api/status');
    if(res.status===401){window.location.href='/login';return;}
    if(!res.ok)throw new Error('HTTP '+res.status);
    var data=await res.json();
    if(Array.isArray(data)&&data.length){
      document.getElementById('servers-body').innerHTML=data.map(renderRow).join('');
      document.getElementById('last-updated').textContent='Updated '+new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
      applyAllHealthDots();
    }
  }catch(e){
    document.getElementById('last-updated').textContent='Refresh error: '+e.message;
  }finally{
    if(pulse)setTimeout(function(){pulse.classList.remove('active');},800);
  }
}

setInterval(loadStatus,REFRESH_MS);
loadStatus();
loadHealth();
</script>
"""


# ── Per-server detail page ─────────────────────────────────────────────────────

_DETAIL_BODY = """
<div id="detail-back" style="padding:1rem 1rem 0">
  <a href="/" class="btn btn-ghost">&#8592; All Servers</a>
</div>

<div class="app">

<div class="hdr">
  <div class="hdr-left">
    <span class="hdr-domain" id="hdr-domain">&hellip;</span>
  </div>
  <div class="hdr-right">
    <span class="pulse" id="pulse"></span>
    <span id="last-updated">Loading&hellip;</span>
  </div>
</div>

<div class="grid-2" id="cert-cards"></div>
<div class="grid-2" id="info-cards"></div>

<div class="log-card">
  <div class="log-hdr">
    <span class="card-title" style="margin:0">Activity Log</span>
    <span class="log-count" id="log-count"></span>
  </div>
  <table class="log-table">
    <tbody id="log-body">
      <tr><td colspan="4"><div class="empty">Loading&hellip;</div></td></tr>
    </tbody>
  </table>
</div>

</div>

<div class="overlay" id="overlay" onclick="overlayClick(event)">
  <div class="modal">
    <div class="modal-hdr">
      <span class="modal-title" id="modal-title">Certificate Details</span>
      <button class="modal-x" onclick="closeModal()">&#x2715;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>
"""

_DETAIL_SCRIPT = """
<script>
// SERVER_ID is injected as a <script> block immediately before this file
var REFRESH_MS = 30000;
var HEALTH_MS  = 300000;
var _certData  = {ecc: null, rsa: null};
var _statusData = null;
var _healthData = {};
var _SERVER_ID  = (typeof SERVER_ID !== 'undefined') ? SERVER_ID : 'env';

function esc(s) {
  return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function cls(d) {
  if(d==null)return'none';if(d>30)return'ok';if(d>14)return'warn';return'danger';
}
function fmtDate(iso){if(!iso)return'—';try{return new Date(iso).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});}catch(e){return iso;}}
function fmtDT(iso){if(!iso)return'—';try{return new Date(iso).toLocaleString('en-US',{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'});}catch(e){return iso;}}
function dnsLabel(p){var m={cloudflare:'Cloudflare',cf:'Cloudflare',porkbun:'Porkbun',route53:'AWS Route53',aws:'AWS Route53',r53:'AWS Route53',digitalocean:'DigitalOcean',do:'DigitalOcean',godaddy:'GoDaddy',gd:'GoDaddy'};return m[p]||p;}
function caLabel(s){var m={letsencrypt:"Let's Encrypt",letsencrypt_test:"Let's Encrypt (Staging)",zerossl:'ZeroSSL',buypass:'Buypass'};return m[s]||s;}
function lvlBadge(l){var c={OK:'lvl-ok',WARN:'lvl-warn',FAILED:'lvl-failed',INFO:'lvl-info'}[l]||'lvl-info';return'<span class="lvl '+c+'">'+esc(l)+'</span>';}
function keyLabel(cert){if(!cert.key_type)return'—';if(cert.key_type==='ECDSA'&&cert.key_curve)return cert.key_type+' ('+cert.key_curve+')';if(cert.key_size)return cert.key_type+' '+cert.key_size+'-bit';return cert.key_type;}

function renderCertCard(cert,label,service,key){
  if(!cert.exists){return'<div class="cert-card"><div class="cert-header"><span class="cert-title">'+esc(label)+'</span><span class="badge badge-none">Not Found</span></div><div class="days-num none">—</div><div class="days-label">days remaining</div><div class="meta"><div class="row"><span class="lbl">Service</span><span class="val">'+esc(service)+'</span></div></div></div>';}
  var d=cert.days_left,c=cls(d);
  var slbl=c==='ok'?'Valid':c==='warn'?'Expiring Soon':c==='danger'?'Critical':'Unknown';
  return'<div class="cert-card '+c+'"><div class="cert-header"><span class="cert-title">'+esc(label)+'</span><span class="badge badge-'+c+'">'+slbl+'</span></div>'
    +'<div class="days-num '+c+'">'+(d!=null?d:'—')+'</div><div class="days-label">days remaining</div>'
    +'<div class="meta">'
    +'<div class="row"><span class="lbl">Expires</span><span class="val">'+fmtDate(cert.not_after)+'</span></div>'
    +'<div class="row"><span class="lbl">Issued</span><span class="val">'+fmtDate(cert.not_before)+'</span></div>'
    +'<div class="row"><span class="lbl">Issuer</span><span class="val">'+esc(cert.issuer_cn||'—')+'</span></div>'
    +'<div class="row"><span class="lbl">Key</span><span class="val">'+esc(keyLabel(cert))+'</span></div>'
    +'<div class="row"><span class="lbl">Service</span><span class="val">'+esc(service)+'</span></div>'
    +'</div>'
    +'<div class="actions"><button class="btn btn-primary" data-key="'+key+'" onclick="showCert(this.dataset.key)">View Details</button></div>'
    +'</div>';
}

function applyDot(el,h){var s=h.status||'unknown',msg=h.message||'';el.className='sdot '+s;el.title=msg?(s+': '+msg):s;}
function sdot(id,h){
  var s=(h&&h.status)||'checking',m=(h&&h.message)||'';
  var tip=m?(s+': '+m):s;
  return '<span id="'+id+'" class="sdot '+s+'" title="'+esc(tip)+'"></span>';
}
function renderInfoCards(data, health){
  health=health||{};
  var sc=data.schedule||{};
  var sh=(health.servers&&health.servers[_SERVER_ID])||{};
  var sched='<div class="card"><div class="card-title">Renewal Schedule</div><div class="big-val">'+esc(sc.until||'—')+'</div><div class="sub-val">until next check</div><div class="meta">'
    +'<div class="row"><span class="lbl">Next check</span><span class="val">'+esc(fmtDT(sc.next_dt))+'</span></div>'
    +'<div class="row"><span class="lbl">Schedule</span><span class="val">'+esc(sc.schedule||'—')+'</span></div>'
    +'<div class="row"><span class="lbl">Renews at</span><span class="val">'+esc(sc.threshold||'—')+'</span></div>'
    +'</div></div>';
  var cfg='<div class="card"><div class="card-title">Configuration</div><div class="meta">'
    +'<div class="row"><span class="lbl">Domain</span><span class="val">'+esc(data.domain)+'</span></div>'
    +'<div class="row"><span class="lbl">DNS</span><span class="val">'+sdot('d-dot-dns',sh.dns)+esc(dnsLabel(data.dns_provider))+'</span></div>'
    +'<div class="row"><span class="lbl">CA</span><span class="val">'+esc(caLabel(data.acme_server))+'</span></div>'
    +'<div class="row"><span class="lbl">ClearPass</span><span class="val">'+sdot('d-dot-cppm',sh.cppm)+esc(data.cppm_host)+'</span></div>'
    +(data.callback_host
      ?'<div class="row"><span class="lbl">Callback</span><span class="val">'+sdot('d-dot-cb',sh.callback)+'http://'+esc(data.callback_host)+':'+esc(data.callback_port)+'/'+'</span></div>'
      :'')
    +'</div></div>';
  return sched+cfg;
}

function renderLog(activity){
  if(!activity||!activity.length)return'<tr><td colspan="4"><div class="empty">No activity recorded yet.</div></td></tr>';
  return activity.map(function(e){return'<tr><td class="ts">'+esc(e.ts)+'</td><td class="lvl-cell">'+lvlBadge(e.level)+'</td><td class="cat">'+esc(e.category)+'</td><td class="msg">'+esc(e.message)+'</td></tr>';}).join('');
}

function render(data){
  _statusData=data;
  document.getElementById('hdr-domain').textContent=data.domain||'—';
  document.getElementById('last-updated').textContent='Updated '+new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  var ecc=(data.certs&&data.certs.ecc)||{exists:false};
  var rsa=(data.certs&&data.certs.rsa)||{exists:false};
  _certData.ecc=ecc; _certData.rsa=rsa;
  document.getElementById('cert-cards').innerHTML=renderCertCard(ecc,'ECC Certificate','HTTPS(ECC)','ecc')+renderCertCard(rsa,'RSA Certificate','RADIUS','rsa');
  document.getElementById('info-cards').innerHTML=renderInfoCards(data,_healthData);
  document.getElementById('log-body').innerHTML=renderLog(data.activity);
  var cnt=(data.activity||[]).length;
  document.getElementById('log-count').textContent=cnt+' event'+(cnt!==1?'s':'');
}

function showCert(key){
  var labels={ecc:'ECC Certificate',rsa:'RSA Certificate'};
  showModal(_certData[key]||{exists:false},labels[key]||key);
}

async function loadStatus(){
  var pulse=document.getElementById('pulse');
  pulse.classList.add('active');
  try{
    var res=await fetch('/api/status/'+_SERVER_ID);
    if(res.status===401){window.location.href='/login';return;}
    if(!res.ok)throw new Error('HTTP '+res.status);
    var data=await res.json();
    render(data);
  }catch(e){
    document.getElementById('last-updated').textContent='Error: '+e.message;
  }finally{
    setTimeout(function(){pulse.classList.remove('active');},800);
  }
}
var _healthRetry=0;
async function loadHealth(){
  try{
    var res=await fetch('/api/health');
    if(res.ok){
      _healthData=await res.json();
      _healthRetry=0;
      var sh=(_healthData.servers&&_healthData.servers[_SERVER_ID])||{};
      var ce=document.getElementById('d-dot-cppm');
      var de=document.getElementById('d-dot-dns');
      var cbe=document.getElementById('d-dot-cb');
      if(ce&&sh.cppm)    applyDot(ce,sh.cppm);
      if(de&&sh.dns)     applyDot(de,sh.dns);
      if(cbe&&sh.callback) applyDot(cbe,sh.callback);
    }
  }catch(e){}
  var delay=_healthRetry<3?[5000,10000,30000][_healthRetry]:HEALTH_MS;
  _healthRetry=Math.min(_healthRetry+1,3);
  setTimeout(loadHealth,delay);
}
setInterval(loadStatus,REFRESH_MS);
loadStatus();
loadHealth();

function showModal(cert,label){
  var kl=keyLabel(cert);
  var sans=(cert.san||[]).join(', ')||'—';
  var serial=cert.serial?(cert.serial.match(/.{1,2}/g)||[cert.serial]).join(':'):'—';
  var issuer=[cert.issuer_cn,cert.issuer_org].filter(Boolean).join(' / ')||'—';
  var html='<div class="detail-grid">'
    +'<span class="dl">Subject CN</span><span class="dv">'+esc(cert.cn||'—')+'</span>'
    +'<span class="dl">SANs</span><span class="dv">'+esc(sans)+'</span>'
    +'<span class="dl">Issuer</span><span class="dv">'+esc(issuer)+'</span>'
    +'<span class="dl">Serial</span><span class="dv">'+esc(serial)+'</span>'
    +'<span class="dl">Key</span><span class="dv">'+esc(kl)+'</span>'
    +'<span class="dl">Valid From</span><span class="dv">'+esc(fmtDT(cert.not_before))+'</span>'
    +'<span class="dl">Valid Until</span><span class="dv">'+esc(fmtDT(cert.not_after))+'</span>'
    +'<span class="dl">Days Left</span><span class="dv">'+(cert.days_left!=null?cert.days_left+' days':'—')+'</span>'
    +'</div>';
  if(cert.pem){
    html+='<div class="pem-section"><div class="pem-hdr"><span>Public Certificate (PEM)</span>'
      +'<button class="btn btn-ghost" style="font-size:0.72rem;padding:0.2rem 0.6rem" onclick="copyPEM()">Copy</button></div>'
      +'<pre class="pem-pre" id="pem-pre">'+esc(cert.pem)+'</pre></div>';
  }
  document.getElementById('modal-title').textContent=label+' Details';
  document.getElementById('modal-body').innerHTML=html;
  document.getElementById('overlay').classList.add('open');
}
function closeModal(){document.getElementById('overlay').classList.remove('open');}
function overlayClick(e){if(e.target===document.getElementById('overlay'))closeModal();}
function copyPEM(){
  var pre=document.getElementById('pem-pre');
  if(!pre)return;
  var btn=pre.closest('.pem-section').querySelector('button');
  navigator.clipboard.writeText(pre.textContent).then(function(){var orig=btn.textContent;btn.textContent='Copied!';setTimeout(function(){btn.textContent=orig;},2000);}).catch(function(){var r=document.createRange();r.selectNode(pre);window.getSelection().removeAllRanges();window.getSelection().addRange(r);});
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeModal();});
</script>
"""


# ── HTTP request handler ──────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_session_user(self):
        """Return authenticated username from session cookie, or None."""
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == COOKIE_NAME and v.strip():
                return verify_session_token(v.strip(), _SESSION_SECRET)
        return None

    def _session_cookie_header(self, username: str) -> str:
        token = make_session_token(username, _SESSION_SECRET)
        return f"{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_LIFETIME}"

    def _clear_cookie_header(self) -> str:
        return f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"

    def _redirect(self, location: str, status: int = 302) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _serve_html(self, html: str, status: int = 200,
                    extra_headers: list = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self, data, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _parse_form(self) -> dict:
        """Parse application/x-www-form-urlencoded POST body."""
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        return {k: v[0] if v else "" for k, v in parse_qs(body, keep_blank_values=True).items()}

    # ── Request logging ───────────────────────────────────────────────────────

    def log_message(self, format, *args):  # noqa: A002
        _log.info("%s %s", self.address_string(), format % args)

    def log_error(self, format, *args):  # noqa: A002
        _log.error("%s %s", self.address_string(), format % args)

    # ── GET routing ───────────────────────────────────────────────────────────

    def do_GET(self):
        try:
            self._do_GET()
        except Exception:
            _log.error("Unhandled exception in GET %s:\n%s",
                       self.path, traceback.format_exc())
            self._serve_500()

    def _do_GET(self):
        path = urlparse(self.path).path

        # Setup wizard — only available when no users exist
        if path == "/setup":
            if needs_setup():
                return self._serve_html(_setup_page())
            return self._redirect("/login")

        # Login / logout — always accessible
        if path == "/login":
            if self._get_session_user():
                return self._redirect("/")
            from urllib.parse import parse_qs as _pqs
            qs = parse_qs(urlparse(self.path).query)
            msg = qs.get("msg", [""])[0]
            ok_msgs = {"setup_complete": "Admin account created. Please sign in."}
            flash_ok = ok_msgs.get(msg, "")
            if flash_ok:
                html = _base("Sign In", f"""
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo">ClearPass ACME Certificate Manager</div>
  <h1 class="auth-title">Sign In</h1>
  <div class="flash flash-ok">{_esc(flash_ok)}</div>
  <form method="POST" action="/login">
    <div class="field"><label>Username</label>
      <input type="text" name="username" autocomplete="username" autofocus required></div>
    <div class="field"><label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required></div>
    <button type="submit" class="btn-submit">Sign In</button>
  </form>
</div></div>""")
                return self._serve_html(html)
            return self._serve_html(_login_page())

        if path == "/logout":
            self._serve_html(
                _login_page(),
                extra_headers=[("Set-Cookie", self._clear_cookie_header())],
            )
            return

        # ── Dashboard and status API ─────────────────────────────────────────
        # Public by default (REQUIRE_AUTH_FOR_STATUS=false).
        # When auth IS required these behave like the admin routes below.
        is_public_path = (
            path in ("/", "/index.html", "/api/status", "/api/health")
            or path.startswith("/server/")
            or path.startswith("/api/status/")
        )
        if is_public_path:
            username = self._get_session_user()

            if REQUIRE_AUTH_FOR_STATUS:
                if needs_setup():
                    return self._redirect("/setup")
                if not username:
                    if path.startswith("/api/"):
                        return self._serve_json({"error": "Unauthorized"}, status=401)
                    return self._redirect("/login")

            # ── JSON APIs ────────────────────────────────────────────────────
            if path == "/api/status":
                try:
                    return self._serve_json(build_all_status())
                except Exception as e:
                    return self._serve_json({"error": str(e)}, status=500)

            if path.startswith("/api/status/"):
                server_id = path[len("/api/status/"):].strip("/")
                try:
                    srv = get_server(server_id)
                    if srv:
                        return self._serve_json(build_server_status(srv))
                    return self._serve_json({"error": "Not found"}, status=404)
                except Exception as e:
                    return self._serve_json({"error": str(e)}, status=500)

            if path == "/api/health":
                try:
                    return self._serve_json(_build_health())
                except Exception as e:
                    return self._serve_json({"error": str(e)}, status=500)

            # ── Pages ────────────────────────────────────────────────────────
            if path.startswith("/server/"):
                server_id = path[len("/server/"):].strip("/")
                servers   = load_servers()
                valid = (any(s.get("id") == server_id for s in servers)
                         if servers else server_id == "env")
                if not valid:
                    return self._redirect("/")
                return self._serve_html(_server_detail_page(server_id, username or ""))

            # "/" and "/index.html" → overview
            return self._serve_html(_overview_page(username or ""))

        # ── Admin routes — always require authentication ──────────────────────
        if needs_setup():
            return self._redirect("/setup")

        username = self._get_session_user()
        if not username:
            return self._redirect("/login")

        if path == "/admin/users":
            qs     = parse_qs(urlparse(self.path).query)
            ftype  = qs.get("ft", [""])[0]
            fmsg   = qs.get("fm", [""])[0]
            return self._serve_html(
                _users_page(load_users(), username, ftype, fmsg)
            )

        if path == "/settings":
            qs    = parse_qs(urlparse(self.path).query)
            ftype = qs.get("ft", [""])[0]
            fmsg  = qs.get("fm", [""])[0]
            return self._serve_html(
                _settings_list_page(load_servers(), username, ftype, fmsg)
            )

        if path == "/settings/add":
            return self._serve_html(_settings_form_page(username=username))

        if path.startswith("/settings/edit/"):
            server_id = path[len("/settings/edit/"):].strip("/")
            srv = get_server(server_id)
            if srv is None:
                return self._redirect("/settings?ft=err&fm=Server+not+found")
            return self._serve_html(
                _settings_form_page(srv, is_edit=True, username=username)
            )

        if path.startswith("/settings/trust-exclusions/"):
            server_id = path[len("/settings/trust-exclusions/"):].strip("/")
            qs    = parse_qs(urlparse(self.path).query)
            ftype = qs.get("ft", [""])[0]
            fmsg  = qs.get("fm", [""])[0]
            srv = get_server(server_id)
            if srv is None:
                return self._redirect("/settings?ft=err&fm=Server+not+found")
            return self._serve_html(
                _trust_exclusions_page(srv, username, ftype, fmsg)
            )

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _serve_500(self):
        try:
            body = b"500 Internal Server Error"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    # ── POST routing ──────────────────────────────────────────────────────────

    def do_POST(self):
        try:
            self._do_POST()
        except Exception:
            _log.error("Unhandled exception in POST %s:\n%s",
                       self.path, traceback.format_exc())
            self._serve_500()

    def _do_POST(self):
        path = urlparse(self.path).path

        if path == "/setup":
            self._handle_setup()
        elif path == "/login":
            self._handle_login()
        elif path == "/admin/users/add":
            self._handle_users_add()
        elif path == "/admin/users/delete":
            self._handle_users_delete()
        elif path == "/admin/users/passwd":
            self._handle_users_passwd()
        elif path == "/settings/add":
            self._handle_settings_add()
        elif path == "/settings/delete":
            self._handle_settings_delete()
        elif path.startswith("/settings/edit/"):
            self._handle_settings_edit(path[len("/settings/edit/"):].strip("/"))
        elif path.startswith("/settings/trust-exclusions/"):
            self._handle_trust_exclusions_save(path[len("/settings/trust-exclusions/"):].strip("/"))
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    # ── POST handlers ─────────────────────────────────────────────────────────

    def _handle_setup(self):
        if not needs_setup():
            return self._redirect("/login")
        f = self._parse_form()
        username = f.get("username", "").strip()
        password = f.get("password", "")
        confirm  = f.get("confirm", "")
        if not username:
            return self._serve_html(_setup_page("Username is required."))
        if password != confirm:
            return self._serve_html(_setup_page("Passwords do not match."))
        try:
            save_user(username, password)
        except Exception as e:
            _log.error("setup: save_user('%s') failed: %s\n%s",
                       username, e, traceback.format_exc())
            return self._serve_html(_setup_page(f"Could not create user: {e}"))
        _log.info("setup: admin user '%s' created", username)
        self._redirect("/login?msg=setup_complete")

    def _handle_login(self):
        f        = self._parse_form()
        username = f.get("username", "").strip()
        password = f.get("password", "")
        try:
            users = load_users()
        except Exception as e:
            _log.error("login: load_users failed: %s\n%s", e, traceback.format_exc())
            return self._serve_html(_login_page("Server error loading credentials."))
        if username and username in users and verify_password(password, users[username]):
            _log.info("login: '%s' authenticated", username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", self._session_cookie_header(username))
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            _log.warning("login: failed attempt for username '%s'", username)
            self._serve_html(_login_page("Invalid username or password.", username))

    def _handle_users_add(self):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        f    = self._parse_form()
        uname = f.get("username", "").strip()
        pw    = f.get("password", "")
        conf  = f.get("confirm", "")
        if pw != conf:
            return self._redirect("/admin/users?ft=err&fm=Passwords+do+not+match")
        try:
            save_user(uname, pw)
            _log.info("users: '%s' added user '%s'", username, uname)
            self._redirect(f"/admin/users?ft=ok&fm=User+%27{uname}%27+added")
        except Exception as e:
            _log.error("users: add '%s' failed: %s\n%s", uname, e, traceback.format_exc())
            self._redirect(f"/admin/users?ft=err&fm={_url_enc(str(e))}")

    def _handle_users_delete(self):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        f     = self._parse_form()
        uname = f.get("username", "").strip()
        if uname == username:
            return self._redirect("/admin/users?ft=err&fm=Cannot+delete+your+own+account")
        if delete_user(uname):
            self._redirect(f"/admin/users?ft=ok&fm=User+%27{uname}%27+deleted")
        else:
            self._redirect(f"/admin/users?ft=err&fm=User+%27{uname}%27+not+found")

    def _handle_users_passwd(self):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        f     = self._parse_form()
        uname = f.get("username", "").strip()
        pw    = f.get("password", "")
        conf  = f.get("confirm", "")
        if pw != conf:
            return self._redirect("/admin/users?ft=err&fm=Passwords+do+not+match")
        try:
            save_user(uname, pw)
            _log.info("users: '%s' changed password for '%s'", username, uname)
            self._redirect(f"/admin/users?ft=ok&fm=Password+updated+for+%27{uname}%27")
        except Exception as e:
            _log.error("users: passwd '%s' failed: %s\n%s", uname, e, traceback.format_exc())
            self._redirect(f"/admin/users?ft=err&fm={_url_enc(str(e))}")

    def _handle_settings_add(self):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        f     = self._parse_form()
        entry = _parse_server_form(f)
        try:
            add_server(entry)
            _log.info("settings: '%s' added server '%s'", username, entry.get("label"))
            self._redirect("/settings?ft=ok&fm=Server+added")
        except Exception as e:
            _log.error("settings: add failed: %s\n%s", e, traceback.format_exc())
            self._serve_html(
                _settings_form_page(entry, str(e), is_edit=False, username=username)
            )

    def _handle_settings_edit(self, server_id: str):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        f     = self._parse_form()
        entry = _parse_server_form(f)
        try:
            found = update_server(server_id, entry)
            if not found:
                return self._redirect("/settings?ft=err&fm=Server+not+found")
            _log.info("settings: '%s' updated server '%s'", username, entry.get("label"))
            self._redirect("/settings?ft=ok&fm=Server+updated")
        except Exception as e:
            _log.error("settings: edit '%s' failed: %s\n%s",
                       server_id, e, traceback.format_exc())
            entry["id"] = server_id
            self._serve_html(
                _settings_form_page(entry, str(e), is_edit=True, username=username)
            )

    def _handle_settings_delete(self):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        f         = self._parse_form()
        server_id = f.get("id", "").strip()
        if delete_server(server_id):
            _log.info("settings: '%s' deleted server id '%s'", username, server_id)
            self._redirect("/settings?ft=ok&fm=Server+deleted")
        else:
            self._redirect("/settings?ft=err&fm=Server+not+found")

    def _handle_trust_exclusions_save(self, server_id: str):
        username = self._get_session_user()
        if not username:
            return self._redirect("/login")
        srv = get_server(server_id)
        if srv is None:
            return self._redirect("/settings?ft=err&fm=Server+not+found")
        f = self._parse_form()
        patterns = [
            line.strip()
            for line in f.get("trust_exclusions", "").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        srv["trust_exclusions"] = patterns
        try:
            update_server(server_id, srv)
            _log.info("trust-exclusions: '%s' saved %d pattern(s) for server '%s'",
                      username, len(patterns), server_id)
            self._redirect(
                f"/settings/trust-exclusions/{server_id}"
                f"?ft=ok&fm=Trust+exclusions+saved."
            )
        except Exception as exc:
            _log.error("trust-exclusions save failed: %s\n%s", exc, traceback.format_exc())
            self._serve_html(
                _trust_exclusions_page(srv, username, "err", f"Save failed: {exc}")
            )

    # log_message and log_error are defined earlier in the class alongside the
    # other request-logging helpers — do not add a duplicate here.


def _url_enc(s: str) -> str:
    from urllib.parse import quote_plus
    return quote_plus(s)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        _init_session_secret()
    except Exception:
        # Log the error but continue — the server can still start; auth will
        # fail gracefully for individual requests if the secret is unavailable.
        _log.error("Failed to initialise session secret:\n%s", traceback.format_exc())

    _log.info("Starting on 0.0.0.0:%d", STATUS_PORT)

    if not HAS_BCRYPT:
        _log.warning(
            "py3-bcrypt not installed — authentication will not work. "
            "Rebuild the image: docker compose build --no-cache"
        )
    if not HAS_CRYPTOGRAPHY:
        _log.warning(
            "cryptography library not installed — "
            "certificate details will be limited to raw PEM display."
        )

    try:
        server = ThreadingHTTPServer(("0.0.0.0", STATUS_PORT), Handler)
    except OSError as e:
        _log.error(
            "Cannot bind to port %d: %s\n"
            "Another instance may already be running. "
            "Check with: docker exec cppm-acme-cert-manager "
            "ss -tlnp | grep %d",
            STATUS_PORT, e, STATUS_PORT,
        )
        sys.exit(1)

    _log.info("Listening — ready to serve requests")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log.info("Shutting down")
