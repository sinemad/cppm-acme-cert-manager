#!/usr/bin/env python3
"""
clearpass_upload.py – Uploads a Let's Encrypt certificate to Aruba ClearPass.

Uses the official pyclearpass SDK (github.com/aruba/pyclearpass) for all API
operations. See api_platformcertificates.py in that package for the authoritative
source of endpoint paths and body schemas.

Steps:
  0  Trust list pre-flight  – ensure all LE CA certs are trusted (EAP + Others)
  1  HTTPS server cert      – upload PKCS12 to the HTTPS service slot
  2  RADIUS service cert    – upload PKCS12 to the RADIUS service slot
  3  Verify                 – confirm domain appears in installed cert list

SDK notes
─────────
pyclearpass sends every request as Content-Type: application/json (json=body).
The cert_file field in new_cert_trust_list() is the PEM text as a plain string.
cert_usage is a list of strings e.g. ["EAP", "Others"].

Server/service cert upload uses cert_file (PEM string) for the JSON body.
pkcs12_file_url and certificate_url are URL-based alternatives that require
CPPM to fetch a remote file; we avoid those since CPPM cannot reach the container.
"""

import sys
if sys.version_info < (3, 9):
    sys.exit(f"ERROR: Python 3.9+ required (found {sys.version}). Rebuild the image.")

import argparse
import base64
import dataclasses
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

import urllib3
from pyclearpass import ClearPassAPILogin, ApiPlatformCertificates

if not shutil.which("openssl"):
    sys.exit("ERROR: 'openssl' binary not found. Rebuild the image.")

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cppm-upload")

# ─────────────────────────────────────────────────────────────────────────────
# Status log
# ─────────────────────────────────────────────────────────────────────────────
STATUS_LOG = "/data/certs/status.log"


def status_write(level: str, category: str, message: str) -> None:
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = (ts + " | " + level.ljust(6) + " | "
                + category.ljust(7) + " | " + message + "\n")
        with open(STATUS_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Bundled LE CA certs
# ─────────────────────────────────────────────────────────────────────────────
LE_CERT_DIR = Path(os.environ.get("LE_CERT_DIR", "/opt/cppm/le-certs"))

LE_BUNDLED_CERTS: dict[str, str] = {
    "isrg-root-x1.pem":     "ISRG Root X1 (RSA root)",
    "isrg-root-x2.pem":     "ISRG Root X2 (ECDSA root)",
    "lets-encrypt-r10.pem": "Let's Encrypt R10 (RSA intermediate)",
    "lets-encrypt-r11.pem": "Let's Encrypt R11 (RSA intermediate)",
    "lets-encrypt-e5.pem":  "Let's Encrypt E5 (ECDSA intermediate)",
    "lets-encrypt-e6.pem":  "Let's Encrypt E6 (ECDSA intermediate)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Certificate helpers
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class CertInfo:
    label:       str
    pem:         str          # raw PEM block (no trailing newline)
    subject:     str
    issuer:      str
    not_after:   str
    fingerprint: str          # SHA-256, uppercase, colon-separated


def _run_openssl(args: list[str], input_data: Optional[bytes] = None) -> str:
    try:
        result = subprocess.run(
            ["openssl"] + args, input=input_data,
            capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"openssl {args[0]} timed out after 30s")
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl {args[0]} failed (exit {result.returncode}):\n"
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout.decode("utf-8", errors="replace")


def parse_pem_bundle(pem_text: str, label_prefix: str = "") -> list[CertInfo]:
    """Split a PEM bundle into individual CertInfo objects."""
    pattern = re.compile(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", re.DOTALL
    )
    certs: list[CertInfo] = []
    for idx, block in enumerate(pattern.findall(pem_text)):
        pem_bytes = (block.strip() + "\n").encode("utf-8")
        try:
            subject = (
                _run_openssl(["x509", "-noout", "-subject", "-nameopt", "compat"],
                             input_data=pem_bytes)
                .strip().removeprefix("subject=").strip()
            )
            issuer = (
                _run_openssl(["x509", "-noout", "-issuer", "-nameopt", "compat"],
                             input_data=pem_bytes)
                .strip().removeprefix("issuer=").strip()
            )
            dates_raw = _run_openssl(["x509", "-noout", "-dates"], input_data=pem_bytes)
            not_after = ""
            for line in dates_raw.splitlines():
                if line.startswith("notAfter="):
                    not_after = line.split("=", 1)[1].strip()
            fp_raw = _run_openssl(
                ["x509", "-noout", "-fingerprint", "-sha256"], input_data=pem_bytes
            ).strip()
            fingerprint = fp_raw.split("=", 1)[-1].strip().upper()
            label = f"{label_prefix} [{idx+1}]" if label_prefix else f"cert[{idx}]"
            certs.append(CertInfo(
                label=label, pem=block.strip(),
                subject=subject, issuer=issuer,
                not_after=not_after, fingerprint=fingerprint,
            ))
        except Exception as exc:
            log.warning("Could not parse PEM block %d from '%s': %s",
                        idx, label_prefix, exc)
    return certs


def _normalise_fp(fp: str) -> str:
    fp = re.sub(r"^(SHA\d+:|MD5:)", "", fp, flags=re.IGNORECASE)
    fp = re.sub(r"[:\s-]", "", fp)
    return fp.upper()


def load_bundled_le_certs() -> dict[str, CertInfo]:
    """Load the LE CA certs baked into the image. Returns dict keyed by normalised SHA-256."""
    required: dict[str, CertInfo] = {}
    if not LE_CERT_DIR.is_dir():
        log.error("Bundled LE cert dir not found: %s – rebuild the image.", LE_CERT_DIR)
        return required
    for filename, label in LE_BUNDLED_CERTS.items():
        pem_path = LE_CERT_DIR / filename
        if not pem_path.is_file():
            log.warning("Bundled cert missing: %s", pem_path)
            continue
        try:
            pem_text = pem_path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("Cannot read %s: %s", pem_path, exc)
            continue
        certs = parse_pem_bundle(pem_text, label_prefix=label)
        if not certs:
            continue
        cert = certs[0]
        cert.label = label
        fp_norm = _normalise_fp(cert.fingerprint)
        if fp_norm not in required:
            required[fp_norm] = cert
            log.debug("Loaded: %s | expires: %s", label, cert.not_after)
    log.info("Loaded %d bundled LE CA certs from %s", len(required), LE_CERT_DIR)
    return required


# ─────────────────────────────────────────────────────────────────────────────
# PKCS12 conversion
# ─────────────────────────────────────────────────────────────────────────────

def pem_to_pkcs12(cert_path: str, key_path: str, fullchain_path: str,
                  passphrase: str, out_path: str) -> None:
    """
    Convert PEM cert + key -> PKCS12 (.pfx).
    No -certpbe/-keypbe/-macalg flags: OpenSSL 3.x defaults to PBES2/AES-256-CBC
    with SHA-256 MAC, which Java 11+ (ClearPass 6.9+) accepts.
    """
    log.info("Converting PEM -> PKCS12: %s", out_path)
    try:
        result = subprocess.run(
            ["openssl", "pkcs12", "-export",
             "-in",      fullchain_path,
             "-inkey",   key_path,
             "-out",     out_path,
             "-passout", f"pass:{passphrase}",
             "-name",    "cppm-server-cert"],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("openssl pkcs12 timed out after 30s")
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl pkcs12 failed (exit {result.returncode}):\n{result.stderr}"
        )
    log.info("PKCS12 conversion OK.")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers for pyclearpass API responses
# ─────────────────────────────────────────────────────────────────────────────

def _items_from_response(data: Any) -> list[dict]:
    """Extract the items list from a pyclearpass response (handles various shapes)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return (data.get("_embedded", {}).get("items", [])
                or data.get("items", []))
    return []


def _check_response(data: Any, operation: str) -> None:
    """Raise RuntimeError if the response looks like an error."""
    if isinstance(data, dict):
        status = data.get("status", 200)
        if isinstance(status, int) and status >= 400:
            raise RuntimeError(
                f"CPPM API error during '{operation}' "
                f"(HTTP {status}): {data.get('detail', data)}"
            )
        # pyclearpass sometimes returns the raw error text as a string
        if "Unauthorized" in str(data) or "Forbidden" in str(data):
            raise RuntimeError(
                f"CPPM API auth/permission error during '{operation}': {data}"
            )
    elif isinstance(data, str) and ("Error" in data or "error" in data):
        raise RuntimeError(f"CPPM API returned error string during '{operation}': {data}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 0 – Trust List Pre-flight
# ─────────────────────────────────────────────────────────────────────────────

def ensure_letsencrypt_chain_trusted(
    api: ApiPlatformCertificates, ca_cert_path: str
) -> dict:
    """
    Ensure every LE CA cert is in the CPPM trust list with EAP + Others enabled.

    Uses pyclearpass.ApiPlatformCertificates:
      get_cert_trust_list()                               – list entries
      new_cert_trust_list(body={...})                    – add new entry
      update_cert_trust_list_by_cert_trust_list_id(...)  – patch existing entry

    Trust list body schema (from api_platformcertificates.py):
      cert_file  (str)  – PEM text of the CA certificate
      enabled    (bool) – whether the entry is active
      cert_usage (list) – list of usage strings: "EAP", "RADIUS", "HTTPS", "Others"
    """
    log.info("=" * 62)
    log.info("Step 0: Let's Encrypt Trust List Pre-flight")
    log.info("  SDK: ApiPlatformCertificates.get/new/update_cert_trust_list")
    log.info("=" * 62)

    summary: dict[str, list[str]] = {
        "already_trusted": [], "flags_updated": [],
        "uploaded": [], "failed": [],
    }

    # Build required cert set: bundled image certs + acme.sh chain extras
    required = load_bundled_le_certs()

    if Path(ca_cert_path).is_file():
        log.info("Parsing acme.sh CA chain: %s", ca_cert_path)
        try:
            chain_text = Path(ca_cert_path).read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("Cannot read CA chain %s: %s", ca_cert_path, exc)
            chain_text = ""
        for c in parse_pem_bundle(chain_text, "chain"):
            fp = _normalise_fp(c.fingerprint)
            if fp not in required:
                cn = (c.subject.split("CN=")[-1].split(",")[0].strip()
                      if "CN=" in c.subject else c.subject[:40])
                c.label = f"LE chain: {cn}"
                required[fp] = c
                log.info("  Extra chain cert (not in bundle): %s", c.label)
    else:
        log.warning("CA chain file not found: %s (using bundled certs only)", ca_cert_path)

    if not required:
        log.error("No LE certs available – rebuild the image.")
        return summary

    log.info("Total unique LE certs to verify: %d", len(required))

    # Fetch current trust list
    try:
        raw = api.get_cert_trust_list(limit="1000")
        _check_response(raw, "get_cert_trust_list")
        trust_list = _items_from_response(raw)
        log.info("Trust list: %d entries", len(trust_list))
    except Exception as exc:
        log.error("Cannot fetch trust list: %s – skipping pre-flight.", exc)
        status_write("WARN", "TRUST", f"Trust list fetch failed: {exc}")
        return summary

    # Build fingerprint lookup from the cert_file PEM in each trust list entry.
    # CPPM does not return a fingerprint field — only id, cert_file, enabled,
    # cert_usage, and _links.  We compute SHA-256 from the PEM ourselves.
    trust_fp_map: dict[str, dict] = {}
    for entry in trust_list:
        pem = entry.get("cert_file", "")
        if not pem or "BEGIN CERTIFICATE" not in pem:
            continue
        try:
            fp_raw = _run_openssl(
                ["x509", "-noout", "-fingerprint", "-sha256"],
                input_data=pem.encode(),
            ).strip()
            fp_norm = _normalise_fp(fp_raw.split("=", 1)[-1].strip())
            trust_fp_map[fp_norm] = entry
        except Exception as exc:
            log.debug("Could not fingerprint trust list entry id=%s: %s",
                      entry.get("id"), exc)

    log.debug("Built fingerprint map from %d/%d trust list entries",
              len(trust_fp_map), len(trust_list))

    def _find_entry(fp: str) -> Optional[dict]:
        return trust_fp_map.get(_normalise_fp(fp))

    for fp_norm, cert in required.items():
        log.info("-" * 50)
        log.info("Checking: %s", cert.label)
        log.info("  Subject: %s", cert.subject)
        log.info("  SHA-256: %s", cert.fingerprint)

        existing = _find_entry(cert.fingerprint)

        if existing is not None:
            entry_id = existing.get("id")
            usage_raw = existing.get("cert_usage", [])
            if isinstance(usage_raw, list):
                usage_strs = [str(u) for u in usage_raw]
                eap_ok    = "EAP"    in usage_strs
                others_ok = "Others" in usage_strs
            else:
                usage_int = int(usage_raw) if usage_raw else 0
                eap_ok    = bool(usage_int & 2)
                others_ok = bool(usage_int & 16)
            enabled = bool(existing.get("enabled", False))

            if enabled and eap_ok and others_ok:
                log.info("  [OK] Already trusted (id=%s, EAP=true, Others=true)", entry_id)
                summary["already_trusted"].append(cert.label)
            else:
                log.info(
                    "  [PATCH] Present (id=%s) flags incomplete "
                    "(enabled=%s EAP=%s Others=%s) – patching...",
                    entry_id, enabled, eap_ok, others_ok,
                )
                try:
                    if entry_id is not None:
                        # Retry with backoff — CPPM may briefly drop connections
                        # after a service reload triggered by a cert upload.
                        import time as _time
                        last_exc: Optional[Exception] = None
                        for attempt in range(1, 4):
                            try:
                                resp = api.update_cert_trust_list_by_cert_trust_list_id(
                                    cert_trust_list_id=str(entry_id),
                                    body={
                                        "enabled":    True,
                                        "cert_usage": ["EAP", "Others"],
                                    },
                                )
                                _check_response(resp, f"patch trust entry {entry_id}")
                                log.info("  Patched successfully.")
                                summary["flags_updated"].append(cert.label)
                                last_exc = None
                                break
                            except Exception as exc:
                                last_exc = exc
                                if attempt < 3:
                                    wait = attempt * 5
                                    log.warning(
                                        "  PATCH attempt %d failed: %s – retrying in %ds...",
                                        attempt, exc, wait,
                                    )
                                    _time.sleep(wait)
                        if last_exc is not None:
                            raise last_exc
                    else:
                        log.warning("  No id field – update manually in CPPM UI.")
                        summary["flags_updated"].append(f"{cert.label} (manual)")
                except Exception as exc:
                    log.error("  PATCH failed: %s", exc)
                    summary["failed"].append(cert.label)
        else:
            log.info("  [UPLOAD] Not in trust list – uploading...")
            try:
                resp = api.new_cert_trust_list(body={
                    "cert_file":  cert.pem.strip() + "\n",
                    "enabled":    True,
                    "cert_usage": ["EAP", "Others"],
                })
                if isinstance(resp, dict):
                    status = resp.get("status", 0)
                    detail = resp.get("detail", "")
                    if status == 422 and "already exists" in str(detail).lower():
                        # Fingerprint map missed this entry — cert is present but
                        # its PEM in the trust list may differ slightly (line endings
                        # etc).  Treat as already trusted and note for manual check.
                        log.warning(
                            "  422 'already exists' but fingerprint lookup missed it. "
                            "Verify EAP+Others flags manually in CPPM Admin UI: "
                            "Administration > Certificates > Trust List"
                        )
                        summary["already_trusted"].append(cert.label)
                        continue
                _check_response(resp, f"new_cert_trust_list for {cert.label}")
                uploaded_id = resp.get("id", "?") if isinstance(resp, dict) else "?"
                log.info("  Uploaded (id=%s)", uploaded_id)
                summary["uploaded"].append(cert.label)
            except Exception as exc:
                log.error("  Upload failed: %s", exc)
                summary["failed"].append(cert.label)

    # Summary
    log.info("=" * 62)
    log.info("Trust Pre-flight Summary")
    log.info("  Already trusted : %d", len(summary["already_trusted"]))
    log.info("  Flags patched   : %d", len(summary["flags_updated"]))
    log.info("  Uploaded new    : %d", len(summary["uploaded"]))
    if summary["failed"]:
        log.error("  FAILED          : %d – %s",
                  len(summary["failed"]), summary["failed"])
        log.error("  Manual: Administration > Certificates > Trust List > Import")
        log.error("  Enable EAP and Others for each imported cert.")
    log.info("=" * 62)

    total      = len(required)
    fail_count = len(summary["failed"])
    if fail_count == 0:
        status_write("OK", "TRUST",
                     f"{total} LE CA certs verified – "
                     f"{len(summary['uploaded'])} uploaded, "
                     f"{len(summary['flags_updated'])} patched, "
                     f"{len(summary['already_trusted'])} already trusted")
    else:
        status_write("WARN", "TRUST",
                     f"{fail_count}/{total} LE CA cert(s) failed – check upload.log")
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 – HTTPS Server Certificate
# ─────────────────────────────────────────────────────────────────────────────

def _get_server_uuid(api: ApiPlatformCertificates) -> str:
    """
    Return the publisher server UUID using the special 'publisher' keyword.

    Uses ApiLocalServerConfiguration.get_cluster_server_by_uuid(uuid="publisher")
    → GET /api/cluster/server/publisher

    This avoids GET /api/server which returns Guest portal HTML on some CPPM
    configurations, and avoids needing a real UUID upfront.
    """
    from pyclearpass.api_localserverconfiguration import ApiLocalServerConfiguration
    local_api = ApiLocalServerConfiguration(
        server=api.server,
        api_token=api.api_token,
        verify_ssl=api.verify_ssl,
        timeout=api.timeout,
    )
    log.info("Fetching publisher server UUID via GET /api/cluster/server/publisher...")
    resp = local_api.get_cluster_server_by_uuid(uuid="publisher")
    if isinstance(resp, dict):
        uuid = resp.get("server_uuid") or resp.get("uuid") or resp.get("id")
        if uuid:
            log.info("  Publisher UUID: %s", uuid)
            return str(uuid)
    raise RuntimeError(
        f"Cannot extract server_uuid from GET /api/cluster/server/publisher: {resp}"
    )


def _get_server_cert_items(api: ApiPlatformCertificates) -> list[dict]:
    """
    Return the list of server cert entries from GET /api/server-cert.
    Each item contains service_id and service_name.
    Note: server_uuid is NOT included in these items — use _get_server_uuid().
    """
    raw = api.get_server_cert()
    _check_response(raw, "get_server_cert")
    items = _items_from_response(raw)
    if not items:
        raise RuntimeError(
            "GET /api/server-cert returned no items – "
            "check API client has Certificate Management permission."
        )
    log.debug("  server-cert entries: %d", len(items))
    for item in items:
        log.debug("    service_id=%s service_name=%s",
                  item.get("service_id"), item.get("service_name"))
    return items


def _serve_pkcs12_and_upload(
    token: str,
    host: str,
    verify_ssl: bool,
    server_uuid: str,
    service_name: str,
    pfx_path: str,
    passphrase: str,
    callback_host: str,
    callback_port: int,
) -> None:
    """
    Serve the PKCS12 file on a fixed port and send CPPM its URL via JSON PUT.

    Endpoint:  PUT /api/server-cert/name/{server_uuid}/{service_name}
    Body:      {"pkcs12_file_url": "http://<callback_host>:<port>/<file>",
                "pkcs12_passphrase": "<passphrase>"}

    This endpoint is JSON-only (confirmed in Swagger UI).  CPPM fetches the
    PKCS12 via the URL — so callback_host MUST be reachable from CPPM.

    Set CPPM_CALLBACK_HOST in .env to the Docker host's IP address (the one
    CPPM can route to).  Use the fixed port exposed in docker-compose.yml via:
      ports:
        - "<CPPM_CALLBACK_PORT>:<CPPM_CALLBACK_PORT>"
    """
    import http.server, socketserver, threading
    import requests as _req

    pfx_name = Path(pfx_path).name
    pfx_url  = f"http://{callback_host}:{callback_port}/{pfx_name}"

    class _SilentHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    # Bind on 0.0.0.0 so Docker port mapping reaches us
    httpd  = socketserver.TCPServer(("0.0.0.0", callback_port), _SilentHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    orig_dir = os.getcwd()
    os.chdir("/tmp")
    thread.start()
    log.info("  Serving PKCS12 at %s (CPPM will fetch this)", pfx_url)

    url     = f"https://{host}/api/server-cert/name/{server_uuid}/{service_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    body = {
        "pkcs12_file_url":  pfx_url,
        "pkcs12_passphrase": passphrase,
    }

    try:
        resp = _req.put(url, headers=headers, json=body,
                        verify=verify_ssl, timeout=60)
        log.debug("  PUT %s → HTTP %d  body=%s",
                  url.split("/api/")[1], resp.status_code, resp.text[:300])
        if resp.status_code not in (200, 201, 204):
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text[:400]
            raise RuntimeError(
                f"CPPM rejected cert upload (HTTP {resp.status_code}) "
                f"for {service_name}: {detail}"
            )
    finally:
        httpd.shutdown()
        os.chdir(orig_dir)


def upload_https_certificate(
    api: ApiPlatformCertificates,
    token: str,
    host: str,
    cert_path: str,
    key_path: str,
    fullchain_path: str,
    passphrase: str,
    callback_host: str,
    callback_port: int,
) -> dict:
    """
    Upload the HTTPS server certificate.

    The PUT /api/server-cert/name/{uuid}/{service_name} endpoint is JSON-only
    (confirmed via CPPM Swagger UI).  CPPM must fetch the PKCS12 via a URL.

    callback_host must be an IP address that CPPM can route to.
    Set CPPM_CALLBACK_HOST in .env to the Docker host's LAN IP.
    callback_port must be exposed in docker-compose.yml ports mapping.
    """
    log.info("Uploading HTTPS server certificate...")

    server_uuid = _get_server_uuid(api)
    items       = _get_server_cert_items(api)

    # Prefer HTTPS(ECC) over HTTPS(RSA), then any HTTPS variant
    service_name: Optional[str] = None
    for preferred in ("HTTPS(ECC)", "HTTPS(RSA)"):
        for item in items:
            if str(item.get("service_name", "")).upper() == preferred.upper():
                service_name = str(item.get("service_name", ""))
                break
        if service_name:
            break
    if not service_name:
        for item in items:
            if str(item.get("service_name", "")).upper().startswith("HTTPS"):
                service_name = str(item.get("service_name", ""))
                break
    if not service_name:
        raise RuntimeError(
            "Could not find an HTTPS entry in GET /api/server-cert. "
            f"Entries: {[i.get('service_name') for i in items]}"
        )

    log.info("  server_uuid=%s  service_name=%s", server_uuid, service_name)
    log.info("  callback_url=http://%s:%d", callback_host, callback_port)

    with tempfile.NamedTemporaryFile(
        suffix=".pfx", prefix="cppm_https_", dir="/tmp", delete=False
    ) as tmp:
        pfx_path = tmp.name

    try:
        pem_to_pkcs12(cert_path, key_path, fullchain_path, passphrase, pfx_path)
        _serve_pkcs12_and_upload(
            token, host, api.verify_ssl,
            server_uuid, service_name, pfx_path, passphrase,
            callback_host, callback_port,
        )
        log.info("  HTTPS certificate uploaded successfully.")
        return {}
    finally:
        Path(pfx_path).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 – RADIUS / EAP Service Certificate
# ─────────────────────────────────────────────────────────────────────────────

def upload_radius_certificate(
    api: ApiPlatformCertificates,
    token: str,
    host: str,
    cert_path: str,
    key_path: str,
    fullchain_path: str,
    passphrase: str,
    callback_host: str,
    callback_port: int,
) -> dict:
    """
    Upload the RADIUS/EAP service certificate.

    Same URL-fetch mechanism as upload_https_certificate.
    Skipped cleanly if CPPM uses a unified HTTPS/RADIUS certificate.
    """
    log.info("Uploading RADIUS/EAP service certificate...")

    server_uuid = _get_server_uuid(api)
    items       = _get_server_cert_items(api)

    service_name: Optional[str] = None
    for item in items:
        svc = str(item.get("service_name", ""))
        if "RADIUS" in svc.upper() or "EAP" in svc.upper():
            service_name = svc
            log.info("  Found RADIUS entry: service_name=%s", service_name)
            break

    if not service_name:
        log.warning(
            "  No RADIUS entry found in server-cert list. "
            "CPPM uses a unified HTTPS/RADIUS certificate – "
            "the HTTPS upload already covers RADIUS."
        )
        return {"status": "skipped", "reason": "unified_cert_mode"}

    log.info("  server_uuid=%s  service_name=%s", server_uuid, service_name)
    log.info("  callback_url=http://%s:%d", callback_host, callback_port)

    with tempfile.NamedTemporaryFile(
        suffix=".pfx", prefix="cppm_radius_", dir="/tmp", delete=False
    ) as tmp:
        pfx_path = tmp.name

    try:
        pem_to_pkcs12(cert_path, key_path, fullchain_path, passphrase, pfx_path)
        _serve_pkcs12_and_upload(
            token, host, api.verify_ssl,
            server_uuid, service_name, pfx_path, passphrase,
            callback_host, callback_port,
        )
        log.info("  RADIUS certificate uploaded successfully.")
        return {}
    finally:
        Path(pfx_path).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 – Verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_cert_installed(api: ApiPlatformCertificates, domain: str) -> bool:
    """
    Check the installed HTTPS server cert references the domain.
    Uses ApiPlatformCertificates.get_server_cert() → GET /api/server-cert.
    """
    try:
        raw = api.get_server_cert()
        return domain.lower() in json.dumps(raw).lower()
    except Exception as exc:
        log.debug("Verification non-fatal: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Upload acme.sh certificate to Aruba ClearPass (pyclearpass SDK)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SDK: pyclearpass  (github.com/aruba/pyclearpass)
Module: api_platformcertificates.ApiPlatformCertificates

Certificate strategy:
  ECC (ec-256) → HTTPS(ECC) slot  (service_id=2)
  RSA (2048)   → RADIUS slot      (service_id=1)

Methods used:
  get_cert_trust_list()                             GET   /api/cert-trust-list
  new_cert_trust_list()                             POST  /api/cert-trust-list
  update_cert_trust_list_by_cert_trust_list_id()   PATCH /api/cert-trust-list/{id}
  get_server_cert()                                 GET   /api/server-cert
  replace_server_cert_name_by_server_uuid_...()    PUT   /api/server-cert/name/{uuid}/{svc}

Note: PATCH /api/server-cert/{id} is NOT used — CPPM returns 405 for PATCH.
""",
    )
    # ECC cert → HTTPS(ECC) slot
    p.add_argument("--https-cert",      required=True,  help="ECC domain cert (.ecc.cer)")
    p.add_argument("--https-key",       required=True,  help="ECC private key (.ecc.key)")
    p.add_argument("--https-fullchain", required=True,  help="ECC fullchain (.ecc.fullchain.cer)")
    p.add_argument("--https-ca",        default=None,   help="ECC CA chain (.ecc.ca.cer)")
    # RSA cert → RADIUS slot
    p.add_argument("--radius-cert",      required=True,  help="RSA domain cert (.rsa.cer)")
    p.add_argument("--radius-key",       required=True,  help="RSA private key (.rsa.key)")
    p.add_argument("--radius-fullchain", required=True,  help="RSA fullchain (.rsa.fullchain.cer)")
    p.add_argument("--radius-ca",        default=None,   help="RSA CA chain (.rsa.ca.cer)")

    p.add_argument("--domain",           default=os.environ.get("DOMAIN", "cppm.sinemalab.com"))
    p.add_argument("--skip-trust-check", action="store_true")
    p.add_argument("--skip-radius",      action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    host          = os.environ.get("CPPM_HOST",            "cppm.sinemalab.com")
    client_id     = os.environ.get("CPPM_CLIENT_ID",       "")
    client_secret = os.environ.get("CPPM_CLIENT_SECRET",   "")
    verify_ssl    = os.environ.get("CPPM_VERIFY_SSL",      "false").lower() == "true"
    passphrase    = os.environ.get("CPPM_CERT_PASSPHRASE", "CppmCert!2024")
    # CPPM_CALLBACK_HOST: Docker host LAN IP that CPPM can route to.
    # CPPM needs to fetch the PKCS12 via HTTP during cert upload (JSON-only API).
    # Set to the IP of the machine running Docker, e.g. 10.1.14.50
    callback_host = os.environ.get("CPPM_CALLBACK_HOST", "")
    callback_port = int(os.environ.get("CPPM_CALLBACK_PORT", "8765"))

    if not client_id or not client_secret:
        log.error("CPPM_CLIENT_ID and CPPM_CLIENT_SECRET must be set.")
        return 1

    if not callback_host:
        log.error(
            "CPPM_CALLBACK_HOST is not set.\n"
            "Set it to the Docker host's LAN IP that CPPM can route to, e.g.:\n"
            "  CPPM_CALLBACK_HOST=10.1.14.50\n"
            "Also ensure docker-compose.yml exposes the port:\n"
            "  ports:\n"
            "    - \"%d:%d\"", callback_port, callback_port
        )
        return 1

    for label, path in [
        ("https-cert",      args.https_cert),
        ("https-key",       args.https_key),
        ("https-fullchain", args.https_fullchain),
        ("radius-cert",     args.radius_cert),
        ("radius-key",      args.radius_key),
        ("radius-fullchain",args.radius_fullchain),
    ]:
        if not Path(path).is_file():
            log.error("File not found (%s): %s", label, path)
            return 1

    # CA chain for trust list pre-flight – prefer ECC chain, fall back to RSA
    https_ca  = args.https_ca  or str(Path(args.https_cert).parent  / f"{args.domain}.ecc.ca.cer")
    radius_ca = args.radius_ca or str(Path(args.radius_cert).parent / f"{args.domain}.rsa.ca.cer")
    ca_path = https_ca if Path(https_ca).is_file() else radius_ca

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("SSL verification DISABLED – set CPPM_VERIFY_SSL=true "
                    "once the certificate is installed.")

    # ── OAuth2 token fetch ────────────────────────────────────────────────────
    # We perform the OAuth2 client_credentials exchange ourselves rather than
    # letting pyclearpass do it. The pyclearpass SDK always includes empty
    # "username" and "password" fields in its token request, which causes CPPM
    # to return 400 invalid_client because those fields violate the strict
    # client_credentials grant schema.
    #
    # Once we have the token we pass it to the SDK as api_token=, which causes
    # pyclearpass to skip its OAuth call entirely and use our token as a Bearer
    # header directly. This preserves client_credentials semantics (correct for
    # extension-style integrations) while avoiding the SDK's broken request body.
    log.info("Authenticating with ClearPass: https://%s/api", host)
    import requests as _requests
    _sess = _requests.Session()
    _sess.verify = verify_ssl
    _resp = _sess.post(
        f"https://{host}/api/oauth",
        json={
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        },
        timeout=30,
    )
    if not _resp.ok:
        try:
            _body = _resp.json()
        except Exception:
            _body = _resp.text[:300]
        log.error(
            "Authentication failed (HTTP %d): %s\n"
            "Check CPPM_CLIENT_ID and CPPM_CLIENT_SECRET in .env.",
            _resp.status_code, _body,
        )
        return 1
    _token = _resp.json().get("access_token", "")
    if not _token:
        log.error("Authentication succeeded but no access_token in response: %s",
                  _resp.json())
        return 1
    log.info("Authenticated. expires_in=%ss",
             _resp.json().get("expires_in", "?"))

    # ── Initialise pyclearpass SDK with the pre-fetched token ────────────────
    sdk_args = dict(
        server=f"https://{host}/api",
        api_token=_token,
        verify_ssl=verify_ssl,
        timeout=60,
    )
    api = ApiPlatformCertificates(**sdk_args)

    hard_errors: list[str] = []
    soft_errors:  list[str] = []

    # Step 0
    if not args.skip_trust_check:
        log.info("== Step 0: Trust List Pre-flight ============================")
        try:
            summary = ensure_letsencrypt_chain_trusted(api, ca_path)
            if summary["failed"]:
                soft_errors.append(
                    f"Trust list incomplete – missing: {summary['failed']}"
                )
        except Exception as exc:
            log.error("Trust pre-flight exception: %s", exc)
            soft_errors.append(f"Trust pre-flight: {exc}")
    else:
        log.info("== Step 0: SKIPPED ==========================================")

    # Step 1 — ECC cert → HTTPS(ECC) slot
    log.info("== Step 1: HTTPS(ECC) Server Certificate =======================")
    try:
        result = upload_https_certificate(
            api, _token, host,
            args.https_cert, args.https_key, args.https_fullchain,
            passphrase, callback_host, callback_port
        )
        log.info("HTTPS upload response: %s", json.dumps(result, indent=2)
                 if isinstance(result, dict) else result)
        try:
            expiry = _run_openssl(
                ["x509", "-noout", "-enddate", "-in", args.https_cert]
            ).strip().split("=", 1)[-1]
        except Exception:
            expiry = ""
        status_write("OK", "UPLOAD",
                     f"HTTPS(ECC) cert uploaded to {host}"
                     + (f" – expires {expiry}" if expiry else ""))
    except Exception as exc:
        log.error("HTTPS upload FAILED: %s", exc)
        hard_errors.append(f"HTTPS: {exc}")

    # Step 2 — RSA cert → RADIUS slot
    if not args.skip_radius:
        log.info("== Step 2: RADIUS (RSA) Service Certificate =================")
        try:
            result = upload_radius_certificate(
                api, _token, host,
                args.radius_cert, args.radius_key, args.radius_fullchain,
                passphrase, callback_host, callback_port
            )
            log.info("RADIUS upload response: %s", json.dumps(result, indent=2)
                     if isinstance(result, dict) else result)
            if isinstance(result, dict) and result.get("status") != "skipped":
                status_write("OK", "UPLOAD", f"RADIUS(RSA) cert uploaded to {host}")
        except Exception as exc:
            log.error("RADIUS upload FAILED: %s", exc)
            hard_errors.append(f"RADIUS: {exc}")
    else:
        log.info("== Step 2: SKIPPED ==========================================")

    # Step 3 — Verification
    log.info("== Step 3: Verification =========================================")
    try:
        if verify_cert_installed(api, args.domain):
            log.info("[OK] Domain '%s' found in installed cert.", args.domain)
        else:
            log.warning(
                "[?] Domain '%s' not confirmed in server-cert API response "
                "(may be false-negative). Verify at: "
                "https://%s/tips/tips_server_cert.php",
                args.domain, host,
            )
    except Exception as exc:
        log.warning("Verification non-fatal: %s", exc)

    if hard_errors:
        log.error("Completed WITH ERRORS: %s", hard_errors)
        status_write("FAILED", "UPLOAD",
                     "Upload failed: " + "; ".join(hard_errors))
        return 1

    if soft_errors:
        log.warning("Completed with warnings: %s", soft_errors)
        log.warning(
            "EAP may fail until missing trust certs are added manually: "
            "Administration > Certificates > Trust List > Import"
        )
    else:
        log.info("All steps completed successfully.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
