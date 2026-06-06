#!/usr/bin/env python3
"""CLI entry-point for ACME operations, called by issue_cert.sh / renew.sh / install_cert.sh.

Environment variables (exported by entrypoint.sh via get_server_shell_env):
    DOMAIN              FQDN to issue/renew
    SERVER_CERT_DIR     Per-server certificate directory
    SERVER_LOG_DIR      Per-server log directory (optional)
    ACME_EMAIL          ACME account email
    DNS_PROVIDER        DNS provider name (cloudflare, porkbun, route53, …)
    ACME_SERVER         ACME CA name or URL (default: letsencrypt)
    ISSUE_ECC           Issue ECC cert (default: true)
    ISSUE_RSA           Issue RSA cert (default: true)
    <DNS credential vars>  Provider-specific credential keys

Exit codes:
    0  Action taken (cert issued, renewed, installed, or revoked)
    2  No action needed (cert not due for renewal)
    1  Error
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from acme_provider import AcmeError, get_provider  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# All credential keys that may be set in the environment. Passed through to
# the provider's dns_env so it can pick what it needs and remap as required.
_DNS_CRED_KEYS = {
    "ACME_EMAIL",
    "CF_Token", "CF_Key", "CF_Email", "CF_Zone_ID", "CF_Account_ID",
    "PORKBUN_API_KEY", "PORKBUN_SECRET_API_KEY",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION",
    "DO_API_KEY",
    "GD_Key", "GD_Secret",
}


def _require(name: str) -> str:
    val = os.environ.get(name, "")
    if not val:
        log.error("Required environment variable not set: %s", name)
        sys.exit(1)
    return val


def _key_types() -> list[str]:
    types: list[str] = []
    if os.environ.get("ISSUE_ECC", "true").lower() == "true":
        types.append("ecc")
    if os.environ.get("ISSUE_RSA", "true").lower() == "true":
        types.append("rsa")
    if not types:
        log.error("Both ISSUE_ECC and ISSUE_RSA are false – nothing to do")
        sys.exit(1)
    return types


def _dns_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _DNS_CRED_KEYS if k in os.environ}


def _log_file(cert_dir: str) -> str:
    log_dir = os.environ.get("SERVER_LOG_DIR", os.path.join(cert_dir, ".logs"))
    return os.path.join(log_dir, "acme_renewal.log")


def cmd_issue(args: argparse.Namespace) -> None:
    domain = _require("DOMAIN")
    cert_dir = _require("SERVER_CERT_DIR")
    _require("ACME_EMAIL")
    acme_server = os.environ.get("ACME_SERVER", "letsencrypt")
    dns_provider = _require("DNS_PROVIDER")
    key_types = _key_types()

    provider = get_provider("lego")
    try:
        result = provider.issue_cert(
            domain=domain,
            acme_server=acme_server,
            cert_dir=cert_dir,
            key_types=key_types,
            dns_provider=dns_provider,
            dns_env=_dns_env(),
            log_file=_log_file(cert_dir),
            force=args.force,
        )
        types_str = "+".join(r.key_type.upper() for r in result.results)
        log.info("Issued %s cert(s) for %s", types_str, domain)
    except AcmeError as exc:
        log.error("Issue failed: %s", exc)
        sys.exit(1)


def cmd_renew(_args: argparse.Namespace) -> None:
    domain = _require("DOMAIN")
    cert_dir = _require("SERVER_CERT_DIR")
    _require("ACME_EMAIL")
    acme_server = os.environ.get("ACME_SERVER", "letsencrypt")
    dns_provider = _require("DNS_PROVIDER")
    key_types = _key_types()

    provider = get_provider("lego")
    try:
        result = provider.renew_cert(
            domain=domain,
            acme_server=acme_server,
            cert_dir=cert_dir,
            key_types=key_types,
            dns_provider=dns_provider,
            dns_env=_dns_env(),
            log_file=_log_file(cert_dir),
        )
        if result.newly_issued:
            log.info("Certificate(s) renewed for %s", domain)
            sys.exit(0)
        else:
            log.info("Certificate not due for renewal for %s", domain)
            sys.exit(2)
    except AcmeError as exc:
        log.error("Renew failed: %s", exc)
        sys.exit(1)


def cmd_install(_args: argparse.Namespace) -> None:
    domain = _require("DOMAIN")
    cert_dir = _require("SERVER_CERT_DIR")
    key_types = _key_types()

    provider = get_provider("lego")
    try:
        provider.install_cert(
            domain=domain,
            cert_dir=cert_dir,
            key_types=key_types,
            log_file=_log_file(cert_dir),
        )
        log.info("Cert files installed for %s", domain)
    except AcmeError as exc:
        log.error("Install failed: %s", exc)
        sys.exit(1)


def cmd_revoke(_args: argparse.Namespace) -> None:
    domain = _require("DOMAIN")
    cert_dir = _require("SERVER_CERT_DIR")
    key_types = _key_types()

    provider = get_provider("lego")
    try:
        provider.revoke_cert(
            domain=domain,
            cert_dir=cert_dir,
            key_types=key_types,
            log_file=_log_file(cert_dir),
        )
        log.info("Certificate(s) revoked for %s", domain)
    except AcmeError as exc:
        log.error("Revoke failed: %s", exc)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="ACME certificate CLI (Lego)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_issue = sub.add_parser("issue", help="Issue new certificates")
    p_issue.add_argument(
        "--force", action="store_true",
        help="Force re-issue even if existing cert is still valid",
    )
    p_issue.set_defaults(func=cmd_issue)

    p_renew = sub.add_parser("renew", help="Renew certificates if due (exit 2 = not due)")
    p_renew.set_defaults(func=cmd_renew)

    p_install = sub.add_parser("install", help="Copy Lego cert state to flat file paths")
    p_install.set_defaults(func=cmd_install)

    p_revoke = sub.add_parser("revoke", help="Revoke issued certificates")
    p_revoke.set_defaults(func=cmd_revoke)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
