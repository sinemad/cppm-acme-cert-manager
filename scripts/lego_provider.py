"""ACME provider backed by the Lego client (https://github.com/go-acme/lego)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from acme_provider import AcmeError, AcmeProvider, IssueResult, KeyTypeResult

_LEGO_BIN = "/usr/local/bin/lego"

_ACME_SERVER_MAP: dict[str, str] = {
    "letsencrypt":      "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl":          "https://acme.zerossl.com/v2/DV90",
    "buypass":          "https://api.buypass.com/acme/directory",
    "buypass_test":     "https://api.test4.buypass.no/acme/directory",
}

# servers.json stores provider names using acme.sh conventions; map to Lego names.
_DNS_PLUGIN_MAP: dict[str, str] = {
    "cloudflare":   "cloudflare",
    "cf":           "cloudflare",
    "porkbun":      "porkbun",
    "route53":      "route53",
    "aws":          "route53",
    "r53":          "route53",
    "digitalocean": "digitalocean",
    "do":           "digitalocean",
    "godaddy":      "godaddy",
    "gd":           "godaddy",
}

# Credential env var names as stored in servers.json (acme.sh convention) → Lego names.
_DNS_ENV_REMAP: dict[str, str] = {
    "CF_Token":           "CF_DNS_API_TOKEN",
    "CF_Key":             "CF_API_KEY",
    "CF_Email":           "CF_API_EMAIL",
    "DO_API_KEY":         "DO_AUTH_TOKEN",
    "GD_Key":             "GODADDY_API_KEY",
    "GD_Secret":          "GODADDY_API_SECRET",
    "AWS_DEFAULT_REGION": "AWS_REGION",
}

# Env vars that acme.sh uses but Lego cloudflare plugin does not need.
_DNS_ENV_DROP: frozenset[str] = frozenset({"CF_Zone_ID", "CF_Account_ID"})

_KEY_TYPE_MAP: dict[str, str] = {"ecc": "ec256", "rsa": "rsa2048"}

# Lego uses a separate --path directory per key type so state never collides.
_LEGO_SUBDIR: dict[str, str] = {"ecc": "lego-ecc", "rsa": "lego-rsa"}


class LegoProvider(AcmeProvider):
    """ACME provider using the Lego client."""

    # ── helpers ───────────────────────────────────────────────────────────────

    def _server_url(self, server: str) -> str:
        if server.startswith("http"):
            return server
        return _ACME_SERVER_MAP.get(server, _ACME_SERVER_MAP["letsencrypt"])

    def _dns_plugin(self, provider: str) -> str:
        return _DNS_PLUGIN_MAP.get(provider.lower(), provider.lower())

    def _map_dns_env(self, dns_env: dict[str, str]) -> dict[str, str]:
        """Translate acme.sh-style env var names to Lego names, dropping unused keys."""
        result: dict[str, str] = {}
        for k, v in dns_env.items():
            if k in _DNS_ENV_DROP or k == "ACME_EMAIL":
                continue
            result[_DNS_ENV_REMAP.get(k, k)] = v
        return result

    def _lego_path(self, cert_dir: str, kt: str) -> str:
        return os.path.join(cert_dir, _LEGO_SUBDIR[kt])

    def _cert_file(self, cert_dir: str, domain: str, kt: str) -> str:
        return os.path.join(self._lego_path(cert_dir, kt), "certificates", f"{domain}.crt")

    def _run(
        self,
        args: list[str],
        extra_env: dict[str, str] | None = None,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[bytes]:
        env = {**os.environ, **(extra_env or {})}
        # Unset DEBUG — a non-numeric value from the host causes Alpine ash
        # integer-range errors in child processes.
        env.pop("DEBUG", None)
        try:
            return subprocess.run([_LEGO_BIN, *args], env=env, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise AcmeError(
                f"lego timed out after {timeout}s ({args[0] if args else '?'})"
            ) from exc

    # ── AcmeProvider interface ─────────────────────────────────────────────────

    def register_account(self, email: str, server: str) -> None:
        """No-op — Lego registers the account implicitly on the first ``run``."""

    def issue_cert(
        self,
        *,
        domain: str,
        acme_server: str,
        cert_dir: str,
        key_types: list[str],
        dns_provider: str,
        dns_env: dict[str, str],
        log_file: str,
        force: bool = False,
    ) -> IssueResult:
        server_url = self._server_url(acme_server)
        plugin = self._dns_plugin(dns_provider)
        lego_env = self._map_dns_env(dns_env)
        email = dns_env.get("ACME_EMAIL") or os.environ.get("ACME_EMAIL", "")
        results: list[KeyTypeResult] = []

        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                raise AcmeError(f"Unknown key type: {kt!r}")

            lego_path = self._lego_path(cert_dir, kt)
            os.makedirs(os.path.join(lego_path, "certificates"), exist_ok=True)

            if force:
                # Remove existing cert state so `lego run` issues a fresh cert
                # regardless of whether the existing one is still valid.
                certs_dir = os.path.join(lego_path, "certificates")
                if os.path.isdir(certs_dir):
                    for fname in os.listdir(certs_dir):
                        if fname.startswith(domain + "."):
                            try:
                                os.unlink(os.path.join(certs_dir, fname))
                            except OSError:
                                pass

            args = [
                "--email",    email,
                "--domains",  domain,
                "--dns",      plugin,
                "--path",     lego_path,
                "--server",   server_url,
                "--key-type", _KEY_TYPE_MAP[kt],
                "run",
            ]
            rc = self._run(args, extra_env=lego_env).returncode
            if rc != 0:
                raise AcmeError(
                    f"lego run ({kt.upper()}) failed (exit {rc}) – check {log_file}"
                )
            results.append(KeyTypeResult(key_type=kt, issued=True))

        return IssueResult(results=results)

    def renew_cert(
        self,
        *,
        domain: str,
        acme_server: str,
        cert_dir: str,
        key_types: list[str],
        dns_provider: str,
        dns_env: dict[str, str],
        log_file: str,
    ) -> IssueResult:
        server_url = self._server_url(acme_server)
        plugin = self._dns_plugin(dns_provider)
        lego_env = self._map_dns_env(dns_env)
        email = dns_env.get("ACME_EMAIL") or os.environ.get("ACME_EMAIL", "")
        results: list[KeyTypeResult] = []
        failures: list[str] = []

        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                failures.append(f"unknown key type {kt!r}")
                continue

            lego_path = self._lego_path(cert_dir, kt)
            cert_file = self._cert_file(cert_dir, domain, kt)
            # lego renew exits 0 whether or not it actually renewed; compare
            # mtime before/after to detect a real renewal.
            before = os.path.getmtime(cert_file) if os.path.exists(cert_file) else 0.0

            args = [
                "--email",    email,
                "--domains",  domain,
                "--dns",      plugin,
                "--path",     lego_path,
                "--server",   server_url,
                "--key-type", _KEY_TYPE_MAP[kt],
                "renew",
                "--days", "30",
            ]
            rc = self._run(args, extra_env=lego_env).returncode
            if rc != 0:
                # Collect failures but continue so the other key type is attempted.
                failures.append(f"{kt.upper()} exit {rc}")
                continue

            after = os.path.getmtime(cert_file) if os.path.exists(cert_file) else 0.0
            results.append(KeyTypeResult(key_type=kt, issued=after > before))

        if failures:
            raise AcmeError(f"lego renew failed for {domain}: {'; '.join(failures)}")
        return IssueResult(results=results)

    def install_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                raise AcmeError(f"Unknown key type: {kt!r}")

            lego_path = self._lego_path(cert_dir, kt)
            base = os.path.join(lego_path, "certificates", domain)
            crt_file = f"{base}.crt"
            key_file_src = f"{base}.key"
            issuer_file = f"{base}.issuer.crt"

            if not os.path.exists(crt_file):
                raise AcmeError(
                    f"Lego {kt.upper()} cert not found at {crt_file} – run issue_cert first"
                )

            # Full chain (leaf + intermediates) → .fullchain.cer
            shutil.copy2(crt_file, os.path.join(cert_dir, f"{domain}.{kt}.fullchain.cer"))

            # Leaf cert only (first PEM block) → .cer
            chain_text = Path(crt_file).read_text()
            m = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                chain_text,
                re.DOTALL,
            )
            if not m:
                raise AcmeError(f"Could not extract leaf certificate from {crt_file}")
            Path(os.path.join(cert_dir, f"{domain}.{kt}.cer")).write_text(
                m.group(0) + "\n"
            )

            # Private key → .key (chmod 600)
            dst_key = os.path.join(cert_dir, f"{domain}.{kt}.key")
            shutil.copy2(key_file_src, dst_key)
            os.chmod(dst_key, 0o600)

            # CA / issuer chain → .ca.cer
            dst_ca = os.path.join(cert_dir, f"{domain}.{kt}.ca.cer")
            if os.path.exists(issuer_file):
                shutil.copy2(issuer_file, dst_ca)
            else:
                # Fallback: strip the leaf from the full chain to get the CA chain.
                end_marker = "-----END CERTIFICATE-----"
                idx = chain_text.index(end_marker) + len(end_marker)
                ca_chain = chain_text[idx:].lstrip()
                if ca_chain:
                    Path(dst_ca).write_text(ca_chain)
                else:
                    raise AcmeError(
                        f"issuer.crt missing and no CA chain found in {crt_file}"
                    )

        # Verify all expected flat files were written.
        missing: list[str] = []
        for kt in key_types:
            for suffix in (f"{kt}.cer", f"{kt}.key", f"{kt}.fullchain.cer", f"{kt}.ca.cer"):
                p = os.path.join(cert_dir, f"{domain}.{suffix}")
                if not os.path.exists(p):
                    missing.append(os.path.basename(p))
        if missing:
            raise AcmeError(
                f"{len(missing)} expected file(s) missing after install: "
                + ", ".join(missing)
            )

    def revoke_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        email = os.environ.get("ACME_EMAIL", "")
        server_url = self._server_url(os.environ.get("ACME_SERVER", "letsencrypt"))
        failures: list[str] = []

        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                failures.append(f"unknown key type {kt!r}")
                continue
            cert_file = self._cert_file(cert_dir, domain, kt)
            if not os.path.exists(cert_file):
                failures.append(f"{kt.upper()} cert not found at {cert_file}")
                continue
            args = [
                "--email",  email,
                "--path",   self._lego_path(cert_dir, kt),
                "--server", server_url,
                "revoke",
                "--cert", cert_file,
            ]
            rc = self._run(args).returncode
            if rc != 0:
                failures.append(f"{kt.upper()} exit {rc}")

        if failures:
            raise AcmeError(f"lego revoke failed for {domain}: {'; '.join(failures)}")
