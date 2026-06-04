"""ACME provider backed by acme.sh."""
from __future__ import annotations

import os
import subprocess

from acme_provider import AcmeError, AcmeProvider, IssueResult, KeyTypeResult

_ACME_BIN = "/usr/local/bin/acme.sh"
_ACME_HOME = "/root/.acme.sh"

# Maps the DNS provider names used in servers.json to acme.sh dnsapi plugin names.
# Unknown values fall through to dns_{provider} passthrough (same behaviour as
# the dns_${DNS_PROVIDER,,} passthrough in issue_cert.sh).
_DNS_PLUGIN_MAP: dict[str, str] = {
    "cloudflare": "dns_cf",
    "cf":         "dns_cf",
    "porkbun":    "dns_porkbun",
    "route53":    "dns_aws",
    "aws":        "dns_aws",
    "r53":        "dns_aws",
    "digitalocean": "dns_dgon",
    "do":           "dns_dgon",
    "godaddy": "dns_gd",
    "gd":      "dns_gd",
}


class AcmeShProvider(AcmeProvider):
    """ACME provider that delegates to the acme.sh CLI."""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _plugin(self, dns_provider: str) -> str:
        return _DNS_PLUGIN_MAP.get(dns_provider.lower(), f"dns_{dns_provider.lower()}")

    def _run(
        self,
        args: list[str],
        env: dict[str, str] | None = None,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[bytes]:
        merged_env = {**os.environ, **(env or {})}
        # acme.sh treats DEBUG as a numeric variable; a non-numeric value
        # (e.g. DEBUG=true from the host) causes Alpine ash integer-range
        # errors on every invocation — same fix as `unset DEBUG` in all
        # shell scripts.
        merged_env.pop("DEBUG", None)
        try:
            return subprocess.run(
                [_ACME_BIN, *args],
                env=merged_env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise AcmeError(
                f"acme.sh timed out after {timeout}s ({args[0] if args else '?'})"
            ) from exc

    # ------------------------------------------------------------------
    # AcmeProvider interface
    # ------------------------------------------------------------------

    def register_account(self, email: str, server: str) -> None:
        """Register or verify an ACME account with the given CA.

        Mirrors entrypoint.sh's ``|| true``: any non-zero exit is tolerated.
        Registration is idempotent and failures here are typically transient
        (network, CA hiccup); the caller should still attempt issuance.
        """
        self._run([
            "--register-account",
            "-m", email,
            "--server", server,
        ])

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
        plugin = self._plugin(dns_provider)
        base_args = [
            "--issue",
            "--dns",       plugin,
            "--domain",    domain,
            "--server",    acme_server,
            "--cert-home", cert_dir,
            "--home",      _ACME_HOME,
            "--log",       log_file,
            "--log-level", "2",
        ]
        if force:
            base_args.append("--force")

        results: list[KeyTypeResult] = []

        if "ecc" in key_types:
            rc = self._run(base_args + ["--keylength", "ec-256"], env=dns_env).returncode
            if rc == 0:
                results.append(KeyTypeResult(key_type="ecc", issued=True))
            elif rc == 2:
                # acme.sh exit 2 means cert exists and is not due for renewal
                results.append(KeyTypeResult(key_type="ecc", issued=False))
            else:
                raise AcmeError(
                    f"acme.sh --issue (ECC) failed (exit {rc}) – check {log_file}"
                )

        if "rsa" in key_types:
            rc = self._run(base_args + ["--keylength", "2048"], env=dns_env).returncode
            if rc == 0:
                results.append(KeyTypeResult(key_type="rsa", issued=True))
            elif rc == 2:
                results.append(KeyTypeResult(key_type="rsa", issued=False))
            else:
                raise AcmeError(
                    f"acme.sh --issue (RSA) failed (exit {rc}) – check {log_file}"
                )

        return IssueResult(results=results)

    def renew_cert(
        self,
        *,
        domain: str,
        acme_server: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> IssueResult:
        base_args = [
            "--renew",
            "--domain",    domain,
            "--server",    acme_server,
            "--cert-home", cert_dir,
            "--home",      _ACME_HOME,
            "--log",       log_file,
            "--log-level", "2",
        ]

        results: list[KeyTypeResult] = []
        failures: list[str] = []

        if "ecc" in key_types:
            rc = self._run(base_args + ["--ecc"]).returncode
            if rc == 0:
                results.append(KeyTypeResult(key_type="ecc", issued=True))
            elif rc == 2:
                results.append(KeyTypeResult(key_type="ecc", issued=False))
            else:
                # Record failure but continue so RSA is always attempted —
                # mirrors renew.sh's RENEW_FAILED tracking (not a hard abort).
                failures.append(f"ECC exit {rc}")

        if "rsa" in key_types:
            # RSA renew: no --ecc flag
            rc = self._run(base_args).returncode
            if rc == 0:
                results.append(KeyTypeResult(key_type="rsa", issued=True))
            elif rc == 2:
                results.append(KeyTypeResult(key_type="rsa", issued=False))
            else:
                failures.append(f"RSA exit {rc}")

        if failures:
            raise AcmeError(
                f"acme.sh --renew failed for {domain}: {'; '.join(failures)}"
            )
        return IssueResult(results=results)

    def install_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        if "ecc" in key_types:
            state_cert = os.path.join(cert_dir, f"{domain}_ecc", f"{domain}.cer")
            if not os.path.exists(state_cert):
                raise AcmeError(
                    f"ECC acme.sh state not found at {state_cert} – run issue_cert first"
                )
            rc = self._run([
                "--install-cert",
                "--domain",        domain,
                "--ecc",
                "--home",          _ACME_HOME,
                "--cert-home",     cert_dir,
                "--cert-file",      os.path.join(cert_dir, f"{domain}.ecc.cer"),
                "--key-file",       os.path.join(cert_dir, f"{domain}.ecc.key"),
                "--fullchain-file", os.path.join(cert_dir, f"{domain}.ecc.fullchain.cer"),
                "--ca-file",        os.path.join(cert_dir, f"{domain}.ecc.ca.cer"),
                "--log",           log_file,
            ]).returncode
            if rc != 0:
                raise AcmeError(f"acme.sh --install-cert (ECC) failed (exit {rc})")
            os.chmod(os.path.join(cert_dir, f"{domain}.ecc.key"), 0o600)

        if "rsa" in key_types:
            state_cert = os.path.join(cert_dir, domain, f"{domain}.cer")
            if not os.path.exists(state_cert):
                raise AcmeError(
                    f"RSA acme.sh state not found at {state_cert} – run issue_cert first"
                )
            rc = self._run([
                "--install-cert",
                "--domain",        domain,
                "--home",          _ACME_HOME,
                "--cert-home",     cert_dir,
                "--cert-file",      os.path.join(cert_dir, f"{domain}.rsa.cer"),
                "--key-file",       os.path.join(cert_dir, f"{domain}.rsa.key"),
                "--fullchain-file", os.path.join(cert_dir, f"{domain}.rsa.fullchain.cer"),
                "--ca-file",        os.path.join(cert_dir, f"{domain}.rsa.ca.cer"),
                "--log",           log_file,
            ]).returncode
            if rc != 0:
                raise AcmeError(f"acme.sh --install-cert (RSA) failed (exit {rc})")
            os.chmod(os.path.join(cert_dir, f"{domain}.rsa.key"), 0o600)

        # Verify all expected flat files were written — mirrors install_cert.sh
        # lines 91-104 which die on any missing file even when exit code was 0.
        missing: list[str] = []
        if "ecc" in key_types:
            for suffix in ("ecc.cer", "ecc.key", "ecc.fullchain.cer", "ecc.ca.cer"):
                p = os.path.join(cert_dir, f"{domain}.{suffix}")
                if not os.path.exists(p):
                    missing.append(os.path.basename(p))
        if "rsa" in key_types:
            for suffix in ("rsa.cer", "rsa.key", "rsa.fullchain.cer", "rsa.ca.cer"):
                p = os.path.join(cert_dir, f"{domain}.{suffix}")
                if not os.path.exists(p):
                    missing.append(os.path.basename(p))
        if missing:
            raise AcmeError(
                f"{len(missing)} expected file(s) missing after --install-cert: "
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
        base_args = [
            "--revoke",
            "--domain",    domain,
            "--home",      _ACME_HOME,
            "--cert-home", cert_dir,
            "--log",       log_file,
        ]
        failures: list[str] = []

        if "ecc" in key_types:
            rc = self._run(base_args + ["--ecc"]).returncode
            if rc != 0:
                failures.append(f"ECC exit {rc}")

        if "rsa" in key_types:
            rc = self._run(base_args).returncode
            if rc != 0:
                failures.append(f"RSA exit {rc}")

        if failures:
            raise AcmeError(
                f"acme.sh --revoke failed for {domain}: {'; '.join(failures)}"
            )
