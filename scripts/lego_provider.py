"""ACME provider backed by the Lego client (https://github.com/go-acme/lego)."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

from acme_provider import AcmeError, AcmeProvider, IssueResult, KeyTypeResult, cert_file_stem

log = logging.getLogger(__name__)

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
    "infoblox":     "infoblox",
    # Lego v5 renamed the rfc2136 provider to dnsupdate.
    "rfc2136":      "dnsupdate",
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
    # Infoblox — stored under acme.sh-style names; Lego uses the same names natively.
    # RFC 2136 — Lego v5's dnsupdate provider uses DNSUPDATE_* env var names.
    "RFC2136_NAMESERVER":     "DNSUPDATE_NAMESERVER",
    "RFC2136_TSIG_KEY":       "DNSUPDATE_TSIG_KEY",
    "RFC2136_TSIG_SECRET":    "DNSUPDATE_TSIG_SECRET",
    "RFC2136_TSIG_ALGORITHM": "DNSUPDATE_TSIG_ALGORITHM",
    "RFC2136_DNS_TIMEOUT":    "DNSUPDATE_DNS_TIMEOUT",
}

# Env vars that acme.sh uses but Lego cloudflare plugin does not need, plus our
# own settings that become Lego flags rather than env vars.
_DNS_ENV_DROP: frozenset[str] = frozenset({"CF_Zone_ID", "CF_Account_ID", "ACME_DNS_RESOLVERS"})

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
        return os.path.join(
            self._lego_path(cert_dir, kt), "certificates", f"{cert_file_stem(domain)}.crt"
        )

    def _eab_args(self, eab_kid: str, eab_hmac_key: str) -> list[str]:
        if not eab_kid and not eab_hmac_key:
            return []
        if not eab_kid or not eab_hmac_key:
            raise AcmeError("Both EAB_KID and EAB_HMAC_KEY are required for External Account Binding")
        return ["--eab", "--eab.kid", eab_kid, "--eab.hmac", eab_hmac_key]

    def _resolver_args(self, dns_env: dict[str, str]) -> list[str]:
        """Return ``--dns.resolvers`` flags for split-horizon DNS, or [] to let
        Lego use the container's resolvers."""
        resolvers = [r for r in dns_env.get("ACME_DNS_RESOLVERS", "").split(",") if r]
        return sum((["--dns.resolvers", r] for r in resolvers), [])

    def _log_dns_resolvers(self, domain: str, resolver_args: list[str]) -> None:
        """Log which resolvers Lego will use, and warn if the container's DNS
        looks split-horizon while the setting is off. Informational only."""
        resolvers = resolver_args[1::2]
        if resolvers:
            log.info("dns: split-horizon enabled -- Lego DNS-01 checks use %s", ", ".join(resolvers))
        else:
            log.info("dns: Lego DNS-01 checks use the container's resolvers")
        try:
            from dns_utils import split_horizon_check  # noqa: PLC0415
            problem = split_horizon_check(domain, bool(resolvers), resolvers)
        except Exception:
            return
        if problem:
            log.warning("dns: %s", problem["message"])

    def _log_cloudflare_token_scope(self, dns_env: dict[str, str]) -> None:
        """Best-effort, informational: log whether the configured Cloudflare
        CF_Token verifies as account-owned or profile (user) scoped.

        Purely for troubleshooting -- both token types authenticate the DNS-01
        record creation below identically, so this has no effect on what gets
        passed to lego. Runs its own quick verify check each call rather than
        sharing status_server.py's cache, since this is a separate, short-lived
        process invoked per renewal, not the long-running web process.
        """
        token = dns_env.get("CF_Token", "")
        if not token:
            return
        account_id = dns_env.get("CF_Account_ID", "")

        def _verify(url: str) -> bool:
            try:
                import requests
                r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                return r.status_code == 200 and r.json().get("success", False)
            except Exception:
                return False

        # Account-scoped first when an Account ID is on file -- the recommended
        # setup -- falling back to profile-scoped, mirroring status_server.py's
        # health check.
        for scope in (["account", "profile"] if account_id else ["profile"]):
            url = (f"https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify"
                   if scope == "account" else
                   "https://api.cloudflare.com/client/v4/user/tokens/verify")
            if _verify(url):
                log.info("cloudflare: configured API token is %s-scoped", scope)
                return
        log.warning(
            "cloudflare: could not confirm token scope (%s) -- token may still be "
            "valid; this only affects troubleshooting visibility, not issuance",
            "rejected by both profile and account checks" if account_id
            else "rejected by profile check, no Account ID set to also try account-scoped",
        )

    def _run(
        self,
        args: list[str],
        extra_env: dict[str, str] | None = None,
        timeout: int = 600,
        confirm_input: bytes | None = None,
        cwd: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        env = {**os.environ, **(extra_env or {})}
        # Unset DEBUG — a non-numeric value from the host causes Alpine ash
        # integer-range errors in child processes.
        env.pop("DEBUG", None)
        # --log.format must precede the subcommand (it's a global flag); text
        # keeps issue_cert.sh's rate-limit grep working (default is colored).
        full_args = ["--log.format", "text", *args]
        log.debug("lego %s", " ".join(full_args))
        try:
            return subprocess.run(
                [_LEGO_BIN, *full_args], env=env, timeout=timeout,
                input=confirm_input, cwd=cwd,
            )
        except FileNotFoundError as exc:
            raise AcmeError(f"lego binary not found at {_LEGO_BIN}") from exc
        except subprocess.TimeoutExpired as exc:
            raise AcmeError(
                f"lego timed out after {timeout}s ({args[0] if args else '?'})"
            ) from exc

    def _has_legacy_account(self, lego_path: str) -> bool:
        """True if lego_path holds a pre-v5 account dir (accounts/<server>/
        <email>/keys/<email>.key). v5 never creates a keys/ subdirectory, so
        its presence unambiguously marks un-migrated v4 storage."""
        accounts_dir = os.path.join(lego_path, "accounts")
        if not os.path.isdir(accounts_dir):
            return False
        for root, _dirs, files in os.walk(accounts_dir):
            if os.path.basename(root) == "keys" and any(f.endswith(".key") for f in files):
                return True
        return False

    def _backup_before_migration(self, lego_path: str) -> str:
        """Archive lego_path's accounts/ and certificates/ state before lego
        rewrites it in place, so a botched migration can be rolled back by
        hand. Stored alongside (not inside) lego_path."""
        backups_dir = os.path.join(os.path.dirname(lego_path), "migration-backups")
        os.makedirs(backups_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = os.path.basename(lego_path)
        archive_path = os.path.join(backups_dir, f"{name}-pre-v5-migrate-{stamp}.tar.gz")
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(lego_path, arcname=name)
        return archive_path

    def _restore_backup(self, lego_path: str, backup_path: str) -> None:
        """Replace lego_path's contents with the pre-migration snapshot in
        backup_path. The partially-migrated directory is renamed aside
        (not deleted) so it's available for forensics; if extraction itself
        fails, that renamed copy is moved back so lego_path is never left
        empty."""
        parent = os.path.dirname(lego_path)
        failed_aside = f"{lego_path}.failed-migration-{int(time.time())}"
        os.rename(lego_path, failed_aside)
        try:
            with tarfile.open(backup_path, "r:gz") as tar:
                tar.extractall(path=parent, filter="data")
        except Exception:
            if os.path.isdir(lego_path):
                shutil.rmtree(lego_path)
            os.rename(failed_aside, lego_path)
            raise
        log.info(
            "lego: pre-migration state restored to %s; the partially-migrated "
            "directory was kept at %s for inspection", lego_path, failed_aside,
        )

    def _migrate_legacy_storage(self, lego_path: str) -> None:
        """One-time conversion of pre-v5 Lego account storage.

        Lego v5 flattened the account key layout (accounts/<server>/<email>/
        keys/<email>.key -> accounts/<server>/<email>/<email>.key). Without
        this, v5 can't read a v4 account directory and silently registers a
        brand new ACME account instead of reusing the existing one.

        Only runs when a legacy account dir is actually detected, so this
        costs nothing on every other issue/renew/revoke call once a server
        is fully on v5. Backs up lego_path first; if the backup itself
        fails, skips the migration for this run rather than migrating
        without a safety net (lego will just register a new account instead,
        which is non-destructive and can be retried later).
        """
        if not self._has_legacy_account(lego_path):
            return

        try:
            backup_path = self._backup_before_migration(lego_path)
        except OSError as exc:
            log.error(
                "lego: could not back up %s before migration (%s) -- skipping "
                "migration this run; lego will register a new ACME account "
                "instead of migrating the existing one", lego_path, exc,
            )
            return

        log.info(
            "lego: migrating legacy (pre-v5) account storage at %s (backup: %s)",
            lego_path, backup_path,
        )
        account_only = not os.path.isdir(os.path.join(lego_path, "certificates"))
        args = ["migrate", "--path", lego_path]
        if account_only:
            args.append("--account-only")
        rc = self._run(args, confirm_input=b"y\n", cwd=lego_path).returncode
        if rc != 0:
            log.error(
                "lego migrate exited %d for %s -- rolling back to the pre-migration "
                "backup at %s", rc, lego_path, backup_path,
            )
            try:
                self._restore_backup(lego_path, backup_path)
            except Exception as restore_exc:
                log.error(
                    "lego: automatic rollback of %s FAILED (%s) -- manual recovery "
                    "needed from backup at %s", lego_path, restore_exc, backup_path,
                )
        else:
            log.info("lego: migration of %s completed successfully", lego_path)

    # ── AcmeProvider interface ─────────────────────────────────────────────────

    def register_account(self, email: str, server: str) -> None:
        """No-op — Lego registers the account implicitly on the first ``run``."""

    def issue_cert(
        self,
        *,
        domain: str,
        san_domains: list[str] | None = None,
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
        eab_args = self._eab_args(
            dns_env.get("EAB_KID", ""), dns_env.get("EAB_HMAC_KEY", "")
        )
        san_domains = san_domains or []
        results: list[KeyTypeResult] = []

        log.info(
            "issue_cert: domain=%s ca=%s plugin=%s types=%s force=%s",
            domain, server_url, plugin, "+".join(k.upper() for k in key_types), force,
        )
        log.debug("issue_cert: mapped dns env keys: %s", sorted(lego_env.keys()))
        if plugin == "cloudflare":
            self._log_cloudflare_token_scope(dns_env)
        resolver_args = self._resolver_args(dns_env)
        self._log_dns_resolvers(domain, resolver_args)

        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                raise AcmeError(f"Unknown key type: {kt!r}")

            lego_path = self._lego_path(cert_dir, kt)
            self._migrate_legacy_storage(lego_path)
            os.makedirs(os.path.join(lego_path, "certificates"), exist_ok=True)

            if force:
                # Remove existing cert state so `lego run` issues a fresh cert
                # regardless of whether the existing one is still valid.
                certs_dir = os.path.join(lego_path, "certificates")
                if os.path.isdir(certs_dir):
                    for fname in os.listdir(certs_dir):
                        if fname.startswith(cert_file_stem(domain) + "."):
                            try:
                                os.unlink(os.path.join(certs_dir, fname))
                            except OSError:
                                pass

            args = [
                "run",
                "--accept-tos",
                "--enable-cn",
                "--email",     email,
                "--domains",   domain,
                *sum((["--domains", san] for san in san_domains), []),
                "--dns",       plugin,
                *resolver_args,
                "--path",      lego_path,
                "--server",    server_url,
                "--key-type",  _KEY_TYPE_MAP[kt],
                "--cert.name", cert_file_stem(domain),
                *eab_args,
                "--always-deactivate-authorizations", "true",
            ]
            rc = self._run(args, extra_env=lego_env).returncode
            if rc != 0:
                log.error("lego run (%s) failed (exit %d) for %s", kt.upper(), rc, domain)
                raise AcmeError(
                    f"lego run ({kt.upper()}) failed (exit {rc}) – check {log_file}"
                )
            log.info("lego run (%s) succeeded for %s", kt.upper(), domain)
            results.append(KeyTypeResult(key_type=kt, issued=True))

        return IssueResult(results=results)

    def renew_cert(
        self,
        *,
        domain: str,
        san_domains: list[str] | None = None,
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
        eab_args = self._eab_args(
            dns_env.get("EAB_KID", ""), dns_env.get("EAB_HMAC_KEY", "")
        )
        san_domains = san_domains or []
        results: list[KeyTypeResult] = []
        failures: list[str] = []

        log.info(
            "renew_cert: domain=%s ca=%s plugin=%s types=%s",
            domain, server_url, plugin, "+".join(k.upper() for k in key_types),
        )
        if plugin == "cloudflare":
            self._log_cloudflare_token_scope(dns_env)
        resolver_args = self._resolver_args(dns_env)
        self._log_dns_resolvers(domain, resolver_args)

        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                failures.append(f"unknown key type {kt!r}")
                continue

            lego_path = self._lego_path(cert_dir, kt)
            self._migrate_legacy_storage(lego_path)
            cert_file = self._cert_file(cert_dir, domain, kt)
            # lego renew exits 0 whether or not it actually renewed; compare
            # mtime before/after to detect a real renewal.
            before = os.path.getmtime(cert_file) if os.path.exists(cert_file) else 0.0

            args = [
                "run",
                "--accept-tos",
                "--enable-cn",
                "--email",     email,
                "--domains",   domain,
                *sum((["--domains", san] for san in san_domains), []),
                "--dns",       plugin,
                *resolver_args,
                "--path",      lego_path,
                "--server",    server_url,
                "--key-type",  _KEY_TYPE_MAP[kt],
                "--cert.name", cert_file_stem(domain),
                *eab_args,
                "--renew-days", "30",
            ]
            rc = self._run(args, extra_env=lego_env).returncode
            if rc != 0:
                log.error("lego renew (%s) failed (exit %d) for %s", kt.upper(), rc, domain)
                # Collect failures but continue so the other key type is attempted.
                failures.append(f"{kt.upper()} exit {rc}")
                continue

            after = os.path.getmtime(cert_file) if os.path.exists(cert_file) else 0.0
            renewed = after > before
            log.info(
                "lego renew (%s) for %s: %s (mtime before=%.0f after=%.0f)",
                kt.upper(), domain, "renewed" if renewed else "not due", before, after,
            )
            results.append(KeyTypeResult(key_type=kt, issued=renewed))

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
        log.info("install_cert: domain=%s types=%s", domain, "+".join(k.upper() for k in key_types))
        stem = cert_file_stem(domain)
        for kt in key_types:
            if kt not in _KEY_TYPE_MAP:
                raise AcmeError(f"Unknown key type: {kt!r}")

            lego_path = self._lego_path(cert_dir, kt)
            base = os.path.join(lego_path, "certificates", stem)
            crt_file = f"{base}.crt"
            key_file_src = f"{base}.key"
            issuer_file = f"{base}.issuer.crt"

            if not os.path.exists(crt_file):
                raise AcmeError(
                    f"Lego {kt.upper()} cert not found at {crt_file} – run issue_cert first"
                )
            if not os.path.exists(key_file_src):
                raise AcmeError(
                    f"Lego {kt.upper()} key not found at {key_file_src} – run issue_cert first"
                )

            # Full chain (leaf + intermediates) → .fullchain.cer
            shutil.copy2(crt_file, os.path.join(cert_dir, f"{stem}.{kt}.fullchain.cer"))

            # Leaf cert only (first PEM block) → .cer
            chain_text = Path(crt_file).read_text()
            m = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                chain_text,
                re.DOTALL,
            )
            if not m:
                raise AcmeError(f"Could not extract leaf certificate from {crt_file}")
            Path(os.path.join(cert_dir, f"{stem}.{kt}.cer")).write_text(
                m.group(0) + "\n"
            )

            # Private key → .key (chmod 600)
            dst_key = os.path.join(cert_dir, f"{stem}.{kt}.key")
            shutil.copy2(key_file_src, dst_key)
            os.chmod(dst_key, 0o600)

            log.info("install_cert: installed %s cert files for %s", kt.upper(), domain)

            # CA / issuer chain → .ca.cer
            dst_ca = os.path.join(cert_dir, f"{stem}.{kt}.ca.cer")
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
                p = os.path.join(cert_dir, f"{stem}.{suffix}")
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
            self._migrate_legacy_storage(self._lego_path(cert_dir, kt))
            args = [
                "certificates", "revoke",
                "--email",     email,
                "--path",      self._lego_path(cert_dir, kt),
                "--server",    server_url,
                "--cert.name", cert_file_stem(domain),
            ]
            rc = self._run(args).returncode
            if rc != 0:
                failures.append(f"{kt.upper()} exit {rc}")

        if failures:
            raise AcmeError(f"lego revoke failed for {domain}: {'; '.join(failures)}")
