"""ACME provider stub for Lego (https://github.com/go-acme/lego).

This provider is not yet implemented. It exists to:
  - validate that the AcmeProvider interface is complete
  - serve as the starting point for the acme.sh → Lego transition

Key differences to account for during implementation:
  - Lego binary: ``lego`` (installed alongside acme.sh or replacing it)
  - DNS plugin names differ (e.g. ``cloudflare``, not ``dns_cf``)
  - Key-type flag: ``--key-type ec256`` or ``--key-type rsa2048``
  - Cert state stored under ``{cert_dir}/.lego/certificates/``
  - No separate --install-cert step; files are written directly on issue/renew
  - ACME server passed via ``--server`` (same as acme.sh)
  - Account registration is implicit on first ``run`` command
"""
from __future__ import annotations

from acme_provider import AcmeProvider, IssueResult


class LegoProvider(AcmeProvider):
    """ACME provider using the Lego client. Not yet implemented."""

    def register_account(self, email: str, server: str) -> None:
        raise NotImplementedError("LegoProvider is not yet implemented")

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
        raise NotImplementedError("LegoProvider is not yet implemented")

    def renew_cert(
        self,
        *,
        domain: str,
        acme_server: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> IssueResult:
        raise NotImplementedError("LegoProvider is not yet implemented")

    def install_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        raise NotImplementedError("LegoProvider is not yet implemented")

    def revoke_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        raise NotImplementedError("LegoProvider is not yet implemented")
