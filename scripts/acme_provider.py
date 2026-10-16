"""Abstract ACME provider interface and shared result types."""
from __future__ import annotations

import abc
import dataclasses


@dataclasses.dataclass
class KeyTypeResult:
    """Outcome for a single key-type operation."""
    key_type: str   # "ecc" or "rsa"
    issued: bool    # True = new cert issued; False = skipped (not due / already exists)


@dataclasses.dataclass
class IssueResult:
    """Combined result from an issue or renew operation."""
    results: list[KeyTypeResult]

    @property
    def newly_issued(self) -> bool:
        return any(r.issued for r in self.results)


class AcmeError(Exception):
    """Raised when an ACME provider operation fails."""


def cert_file_stem(domain: str) -> str:
    """Return the filename-safe form of ``domain`` used for all cert files.

    Wildcard domains map ``*`` to ``_`` (``*.example.com`` → ``_.example.com``),
    matching the names Lego itself writes under ``certificates/``. Keep in sync
    with ``cert_file_stem`` in status.sh.
    """
    return domain.replace("*", "_")


class AcmeProvider(abc.ABC):
    """Common interface for ACME certificate providers.

    All path arguments should be absolute. ``key_types`` is a list containing
    any combination of ``"ecc"`` and ``"rsa"``.
    """

    @abc.abstractmethod
    def register_account(self, email: str, server: str) -> None:
        """Register or verify an ACME account (idempotent)."""

    @abc.abstractmethod
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
        """Issue certificates via DNS-01 challenge.

        ``dns_env`` contains the provider-specific credential env vars
        (e.g. ``{"CF_Token": "..."}`` for Cloudflare). They are merged into
        the subprocess environment; the caller need not export them globally.
        """

    @abc.abstractmethod
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
        """Renew an existing certificate. Returns the renewal outcome.

        ``dns_provider`` and ``dns_env`` are required because some providers
        (Lego) need DNS credentials on every renewal call, not just issuance.
        Providers that store credentials in per-cert state (acme.sh) accept
        these parameters for interface compatibility but do not use them.
        """

    @abc.abstractmethod
    def install_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        """Copy provider-managed cert state to well-known flat file paths.

        After this call the following files must exist (for each enabled type):

        ECC:  ``{cert_dir}/{domain}.ecc.cer``   ``.ecc.key``
              ``{domain}.ecc.fullchain.cer``      ``.ecc.ca.cer``

        RSA:  ``{cert_dir}/{domain}.rsa.cer``   ``.rsa.key``
              ``{domain}.rsa.fullchain.cer``      ``.rsa.ca.cer``
        """

    @abc.abstractmethod
    def revoke_cert(
        self,
        *,
        domain: str,
        cert_dir: str,
        key_types: list[str],
        log_file: str,
    ) -> None:
        """Revoke an issued certificate."""

    @abc.abstractmethod
    def migrate_legacy_storage(
        self,
        *,
        cert_dir: str,
        key_types: list[str],
    ) -> None:
        """Convert any legacy on-disk account storage to the current layout.

        Local-only: never makes an ACME/network call, and is a no-op when
        storage is already current. Safe to call unconditionally on every
        container start so a storage-layout change takes effect immediately
        on upgrade rather than waiting for the next scheduled renew/issue.
        """


def get_provider(provider_type: str = "lego") -> AcmeProvider:
    """Factory: return a provider instance by name (``"acme_sh"`` or ``"lego"``)."""
    if provider_type == "acme_sh":
        from acme_sh_provider import AcmeShProvider  # noqa: PLC0415
        return AcmeShProvider()
    if provider_type == "lego":
        from lego_provider import LegoProvider  # noqa: PLC0415
        return LegoProvider()
    raise ValueError(f"Unknown ACME provider type: {provider_type!r}")
