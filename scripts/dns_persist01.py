"""Scaffolding for ACME DNS-PERSIST-01 (draft-ietf-acme-dns-persist).

DNS-PERSIST-01 is an IETF-draft ACME challenge type, not an invention of this
project. Instead of a fresh per-issuance TXT record (DNS-01's model), the
domain owner publishes one standing TXT record at `_validation-persist.<fqdn>`
that names the issuing CA and the ACME account authorized to use it. Once
published, no further DNS writes are needed for later issuance or renewal of
that FQDN -- the only credential that stays sensitive afterward is the ACME
account key, not DNS write access.

Status: the draft is not ratified, and as of this writing no CA this project
currently supports (see `_CA_CAPABLE` below) has confirmed production support.
Nothing in this file is wired into issuance/renewal (see lego_provider.py) --
this is read-only scaffolding so that work isn't starting from zero once a CA
here actually ships it. See docs/09-dns-persist-01-draft.md.

Record-sharing note: per the draft, a record published WITHOUT
`policy=wildcard` authorizes only the exact FQDN it's published under -- one
record per host. WITH `policy=wildcard`, a single record at a zone's apex
(e.g. `_validation-persist.example.com`) can authorize that apex, any of its
subdomains, and matching wildcards -- i.e. it can be shared across every
server in this tool that issues for a domain under that zone. That means the
natural unit for a persist record is (CA, ACME account, zone), not
(server) -- worth keeping in mind for the eventual servers.json schema, which
isn't designed yet.

The `accounturi` TXT field is a hash keyed partly on the domain the record
is published under (see compute_account_hash_uri), not the FQDN being
issued for -- the draft confirms this hash does not vary per requested
subdomain, so the one-record-per-zone sharing model above still holds.

NOTE ON DRAFT CHURN: the record format has already changed materially once
-- `accounturi` was a plain ACME account URI through draft -01, and is now
a cryptographic hash (see compute_account_hash_uri's docstring). The draft
is actively being revised; re-check
https://ietf-wg-acme.github.io/draft-ietf-acme-dns-persist/draft-ietf-acme-dns-persist.html
(the continuously-updated "latest" rendering) before trusting anything in
this file against the current spec.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

# Keyed by the acme_server values already used in cppm_acme_manager_servers.py
# / lego_provider.py's _ACME_SERVER_MAP. Flip an entry to True only once that
# CA has confirmed, documented production support for DNS-PERSIST-01 -- not
# on a forum claim. This is the single place that decision should be recorded.
_CA_CAPABLE: dict[str, bool] = {
    "letsencrypt":      False,  # production: not yet (phased rollout, status unconfirmed)
    "letsencrypt_test": False,  # staging: known accounturi bugs reported 2026-07
    "zerossl":          False,  # no public statement found
    "buypass":          False,
    "buypass_test":     False,
}

# The literal issuer-domain-name token each CA expects in the TXT record
# value (see build_persist_txt_value). Left unset until each CA publishes
# its own exact value for this -- do not guess it from the ACME directory
# URL, they are not guaranteed to match.
_CA_ISSUER_DOMAIN: dict[str, str | None] = {
    "letsencrypt":      None,
    "letsencrypt_test": None,
    "zerossl":          None,
    "buypass":          None,
    "buypass_test":     None,
}


def persist01_ca_capable(acme_server: str) -> bool:
    """True if `acme_server` has confirmed production DNS-PERSIST-01 support."""
    return _CA_CAPABLE.get(str(acme_server).strip(), False)


def read_account_uri(lego_path: str, acme_server_host: str, email: str) -> str | None:
    """Read the ACME account URI Lego already stores on disk, or None if no
    account has been registered yet for this (server, email).

    `acme_server_host` is the CA directory URL's host, with ':' and '/'
    replaced by '_' -- matching Lego's own `AccountsStorage` layout
    (go-acme/lego cmd/accounts_storage.go):

        <lego_path>/accounts/<acme_server_host>/<email>/account.json

    The URI lives at .registration.uri in that file (go-acme/lego
    cmd/account.go + registration/registar.go).

    NOTE: the plain URI this returns is one input to compute_account_hash_uri
    (the `account_url` parameter), not the final `accounturi` TXT field value
    -- the current draft hashes it together with the account key thumbprint
    and the record's domain. Don't publish this return value directly.
    """
    userid = email or "noemail@example.com"
    account_file = os.path.join(lego_path, "accounts", acme_server_host, userid, "account.json")
    try:
        with open(account_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    registration = data.get("registration") or {}
    return registration.get("uri") or None


def compute_account_hash_uri(
    account_hash_prefix: str,
    domain_name: str,
    account_key_thumbprint: str,
    account_url: str,
    hash_alg: str = "sha-256",
) -> str:
    """Build the `accounturi` value's current (post -01) hashed form:

        <accountHashPrefix><hash-alg>/<base64url hash, no padding>

    digest = H(len(domain_name) || domain_name || account_key_thumbprint || account_url)

    where `len(domain_name)` is a single length-prefix octet and H is the
    hash named by `hash_alg` ("sha-256" is the only one CAs are required to
    support, and the only one implemented here).

    IMPORTANT -- this superseded a *plain* account URI used in
    draft-ietf-acme-dns-persist-01 and earlier; don't reintroduce that form.

    `domain_name` is the FQDN the `_validation-persist` record is published
    under -- e.g. a zone's apex when sharing one record across the zone via
    `policy=wildcard` -- NOT the FQDN being requested for a cert; the draft
    confirms the hash does not vary per requested subdomain because of this.
    Per the draft, a client may instead pass "*" for a hash that doesn't
    depend on any domain and can be reused across zones.

    `account_hash_prefix` comes from the CA's own ACME directory metadata
    (its `accountHashPrefix` field) -- don't guess or hardcode a CA's value.

    `account_key_thumbprint` is the ACME account key's RFC 7638 JWK
    thumbprint. This is NOT present in Lego's account.json (see
    read_account_uri) -- computing it from the account's private key is not
    implemented here yet, since no CA this tool supports can accept this
    record today; revisit once one does.
    """
    if hash_alg != "sha-256":
        raise ValueError(f"unsupported hash-alg {hash_alg!r} -- only 'sha-256' is implemented")
    domain_bytes = domain_name.encode("ascii")
    if len(domain_bytes) > 255:
        raise ValueError("domain_name must fit in a one-octet length prefix (<=255 bytes)")
    digest_input = (
        bytes([len(domain_bytes)]) + domain_bytes
        + account_key_thumbprint.encode("ascii")
        + account_url.encode("utf-8")
    )
    digest = hashlib.sha256(digest_input).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{account_hash_prefix}{hash_alg}/{b64}"


def build_persist_txt_value(
    issuer_domain: str,
    account_hashed_uri: str,
    wildcard: bool = False,
    persist_until: int | None = None,
) -> str:
    """Assemble a `_validation-persist` TXT record value: "<issuer-domain>
    ;accounturi=<hashed-uri>[;policy=wildcard][;persistUntil=<unix-seconds>]".

    `account_hashed_uri` is the output of compute_account_hash_uri() --
    passing a plain ACME account URI here matches the superseded -01 draft
    form, not the current one.
    """
    parts = [f"{issuer_domain};accounturi={account_hashed_uri}"]
    if wildcard:
        parts.append("policy=wildcard")
    if persist_until is not None:
        parts.append(f"persistUntil={persist_until}")
    return ";".join(parts)
