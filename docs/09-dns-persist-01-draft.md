# DNS-PERSIST-01 (tracking — not usable yet)

## Status

**Current behavior in this tool is unchanged.** Every server still issues
and renews using DNS-01, exactly as before. This document and
`scripts/dns_persist01.py` exist to track an IETF-draft ACME challenge type
that may eventually let this tool avoid keeping a live DNS-API credential
around for renewals — but it isn't usable yet, for two independent reasons:

1. The standard itself is a draft, not a ratified RFC —
   [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)
   ([working-group HTML rendering](https://ietf-wg-acme.github.io/draft-ietf-acme-dns-persist/draft-ietf-acme-dns-persist.html)
   — rendered as `draft-ietf-acme-dns-persist-latest`, dated **7 October
   2026**, expiring 10 April 2027; kept continuously up to date as the
   draft is revised, so **re-check this link often** rather than trusting
   anything summarized here against a future revision — the record format
   has already changed materially once, see below).
2. No CA this tool currently supports (Let's Encrypt, ZeroSSL) has
   confirmed *production* support. Let's Encrypt has it in **staging only**,
   and staging is currently stuck on an older draft revision than clients
   expect: staging implements **draft 00**, which has no `accounturi` field
   at all, while Lego (and the current working-group draft) require it per
   **draft 01**. Clients built against draft 01 fail against staging with
   `dnspersist01: missing accounturi in challenge object` — tracked as
   [Boulder issue #8708](https://github.com/letsencrypt/boulder/issues/8708)
   (confirmed via the
   [community.letsencrypt.org thread](https://community.letsencrypt.org/t/missing-accounturi-field-in-le-dns-persist-01-challenges/246486),
   checked 2026-10-16). A separate thread
   ([deployment status and timeline](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468/6))
   has Let's Encrypt staff saying the spec is still changing and a wider
   release might land in Q3 if open IETF issues resolve — no firm date. An
   unconfirmed third-party post (Sept 16, 2026) claims the rollout has since
   been frozen; I couldn't verify that against an official source, so treat
   it as unconfirmed, not settled. Other CAs — Google Trust Services
   (production, since September 2026) and reportedly DigiCert — aren't
   options in this tool today.
3. There's also an open design complaint worth tracking separately: checking
   whether a `_validation-persist` record is even present currently requires
   creating a full ACME order (to learn the CA's `issuerDomainNames`), which
   wastes orders for a client that only wants to verify its DNS setup —
   especially under short-lived authorization profiles. See
   [the "DNS-PERSIST without spending an Order" thread](https://community.letsencrypt.org/t/dns-persist-01-challenge/245569/17).
   Doesn't block anything here yet, but worth knowing before designing any
   "verify my persist record" UX later.

`scripts/dns_persist01.py`'s `_CA_CAPABLE` map tracks this per CA and starts
with everything `False`. Revisit it before building anything user-facing.

## What it actually is

Unlike DNS-01, which needs a fresh `_acme-challenge` TXT record for every
issuance, DNS-PERSIST-01 has the domain owner publish **one standing TXT
record** that the CA reuses for all future issuance and renewal of that
name — no further DNS writes needed afterward. The record lives at:

```
_validation-persist.<fqdn>.  IN TXT  "<issuer-domain>;accounturi=<acme-account-uri>"
```

- `<issuer-domain>` — a literal token the CA itself publishes (not the ACME
  directory URL — don't guess this per CA; wait for each one to document it).
- `accounturi=` — **not a plain account URI.** As of the current draft (this
  changed since draft -01, which earlier sources like the Trustico article
  and Google Trust Services' published example still reflect), it's a
  cryptographic hash that binds the ACME account to the domain:

  ```
  <accountHashPrefix><hash-alg>/<base64url hash, no padding>
  digest = SHA-256(len(domain_name) || domain_name || account_key_JWK_thumbprint || account_URL)
  ```

  - `accountHashPrefix` and the hash algorithm (`sha-256` is the minimum
    CAs must support) come from the CA's own ACME directory metadata —
    don't hardcode a value.
  - `domain_name` is the FQDN the record is published under (the record's
    own apex, e.g. when sharing one record across a zone — see "Record
    sharing" below), **not** the FQDN being requested for a cert. The draft
    confirms the hash doesn't vary per requested subdomain because of this.
    A client may instead use `*` for a hash reusable across domains.
  - `account_key_JWK_thumbprint` is the ACME account key's RFC 7638
    thumbprint — Lego doesn't store this directly (see below); computing it
    isn't implemented yet in `dns_persist01.py`, since nothing can use it
    today.
  - `account_URL` is the plain ACME account URI — this is the one piece
    Lego already gives us (see below), now just one input to the hash
    rather than the record value itself.

  See `dns_persist01.compute_account_hash_uri()` for the implementation.
- `policy=wildcard` (optional) — extends the record's authorization beyond
  the exact FQDN. See "Record sharing" below.
- `persistUntil=<unix-seconds>` (optional) — an expiry; the record must be
  refreshed before it passes or the CA stops honoring it.

Once DNS-01 stops being needed per-issuance, the thing worth protecting
shifts from "the DNS API credential" to "the ACME account private key" —
whoever holds that key can issue against the published record.

## Where the plain account URI comes from (one input to the hash, not the final value)

Confirmed directly from the upstream `go-acme/lego` source
(`cmd/accounts_storage.go`, `cmd/account.go`, `registration/registar.go`),
not a guess: Lego already writes this to disk on every registration, at

```
<lego_path>/accounts/<ca-host>/<email>/account.json
```

```json
{
  "email": "user@example.com",
  "registration": {
    "body": { "...": "..." },
    "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"
  }
}
```

`dns_persist01.read_account_uri()` reads `.registration.uri` from that file.
It's a pure read with no side effects — safe to call any time an account
already exists, and returns `None` if one doesn't. Its result feeds into
`compute_account_hash_uri()` as the `account_url` input; it is **not**
itself a valid `accounturi` field value under the current draft.

Still missing: the account key's RFC 7638 JWK thumbprint, the other input
`compute_account_hash_uri()` needs. Lego's `account.json` doesn't store it —
it would have to be computed from the account's private key file (the
`.key` PEM alongside `account.json`). Not implemented yet; see "What's
intentionally not built yet" below.

## Record sharing — one record can cover a whole zone

Confirmed against the IETF draft text itself (section 6.3), not a secondhand
summary:

- **Without `policy=wildcard`**, a record at `_validation-persist.<fqdn>`
  authorizes *only that exact FQDN*. Two servers on different hostnames in
  the same zone each need their own record.
- **With `policy=wildcard`**, a record published at a zone's apex (e.g.
  `_validation-persist.example.com`) can authorize the apex itself, any
  subdomain (`www.example.com`, `server.dept.example.com`), and matching
  wildcards (`*.example.com`, `*.dept.example.com`). The draft uses "MAY"
  here, so this depends on each CA actually implementing it that way.

Practical consequence for this tool: the natural unit for a persist record
is **(CA, ACME account, zone)**, not (server). Multiple servers in this tool
that issue for hosts under one zone could eventually share a single
apex record, rather than each needing their own — worth designing the
eventual servers.json schema around once this becomes buildable.

## What's intentionally not built yet

- No GUI/CLI toggle — there's nothing safe to turn on.
- No automatic publishing of the persist record to a DNS provider — the
  draft's whole point is that ongoing DNS write access isn't needed, so
  automating a one-time write isn't an obvious win; likely stays a manual,
  documented step for the admin even once this ships.
- No `_CA_ISSUER_DOMAIN` values — these must come from each CA's own
  documentation, not be inferred from their ACME directory URL.
- No RFC 7638 JWK-thumbprint computation from the account's private key —
  needed to actually compute `accounturi`'s hash; not written yet since
  nothing can use it today.

## Related

- [RFC 8659](https://www.rfc-editor.org/info/rfc8659/) — the DNS CAA
  (Certification Authority Authorization) record. Not DNS-PERSIST-01 itself,
  but the natural companion: CAA governs which CAs are allowed to issue for
  a domain at all, independent of (and checked before) any DNS-01 or
  DNS-PERSIST-01 validation. Worth checking a domain's CAA record isn't
  blocking a CA before assuming a DNS-PERSIST-01 failure is about the
  persist record itself.

## Revisit when

A CA already selectable in this tool (`letsencrypt`, `zerossl`)
publishes confirmed production support, or the draft is adopted as an RFC —
whichever comes first. At that point, flip the relevant `_CA_CAPABLE` entry
in `scripts/dns_persist01.py` and design the actual user-facing feature
(likely: a per-zone "Set up DNS-PERSIST-01" flow in the GUI that shows the
exact record to publish, using `build_persist_txt_value()`).
