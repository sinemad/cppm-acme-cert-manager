# How It Works

## Startup Decision Tree

Every time the container starts, `entrypoint.sh` runs a one-time migration
check (`migrate_from_env`) to auto-populate `servers.json` from any legacy
`.env` configuration, then iterates over every server in `servers.json`.

```
Container starts
│
├─ servers.json empty?
│    YES → Warn. Start web server and supercronic anyway.
│          Add a server via web UI or `cppm-servers add`, then restart.
│
└─ For each server in servers.json:
       │
       ├─ FORCE_RENEW=true in .env?
       │    YES → Issue both certs (--force) → Install flat files → Upload to CPPM
       │
       ├─ <domain>.ecc.cer AND <domain>.rsa.cer both exist?
       │    YES → Log subject + expiry. NOTHING ELSE.
       │          This is the normal path on every restart after initial setup.
       │
       ├─ acme.sh internal state has both certs but flat files are missing?
       │   (happens after a container rebuild before --install-cert ran)
       │    YES → --install-cert only → Upload to CPPM
       │          No DNS challenge. No contact with the ACME CA.
       │
       └─ No certificates found (true first run or partial state)
              → DNS-01 challenge via configured provider → Issue ECC + RSA
              → Install → Upload to CPPM
```

---

## Certificate Issuance (first run only)

```
entrypoint.sh
    └── issue_cert.sh
            │
            ├── acme.sh --issue --keylength ec-256   ECC via <provider> DNS-01
            ├── acme.sh --issue --keylength 2048      RSA via <provider> DNS-01
            │
            └── install_cert.sh
                    │
                    ├── acme.sh --install-cert --ecc  ECC → <domain>.ecc.*
                    ├── acme.sh --install-cert        RSA → <domain>.rsa.*
                    │
                    └── deploy_hook.sh
                            │
                            └── clearpass_upload.py  (pyclearpass SDK)
                                    │
                                    ├── Step 0: Trust List Pre-flight
                                    │     ├── Load bundled ACME CA certs from image
                                    │     ├── Parse acme.sh ECC CA chain
                                    │     ├── Apply trust exclusions (per-server from
                                    │     │   servers.json, or global trust-exclusions.conf)
                                    │     ├── Compute SHA-256 fingerprints from
                                    │     │   cert_file PEM in each trust list entry
                                    │     ├── get_cert_trust_list()
                                    │     ├── new_cert_trust_list()        (missing certs)
                                    │     │     body: cert_file=<PEM string>
                                    │     │           cert_usage=["EAP","Others"]
                                    │     │           enabled=true
                                    │     └── update_cert_trust_list_...() (flags wrong)
                                    │
                                    ├── Step 1: HTTPS(ECC) Server Certificate
                                    │     ├── get_cluster_server_by_uuid("publisher")
                                    │     │     GET /api/cluster/server/publisher
                                    │     ├── get_server_cert()   (find HTTPS(ECC) service_name)
                                    │     └── PUT /api/server-cert/name/{uuid}/HTTPS(ECC)
                                    │           PKCS12 served via CPPM_CALLBACK_HOST
                                    │
                                    ├── Step 2: RADIUS (RSA) Service Certificate
                                    │     ├── get_cluster_server_by_uuid("publisher")
                                    │     ├── get_server_cert()   (find RADIUS service_name)
                                    │     └── PUT /api/server-cert/name/{uuid}/RADIUS
                                    │           PKCS12 served via CPPM_CALLBACK_HOST
                                    │
                                    └── Step 3: get_server_cert()  (verify domain present)
```

---

## Automatic Renewal (supercronic)

acme.sh renews certificates when 30 or fewer days remain (roughly 60 days
after issue for a 90-day Let's Encrypt cert).

```
supercronic runs renew.sh at 02:00 and 14:00 UTC every day
    │
    └── renew.sh
            │
            ├── acme.sh --renew (ECC + RSA)
            │       │
            │       ├── exit 2  (>30 days remaining)
            │       │     └── Log "not due". Done.
            │       │
            │       └── exit 0  (renewed)
            │             └── install_cert.sh → deploy_hook.sh → clearpass_upload.py
            │
            └── (other exit code)  Log error. supercronic retries at next window.
```

---

## ACME Provider Abstraction

The ACME operations (issue, renew, install, revoke) are expressed as a Python
provider interface alongside the existing shell scripts. This is prework for an
eventual transition from `acme.sh` to [Lego](https://github.com/go-acme/lego).

```
acme_provider.py          ← Abstract base class: AcmeProvider
                               issue_cert / renew_cert / install_cert / revoke_cert / register_account
                               Shared types: IssueResult, KeyTypeResult, AcmeError
        │
        ├── acme_sh_provider.py   ← AcmeShProvider: wraps acme.sh CLI subprocess calls
        │                              DNS plugin mapping (cloudflare → dns_cf, etc.)
        │                              Mirrors behaviour of issue_cert.sh / renew.sh / install_cert.sh
        │
        └── lego_provider.py      ← LegoProvider: stub (NotImplementedError)
                                       Documents key differences vs acme.sh for future implementer
```

The shell scripts remain the active code path. The Python provider layer is a
parallel implementation that is ready to replace them incrementally. Callers
switch providers via the factory:

```python
from acme_provider import get_provider

provider = get_provider("acme_sh")   # current default
# provider = get_provider("lego")   # future
```

### Key differences between acme.sh and Lego (for future migration)

| Aspect | acme.sh | Lego |
|---|---|---|
| DNS plugin names | `dns_cf`, `dns_porkbun`, `dns_aws`, … | `cloudflare`, `porkbun`, `route53`, … |
| Key-type flag | `--keylength ec-256` / `2048` | `--key-type ec256` / `rsa2048` |
| Cert state path | `{cert_dir}/{domain}_ecc/` | `{cert_dir}/.lego/certificates/` |
| Install step | Separate `--install-cert` required | Files written directly on issue/renew |
| Account registration | Explicit `--register-account` | Implicit on first `run` |

---

## ClearPass REST API — SDK and Endpoints

All ClearPass API calls use the **official Aruba pyclearpass SDK**
(`pip install pyclearpass`). The SDK module used is
`pyclearpass.api_platformcertificates.ApiPlatformCertificates`.

Source: https://github.com/aruba/pyclearpass

API reference: https://developer.arubanetworks.com/cppm/reference (v6.9–v6.12)

### Authentication

The pyclearpass SDK's built-in OAuth2 exchange sends extra `username` and
`password` fields that cause CPPM to reject the token request. Instead,
`clearpass_upload.py` performs the OAuth2 `client_credentials` exchange
directly with a clean minimal JSON body, then passes the resulting Bearer token
to the SDK as `api_token=`. The SDK skips its own token fetch and uses the
provided token for all requests.

### Step 0 — Trust List Pre-flight

| SDK Method | HTTP | Path |
|---|---|---|
| `get_cert_trust_list(limit="1000")` | `GET` | `/api/cert-trust-list` |
| `new_cert_trust_list(body={...})` | `POST` | `/api/cert-trust-list` |
| `update_cert_trust_list_by_cert_trust_list_id(id, body={...})` | `PATCH` | `/api/cert-trust-list/{id}` |

The CPPM trust list response includes only `id`, `cert_file`, `enabled`,
`cert_usage`, and `_links` — no fingerprint or subject field. The script
computes SHA-256 fingerprints from the `cert_file` PEM in each entry using
`openssl x509 -fingerprint -sha256`, building a lookup map to match against
the bundled ACME CA certs. This allows reliable detection of existing entries
and accurate flag checking before any PATCH or POST is attempted.

**POST body schema:**
```json
{
  "cert_file":  "<PEM text of CA certificate>",
  "enabled":    true,
  "cert_usage": ["EAP", "Others"]
}
```

**PATCH body schema** (for entries with incomplete flags):
```json
{
  "enabled":    true,
  "cert_usage": ["EAP", "Others"]
}
```

Valid `cert_usage` string values per CPPM API docs:
`"AD/LDAP Servers"`, `"Aruba Infrastructure"`, `"Aruba Services"`,
`"Database"`, `"EAP"`, `"Endpoint Context Servers"`, `"RadSec"`,
`"SAML"`, `"SMTP"`, `"EST"`, `"Others"`

### Step 1 — HTTPS(ECC) Server Certificate

The `PUT /api/server-cert/name/{server_uuid}/{service_name}` endpoint is
JSON-only (confirmed in CPPM Swagger UI). CPPM must fetch the PKCS12 from a
URL — there is no binary upload path. The script serves the PKCS12 from a
temporary HTTP server bound to `0.0.0.0` on a fixed port exposed by
`docker-compose.yml`. `CPPM_CALLBACK_HOST` must be set to the Docker host's
LAN IP that CPPM can route to.

| Method | Path |
|---|---|
| `GET` | `/api/cluster/server/publisher` |
| `GET` | `/api/server-cert` |
| `PUT` | `/api/server-cert/name/{server_uuid}/HTTPS(ECC)` |

The publisher server UUID is fetched via
`ApiLocalServerConfiguration.get_cluster_server_by_uuid(uuid="publisher")`.
The HTTPS(ECC) service name is confirmed from `get_server_cert()` — the
script prefers `HTTPS(ECC)` (service_id=2) then falls back to `HTTPS(RSA)`
(service_id=7).

### Step 2 — RADIUS (RSA) Service Certificate

Same PUT mechanism as Step 1, targeting the RADIUS service name (service_id=1).
If no RADIUS entry exists in `get_server_cert()`, CPPM uses a unified
certificate — the step is skipped cleanly.

| Method | Path |
|---|---|
| `PUT` | `/api/server-cert/name/{server_uuid}/RADIUS` |

### Step 3 — Verification

`get_server_cert()` is called and the response is searched for the domain name
as a sanity check.

---

## Certificate Strategy

| Certificate | Algorithm | CPPM Service | Service ID |
|---|---|---|---|
| ECC (ec-256) | ECDSA P-256 | HTTPS(ECC) | 2 |
| RSA (2048)   | RSA 2048    | RADIUS      | 1 |

acme.sh stores each type in a separate directory:

| Type | acme.sh state dir | Flat files |
|---|---|---|
| ECC | `/data/certs/<cppm_host>/<domain>_ecc/` | `<domain>.ecc.cer`, `.ecc.key`, `.ecc.fullchain.cer`, `.ecc.ca.cer` |
| RSA | `/data/certs/<cppm_host>/<domain>/` | `<domain>.rsa.cer`, `.rsa.key`, `.rsa.fullchain.cer`, `.rsa.ca.cer` |

All cert files for a given ClearPass server live inside `/data/certs/<cppm_host>/`,
where `<cppm_host>` is the sanitized ClearPass hostname (e.g. `cppm.example.com`).

---

## Persistent Storage Layout

Only `/data/certs` is mounted from the host. Everything else lives in the
image and is recreated on every `docker compose build`.

```
/opt/cppm-certs/                          ← host directory (bind-mounted to /data/certs)
│
├── servers.json                          ← All ClearPass server configs (chmod 600, contains secrets)
├── admin.htpasswd                        ← Web UI admin credentials (bcrypt, chmod 600)
├── .session-secret                       ← Web UI session signing key (chmod 600)
├── trust-exclusions.conf                 ← Global CA trust exclusion fallback
├── status.log                            ← Container-level startup events only
│
├── .acme-state/                          ← Shared acme.sh account home (all servers)
│   ├── ca/
│   ├── dnsapi/
│   └── account.conf
│
├── .logs/                                ← Container-level logs
│   ├── startup.log                       ← entrypoint.sh boot log
│   └── status_server.log                 ← Web UI process log
│
├── cppm.example.com/                     ← Per-server directory (named by ClearPass hostname)
│   ├── status.log                        ← Per-server activity log (web UI Activity tab)
│   ├── cppm.example.com.ecc.cer          ← ECC domain cert
│   ├── cppm.example.com.ecc.key          ← ECC private key (chmod 600)
│   ├── cppm.example.com.ecc.fullchain.cer
│   ├── cppm.example.com.ecc.ca.cer
│   ├── cppm.example.com.rsa.cer          ← RSA domain cert
│   ├── cppm.example.com.rsa.key          ← RSA private key (chmod 600)
│   ├── cppm.example.com.rsa.fullchain.cer
│   ├── cppm.example.com.rsa.ca.cer
│   ├── cppm.example.com_ecc/             ← acme.sh ECC internal state
│   ├── cppm.example.com/                 ← acme.sh RSA internal state
│   └── .logs/
│       ├── acme_renewal.log              ← acme.sh issuance/renewal detail (web UI ACME Renewal tab)
│       └── cppm_upload.log               ← ClearPass API upload detail (web UI ClearPass Upload tab)
│
└── cppm-lab.example.com/                 ← Second server (same structure)
    ├── status.log
    └── .logs/
        ├── acme_renewal.log
        └── cppm_upload.log
```

> **`trust-exclusions.conf`** is a global fallback only — it applies to servers
> that have no per-server exclusions configured in `servers.json`. Per-server
> trust exclusions are configured via the web UI (Servers → Trust Exclusions)
> and stored inside `servers.json` under each server's `trust_exclusions` field.

---

## Image Contents (self-contained)

| Path in image | Contents | Source |
|---|---|---|
| `/usr/local/bin/acme.sh` | acme.sh binary | GitHub (git clone at build time) |
| `/opt/acme-seed/` | Full acme.sh install (dnsapi/, deploy/) | Copied from clone |
| `/opt/cppm/acme-ca-certs/` | Let's Encrypt CA PEM files + `trust-exclusions.conf` default | letsencrypt.org (curl at build time) |
| `/opt/cppm/` | All management scripts | COPY from project directory |
| Python packages | pyclearpass, requests, urllib3 | pip at build time |

Runtime network access:

| Destination | Purpose | When |
|---|---|---|
| DNS provider API (e.g. `api.cloudflare.com`) | DNS-01 challenge TXT record | Issuance and renewal only |
| ACME CA (e.g. `acme-v02.api.letsencrypt.org`) | Certificate issuance protocol | Issuance and renewal only |
| `<CPPM_HOST>` | ClearPass REST API | After every issuance/renewal |
| `<CPPM_CALLBACK_HOST>:<CPPM_CALLBACK_PORT>` | PKCS12 fetch (inbound from CPPM) | During cert upload only |
