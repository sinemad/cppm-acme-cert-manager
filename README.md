# ClearPass Certificate Manager

Automated TLS certificate issuance and renewal for **Aruba ClearPass Policy Manager (CPPM)**
using [acme.sh](https://github.com/acmesh-official/acme.sh) and a DNS-01 challenge.
Everything runs in a self-contained Alpine Linux Docker container with persistent storage
on the host.

Two certificates are issued and maintained simultaneously:

| Certificate | Algorithm | CPPM Service | Purpose |
|---|---|---|---|
| ECC (P-256) | ECDSA | HTTPS(ECC) | Web UI and API access |
| RSA (2048) | RSA | RADIUS | 802.1X / EAP authentication |

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      ClearPass Cert Manager Flow                         │
│                                                                          │
│  ┌──────────────┐  DNS-01  ┌─────────────────┐                          │
│  │   acme.sh    │◄────────►│  DNS Provider   │                          │
│  │  (supercronic│          │  (Cloudflare,   │                          │
│  │   2x daily)  │          │   Porkbun, etc) │                          │
│  └──────┬───────┘          └─────────────────┘                          │
│         │ ECC + RSA certs issued/renewed                                 │
│         ▼                                                                │
│  ┌──────────────┐  PKCS12 + REST API  ┌──────────────────────────────┐  │
│  │ deploy_hook  │────────────────────►│  clearpass_upload.py         │  │
│  │    .sh       │                     │  (pyclearpass SDK)            │  │
│  └──────────────┘                     │                              │  │
│                                       │  Step 0: LE Trust List       │  │
│                                       │  Step 1: PUT HTTPS(ECC) cert │  │
│                                       │  Step 2: PUT RADIUS(RSA) cert│  │
│                                       │  Step 3: Verify              │  │
│                                       └──────────────┬───────────────┘  │
│                                                      │                  │
│                                              ┌───────▼──────┐           │
│                                              │     CPPM     │           │
│                                              │  HTTPS(ECC)  │           │
│                                              │  RADIUS(RSA) │           │
│                                              └──────────────┘           │
│                                                                          │
│  Persistent storage: /opt/cppm-certs (host) ◄──── /data/certs (container) │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [DNS Provider Support](#dns-provider-support)
3. [Directory Structure](#directory-structure)
4. [Initial Setup](#initial-setup)
5. [How It Works](#how-it-works)
6. [Certificate Files](#certificate-files)
7. [Verifying the Certificates in CPPM](#verifying-the-certificates-in-cppm)
8. [Maintenance](#maintenance)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)
11. [ClearPass API Reference](#clearpass-api-reference)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine ≥ 24.x | With Compose v2 plugin (`docker compose`) |
| Host OS | Any Linux with Docker support (Ubuntu 22.04 LTS recommended) |
| DNS provider | Domain managed by a supported DNS provider (see below) |
| CPPM version | 6.9.x through 6.12.x (confirmed on 6.11.13) |
| Network | Container needs outbound HTTPS to your DNS provider API and CPPM |
| LAN IP | A host IP that CPPM can route to (required for cert upload callback) |

---

## DNS Provider Support

The ACME DNS-01 challenge is used for certificate issuance. Set `DNS_PROVIDER`
in `.env` to select your provider.

| `DNS_PROVIDER` | Provider | Credentials required |
|---|---|---|
| `cloudflare` *(default)* | Cloudflare | `CF_Token` + `CF_Account_ID` + `CF_Zone_ID` |
| `porkbun` | Porkbun | `PORKBUN_API_KEY` + `PORKBUN_SECRET_API_KEY` |
| `route53` | AWS Route53 | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| `digitalocean` | DigitalOcean | `DO_API_KEY` |
| `godaddy` | GoDaddy | `GD_Key` + `GD_Secret` |
|  *any* is NOT SUPPORTED AND EXPERIMENTAL
| *any* | [Any acme.sh dnsapi plugin](https://github.com/acmesh-official/acme.sh/wiki/dnsapi) | Plugin-specific variables |

```
## NOT SUPPORTED & EXPERIMENTAL
For any provider not in the list above, set `DNS_PROVIDER` to the plugin name
without the `dns_` prefix (e.g. `DNS_PROVIDER=linode_v4` invokes `dns_linode_v4`)
and ensure the plugin's credential variables are present in `.env`.
```
---

## Directory Structure

```
cppm-cert-manager/
├── Dockerfile                  # Alpine + acme.sh + Python image
├── docker-compose.yml          # Service definition, volume and port mapping
├── env-example                 # Safe-to-commit reference — copy to .env
├── .env.example                # Annotated local reference
├── .gitignore
├── .dockerignore
├── setup.sh                    # One-time host preparation script
├── config/
│   └── crontab                 # Renewal schedule (supercronic, inside container)
├── scripts/
│   ├── entrypoint.sh           # Startup: validates env, manages cert state, starts supercronic
│   ├── issue_cert.sh           # Issues ECC + RSA certs via DNS-01
│   ├── install_cert.sh         # Copies flat files from acme.sh state to /data/certs/
│   ├── renew.sh                # Called by supercronic — runs acme.sh --renew
│   ├── deploy_hook.sh          # Called after issuance/renewal — triggers CPPM upload
│   ├── clearpass_upload.py     # Uploads certs to CPPM via pyclearpass SDK
│   └── status.sh               # Shared status logging library
└── docs/
    ├── 01-initial-setup.md
    ├── 02-how-it-works.md
    ├── 03-monitoring.md
    ├── 04-maintenance.md
    ├── 05-troubleshooting.md
    ├── 06-script-reference.md
    └── 07-quick-reference.md
```

**Host persistent storage (survives container rebuilds):**

```
/opt/cppm-certs/                              ← bind-mounted to /data/certs in container
├── status.log                                ← one-line-per-event summary log
├── <domain>.ecc.cer                          ← ECC domain cert (PEM)
├── <domain>.ecc.key                          ← ECC private key (chmod 600)
├── <domain>.ecc.fullchain.cer                ← ECC cert + intermediates
├── <domain>.ecc.ca.cer                       ← ECC CA chain
├── <domain>.rsa.cer                          ← RSA domain cert (PEM)
├── <domain>.rsa.key                          ← RSA private key (chmod 600)
├── <domain>.rsa.fullchain.cer                ← RSA cert + intermediates
├── <domain>.rsa.ca.cer                       ← RSA CA chain
├── <domain>_ecc/                             ← acme.sh ECC internal state
├── <domain>/                                 ← acme.sh RSA internal state
├── .acme-state/                              ← acme.sh config and account keys
└── .logs/
    ├── startup.log
    ├── renewal.log
    ├── upload.log
    └── cron.log
```

---

## Initial Setup

### 1. Host preparation

```bash
cd /opt/cppm-cert-manager
chmod +x setup.sh && ./setup.sh
```

`setup.sh` verifies Docker, creates `/opt/cppm-certs`, and copies `env-example`
to `.env` if it does not already exist.

### 2. DNS provider credentials

**Cloudflare (default)**

Create a scoped API token:

1. [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) → **Create Token → Custom token**
2. Set **Permissions:** `Zone → DNS → Edit`
3. Set **Zone Resources:** `Include → Specific zone → <your zone>`
4. Copy the token and note your **Account ID** and **Zone ID** (Zone Overview page)

```ini
DNS_PROVIDER=cloudflare
CF_Token=<scoped-api-token>
CF_Account_ID=<account-id>
CF_Zone_ID=<zone-id>
```

**Porkbun**

1. [Porkbun](https://porkbun.com/account/api) → Create API key
2. Enable API access on the domain under Domain Management

```ini
DNS_PROVIDER=porkbun
PORKBUN_API_KEY=pk1_...
PORKBUN_SECRET_API_KEY=sk1_...
```

**Route53 / AWS**

IAM policy required: `route53:ChangeResourceRecordSets`, `route53:ListHostedZones`,
`route53:GetChange`, `route53:ListResourceRecordSets`

```ini
DNS_PROVIDER=route53
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

**DigitalOcean**

```ini
DNS_PROVIDER=digitalocean
DO_API_KEY=dop_v1_...
```

**GoDaddy**

```ini
DNS_PROVIDER=godaddy
GD_Key=...
GD_Secret=...
```

### 3. ClearPass API client

1. CPPM Admin UI → **Administration → API Services → API Clients → Add**
2. Configure:

   | Field | Value |
   |---|---|
   | Client ID | `cppm-cert-manager` |
   | Enabled | ✓ |
   | Operator Profile | `Super Administrator` or custom (see note) |
   | Grant Types | `client_credentials` |
   | Access Token Lifetime | `28800` (8 hours) |

3. Click **Create Client** and copy the client secret — shown only once.

> **Minimum custom Operator Profile permissions:**
> Administration → Operator Logins → Operator Profiles → Add
> Enable **Allow → All → Certificate Management**

### 4. Configure `.env`

```bash
cp env-example .env
chmod 600 .env
nano .env
```

Minimum required values (Cloudflare example):

```ini
# DNS
DNS_PROVIDER=cloudflare
CF_Token=<scoped-api-token>
CF_Account_ID=<account-id>
CF_Zone_ID=<zone-id>

# ACME
DOMAIN=cppm.example.com
ACME_EMAIL=admin@example.com
ACME_SERVER=letsencrypt

# ClearPass
CPPM_HOST=cppm.example.com
CPPM_CLIENT_ID=cppm-cert-manager
CPPM_CLIENT_SECRET=<secret>
CPPM_VERIFY_SSL=false

# Callback — Docker host LAN IP that CPPM can reach (NOT the container IP)
# Find it: ip route get <cppm-ip>  (look for 'src X.X.X.X')
CPPM_CALLBACK_HOST=<host-lan-ip>
CPPM_CALLBACK_PORT=8765
```

### 5. Build and start

```bash
docker compose build --no-cache
docker compose up -d
docker compose logs -f
```

**Expected first-run sequence:**

```
[INFO ] No certificates found – starting first-time issuance
[ISSUE] Issuing ECC (ec-256) certificate via cloudflare DNS-01
[ISSUE] Issuing RSA (2048) certificate via cloudflare DNS-01
[OK   ] New certificates issued (ECC + RSA)
[OK   ] ECC+RSA certs installed – expires <date>
[OK   ] 7 LE CA certs verified – 7 uploaded, 0 already trusted
[OK   ] ECC→HTTPS + RSA→RADIUS uploaded to cppm.example.com
[INFO ] supercronic started – renewal checks at 02:00 and 14:00 UTC
```

First-run time: 2–5 minutes (DNS propagation for the ACME challenge).

---

## How It Works

### Certificate issuance (first run)

```
entrypoint.sh
    └── issue_cert.sh
            ├── acme.sh --issue --keylength ec-256   ECC via DNS-01
            ├── acme.sh --issue --keylength 2048      RSA via DNS-01
            └── install_cert.sh
                    ├── acme.sh --install-cert --ecc  → <domain>.ecc.*
                    ├── acme.sh --install-cert        → <domain>.rsa.*
                    └── deploy_hook.sh
                            └── clearpass_upload.py  (pyclearpass SDK)
                                    ├── Step 0: Trust List Pre-flight
                                    │     Compute SHA-256 fingerprints from cert_file
                                    │     PEM in each trust list entry, then:
                                    │     POST  /api/cert-trust-list  (missing certs)
                                    │     PATCH /api/cert-trust-list/{id}  (wrong flags)
                                    │     cert_usage: ["EAP", "Others"]
                                    │
                                    ├── Step 1: ECC → HTTPS(ECC)
                                    │     GET  /api/cluster/server/publisher  (UUID)
                                    │     GET  /api/server-cert  (find HTTPS(ECC) slot)
                                    │     PUT  /api/server-cert/name/{uuid}/HTTPS(ECC)
                                    │     CPPM fetches PKCS12 via CPPM_CALLBACK_HOST
                                    │
                                    ├── Step 2: RSA → RADIUS
                                    │     PUT  /api/server-cert/name/{uuid}/RADIUS
                                    │
                                    └── Step 3: GET /api/server-cert (verify domain)
```

### Automatic renewal (supercronic)

supercronic runs `renew.sh` at **02:00 and 14:00 UTC** daily. acme.sh renews
when ≤30 days remain — approximately 60 days after issuance for a 90-day
Let's Encrypt certificate.

```
supercronic (02:00 / 14:00 UTC)
    └── renew.sh
            ├── acme.sh --renew (ECC)
            ├── acme.sh --renew (RSA)
            └── on renewal → install_cert.sh → deploy_hook.sh → clearpass_upload.py
```

### Authentication

`clearpass_upload.py` performs an OAuth2 `client_credentials` exchange directly
rather than using the pyclearpass SDK's built-in token fetch (which sends
extra fields that cause CPPM to reject the request). The resulting Bearer token
is then passed to the SDK as `api_token=` for all subsequent calls.

### Server certificate upload

The `PUT /api/server-cert/name/{uuid}/{service_name}` endpoint is JSON-only —
CPPM must fetch the PKCS12 from a URL. The script serves the file from a
temporary HTTP server bound to `0.0.0.0` on `CPPM_CALLBACK_PORT`, which is
published to the Docker host via `docker-compose.yml`. `CPPM_CALLBACK_HOST`
must be the host's LAN IP that CPPM can route to.

---

## Certificate Files

After successful issuance, flat cert files are written to `/opt/cppm-certs/`:

| File | Contents |
|---|---|
| `<domain>.ecc.cer` | ECC domain certificate (PEM) |
| `<domain>.ecc.key` | ECC private key (**chmod 600**) |
| `<domain>.ecc.fullchain.cer` | ECC cert + intermediates |
| `<domain>.ecc.ca.cer` | ECC CA chain |
| `<domain>.rsa.cer` | RSA domain certificate (PEM) |
| `<domain>.rsa.key` | RSA private key (**chmod 600**) |
| `<domain>.rsa.fullchain.cer` | RSA cert + intermediates |
| `<domain>.rsa.ca.cer` | RSA CA chain |

Private keys are never transmitted to CPPM directly. Each cert is converted to
an ephemeral PKCS12 file written to `/tmp` and deleted immediately after upload.

---

## Verifying the Certificates in CPPM

**In the CPPM Admin UI:**

- HTTPS cert: **Administration → Certificates → Server Certificate**
- RADIUS cert: **Administration → Certificates → Service Certificates → RADIUS**

**Via CLI:**

```bash
# Verify HTTPS cert
openssl s_client -connect cppm.example.com:443 \
    -servername cppm.example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates

# Check installed ECC flat file
openssl x509 -in /opt/cppm-certs/cppm.example.com.ecc.cer -noout -subject -dates

# Check installed RSA flat file
openssl x509 -in /opt/cppm-certs/cppm.example.com.rsa.cer -noout -subject -dates
```

---

## Maintenance

### View logs

```bash
# Quick status overview
cat /opt/cppm-certs/status.log
grep FAILED /opt/cppm-certs/status.log

# Detailed logs
tail -100 /opt/cppm-certs/.logs/startup.log
tail -100 /opt/cppm-certs/.logs/renewal.log
tail -100 /opt/cppm-certs/.logs/upload.log

# Docker container output
docker compose logs -f
```

### Force certificate re-issue

```bash
# Edit .env: FORCE_RENEW=true
docker compose up -d --force-recreate
# After completion, edit .env: FORCE_RENEW=false
docker compose up -d --force-recreate
```

### Re-upload to CPPM (cert unchanged)

```bash
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
```

### Switch DNS provider

Update `.env` with the new `DNS_PROVIDER` and its credentials, then recreate:

```bash
# Example: switch to Porkbun
# Edit .env:
#   DNS_PROVIDER=porkbun
#   PORKBUN_API_KEY=pk1_...
#   PORKBUN_SECRET_API_KEY=sk1_...
docker compose up -d --force-recreate
```

Existing certificates on the volume are unaffected — only new issuances and
renewals use the new provider.

### Enable SSL verification

After the Let's Encrypt cert is installed and trusted:

```bash
# Edit .env: CPPM_VERIFY_SSL=true
docker compose up -d --force-recreate
```

### Rebuild the image (cert data preserved)

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## Troubleshooting

### Container exits immediately

```bash
docker compose logs | grep -E "ERROR|Missing"
```

Check that `DNS_PROVIDER` is set and the required credentials for that provider
are present in `.env`.

### DNS-01 challenge fails

**Cloudflare:** verify the token has `Zone:DNS:Edit` on the correct zone.

```bash
# Test Cloudflare token
docker exec -it cppm-cert-manager sh -c '
    curl -s -H "Authorization: Bearer $CF_Token" \
    "https://api.cloudflare.com/client/v4/zones/$CF_Zone_ID" \
    | python3 -m json.tool | grep '"'"'name\|success'"'"'
'
```

**Porkbun:** ensure API access is enabled on the domain in the Porkbun dashboard.

**Route53:** verify the IAM policy includes `route53:GetChange` — without it
acme.sh cannot poll for propagation.

Check the full acme.sh output:
```bash
tail -100 /opt/cppm-certs/.logs/renewal.log
```

### ClearPass API authentication fails (400 invalid_client)

```bash
docker exec -it cppm-cert-manager python3 -c "
import os, requests
r = requests.post(
    'https://' + os.environ['CPPM_HOST'] + '/api/oauth',
    json={
        'grant_type':    'client_credentials',
        'client_id':     os.environ['CPPM_CLIENT_ID'],
        'client_secret': os.environ['CPPM_CLIENT_SECRET'],
    },
    verify=False,
)
print(r.status_code, r.json())
"
```

Common causes: wrong `CPPM_CLIENT_SECRET`, API client disabled, grant type not
set to `client_credentials`.

### HTTPS/RADIUS upload fails — 422 "Cert File is empty"

CPPM tried to fetch the PKCS12 from `CPPM_CALLBACK_HOST` but could not reach it.

1. Verify `CPPM_CALLBACK_HOST` is the Docker **host** LAN IP (not the container IP):
   ```bash
   ip route get <cppm-ip>   # look for 'src X.X.X.X'
   ```
2. Verify the port is published in `docker-compose.yml`:
   ```yaml
   ports:
     - "8765:8765"
   ```
3. Verify CPPM can reach the host on that port (no firewall blocking it).

### EAP authentication fails after cert install

A Let's Encrypt CA cert is missing from the CPPM trust list with EAP enabled.
Force a re-run of the trust list pre-flight:

```bash
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
tail -f /opt/cppm-certs/status.log
```

If entries still fail, add them manually:
**Administration → Certificates → Trust List → Import** — enable **EAP** and
**Others** for each entry.

### Let's Encrypt rate limit

Switch to staging for testing:
```bash
# Edit .env: ACME_SERVER=letsencrypt_test
docker compose up -d --force-recreate
```

Switch back to `letsencrypt` and wait 7 days before re-issuing if rate-limited.

---

## Security Considerations

| Item | Recommendation |
|---|---|
| `.env` permissions | `chmod 600 .env` — readable by root only |
| `/opt/cppm-certs` permissions | `chmod 750` |
| Private keys | Never leave the host; PKCS12 export is ephemeral in `/tmp` |
| `CPPM_CERT_PASSPHRASE` | Change from default; used transiently only |
| `CPPM_VERIFY_SSL` | Set `true` after initial cert install |
| API client scope | Use a dedicated Operator Profile with Certificate Management only |
| Cloudflare token scope | Restrict to the specific zone, `DNS:Edit` only |
| Other DNS providers | Apply least-privilege: zone-specific where supported |
| Secrets in Docker | Managed via `.env`; never hard-coded in `Dockerfile` |

---

## ClearPass API Reference

All API calls use the **official pyclearpass SDK** (`pip install pyclearpass`).

Source: https://github.com/aruba/pyclearpass

Interactive Swagger UI on your CPPM instance:
```
https://cppm.example.com/api-docs/
```

### Endpoints used

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/oauth` | OAuth2 token exchange |
| `GET` | `/api/cert-trust-list` | Fetch trust list entries |
| `POST` | `/api/cert-trust-list` | Add LE CA cert to trust list |
| `PATCH` | `/api/cert-trust-list/{id}` | Patch trust list flags |
| `GET` | `/api/cluster/server/publisher` | Get publisher server UUID |
| `GET` | `/api/server-cert` | List server cert slots |
| `PUT` | `/api/server-cert/name/{uuid}/HTTPS(ECC)` | Upload ECC cert |
| `PUT` | `/api/server-cert/name/{uuid}/RADIUS` | Upload RSA cert |

### Known service_id values

| service_id | service_name |
|---|---|
| 1 | RADIUS |
| 2 | HTTPS(ECC) |
| 7 | HTTPS(RSA) |
| 21 | RadSec |
| 106 | Database |

### Trust list cert_usage values

Valid strings per CPPM API docs:
`"AD/LDAP Servers"`, `"Aruba Infrastructure"`, `"Aruba Services"`,
`"Database"`, `"EAP"`, `"Endpoint Context Servers"`, `"RadSec"`,
`"SAML"`, `"SMTP"`, `"EST"`, `"Others"`

This project sets `["EAP", "Others"]` for all Let's Encrypt CA entries.
