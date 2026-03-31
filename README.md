# ClearPass ACME Certificate Manager

Automated TLS certificate issuance and renewal for **Aruba ClearPass Policy Manager (CPPM)**
using [acme.sh](https://github.com/acmesh-official/acme.sh) and Cloudflare DNS-01 challenge.
Everything runs in a self-contained Alpine Linux Docker container with persistent storage
on the host.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ClearPass Cert Manager Flow                          │
│                                                                             │
│  ┌───────────┐    DNS-01     ┌───────────────┐    Upload cert   ┌────────┐  │
│  │ acme.sh   │◄─────────────►│  Cloudflare   │                  │ CPPM   │  │
│  │  (cron)   │               │  DNS API      │                  │ HTTPS  │  │
│  └─────┬─────┘               └───────────────┘                  │ RADIUS │  │
│        │ cert issued/renewed                                     └────────┘  │
│        ▼                                                              ▲      │
│  ┌─────────────┐   PKCS12 + API   ┌───────────────────────────────────┐     │
│  │ deploy_hook │─────────────────►│  clearpass_upload.py              │     │
│  │   .sh       │                  │  POST /api/server-certificate      │     │
│  └─────────────┘                  │  POST /api/radius/service-cert     │     │
│                                   └───────────────────────────────────┘     │
│                                                                             │
│  Persistent Storage: /opt/cppm-data (host) ◄──── /data (container)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Directory Structure](#directory-structure)
3. [Initial Setup](#initial-setup)
   - [Host Preparation](#1-host-preparation)
   - [Cloudflare API Token](#2-cloudflare-api-token)
   - [ClearPass API Client](#3-clearpass-api-client)
   - [Configure Environment](#4-configure-environment)
   - [Build and Start](#5-build-and-start)
4. [How It Works](#how-it-works)
5. [Certificate Files](#certificate-files)
6. [Verifying the Certificate in CPPM](#verifying-the-certificate-in-cppm)
7. [Maintenance](#maintenance)
   - [View Logs](#view-logs)
   - [Force Manual Renewal](#force-manual-renewal)
   - [Update Credentials](#update-credentials)
   - [Rebuilding the Container](#rebuilding-the-container)
8. [Troubleshooting](#troubleshooting)
9. [Security Considerations](#security-considerations)
10. [ClearPass API Reference](#clearpass-api-reference)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine ≥ 24.x | With Compose v2 plugin (`docker compose`) |
| Host OS | Any Linux with Docker support (Ubuntu 22.04 LTS recommended) |
| DNS | A domain managed by Cloudflare |
| CPPM version | 6.9.x or 6.11.x (6.8.x requires endpoint adjustment; see [API Reference](#clearpass-api-reference)) |
| Network | Container needs outbound HTTPS to `api.cloudflare.com` and the clearpass server |

---

## Directory Structure

```
cppm-cert-manager/
├── Dockerfile                  # Alpine + acme.sh + Python image
├── docker-compose.yml          # Service definition + volume mapping
├── .env.example                # Copy to .env and fill in secrets
├── config/
│   └── crontab                 # Renewal schedule (runs inside container)
├── scripts/
│   ├── entrypoint.sh           # Container startup: validates env, issues cert, starts cron
│   ├── issue_cert.sh           # One-time cert issuance via Cloudflare DNS-01
│   ├── renew.sh                # Called by cron – runs acme.sh --renew
│   ├── deploy_hook.sh          # Called by acme.sh on successful renewal
│   └── clearpass_upload.py     # Pushes cert to CPPM via REST API
└── README.md                   # This file
```

**Host persistent storage (survives container rebuilds):**
```
NOTE: cppm.sinemalab.com is an example domain
```
```
/opt/cppm-data/                 # Host directory (bind-mounted to /data in container)
├── acme.sh/                    # acme.sh account keys, cert metadata, CA cache
│   ├── ca/                     # ACME CA trust store
│   ├── cppm.sinemalab.com/     # Domain-specific cert state managed by acme.sh
│   └── account.conf            # Registered ACME account (email, EAB if used)
├── certs/                      # Flat certificate files for easy access
│   ├── cppm.sinemalab.com.cer          # Domain certificate (PEM)
│   ├── cppm.sinemalab.com.key          # Private key (PEM, chmod 600)
│   ├── cppm.sinemalab.com.fullchain.cer # Cert + intermediates (PEM)
│   └── cppm.sinemalab.com.ca.cer       # Issuer CA chain (PEM)
└── logs/
    ├── startup.log             # Container start events
    ├── renewal.log             # acme.sh issuance/renewal output
    ├── upload.log              # ClearPass API upload results
    ├── last_upload.txt         # Timestamp of last successful upload
    └── cron.log                # crond daemon log
```

---

## Initial Setup

### 1. Host Preparation

```bash
# Create the persistent data directory
sudo mkdir -p /opt/cppm-data
sudo chown root:root /opt/cppm-data
sudo chmod 750 /opt/cppm-data

# Clone or copy the project files
cd /opt
git clone <your-repo-url> cppm-cert-manager
# -- OR --
# copy files manually, then:
cd /opt/cppm-cert-manager
```

### 2. Cloudflare API Token

Create a **scoped API token** (preferred over the global API key):

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token** → **Custom token**
3. Set:
   - **Token name:** `acme-cppm-dns`
   - **Permissions:** `Zone` → `DNS` → `Edit`
   - **Zone Resources:** `Include` → `Specific zone` → `sinemalab.com`
4. Copy the token and note your **Account ID** and **Zone ID**
   (both are visible on the Overview page of your zone in the Cloudflare dashboard)

### 3. ClearPass API Client

Create a dedicated API client in CPPM:

1. Log in to CPPM Admin UI → **Administration → API Services → API Clients**
2. Click **Add API Client**
3. Configure:
   | Field | Value |
   |---|---|
   | Client ID | `cppm-cert-manager` |
   | Enabled | ✓ |
   | Operator Profile | `Super Administrator` (or a custom profile — see note below) |
   | Grant Types | `client_credentials` |
   | Access Token Lifetime | `28800` (8 hours) |
4. Click **Create Client** and **copy the client secret** — it is shown only once.

> **Minimum permissions for a custom Operator Profile:**
> The API client needs write access to *Server Certificates* only.
> Create a custom profile under **Administration → Operator Logins → Operator Profiles**
> with **Allow → All → Certificate Management** enabled.

### 4. Configure Environment

```bash
cp .env.example .env
chmod 600 .env       # Restrict read access to root only
nano .env            # Fill in all values
```

Key values to set:
```
NOTE: cppm.sinemalab.com is an example domain, replace with your domain information
```
```ini
# Cloudflare
CF_Token=<your-scoped-api-token>
CF_Account_ID=<cloudflare-account-id>
CF_Zone_ID=<zone-id-for-sinemalab.com>

# ACME
ACME_EMAIL=admin@sinemalab.com

# ClearPass
CPPM_HOST=cppm.sinemalab.com
CPPM_CLIENT_ID=cppm-cert-manager
CPPM_CLIENT_SECRET=<secret-from-step-3>
CPPM_VERIFY_SSL=false   # ← change to true after cert is installed
```

### 5. Build and Start

```bash
# Build the image
docker compose build

# Start (runs in background, issues cert on first start)
docker compose up -d

# Watch startup logs (Ctrl-C to stop watching, container keeps running)
docker compose logs -f

# Or watch the startup log file directly:
tail -f /opt/cppm-data/logs/startup.log
```

**What happens on first start:**

1. Environment variables are validated
2. `acme.sh` state is linked to `/data/acme.sh` (persistent)
3. Certificate is issued via Cloudflare DNS-01
4. Cert files are written to `/opt/cppm-data/certs/`
5. `deploy_hook.sh` is called → `clearpass_upload.py` runs → cert uploaded to CPPM
6. `crond` starts and runs the renewal schedule

**Expected first-start time:** 2–5 minutes (DNS propagation for the ACME challenge).

---

## How It Works

### Certificate Issuance (first run)

```
entrypoint.sh
    └─► issue_cert.sh
            ├─ acme.sh --issue --dns dns_cf      (Cloudflare DNS-01 challenge)
            ├─ acme.sh --install-cert            (copies flat files to /data/certs/)
            └─ deploy_hook.sh
                    └─ clearpass_upload.py
                            │
                            ├─ Step 0: Let's Encrypt Trust List Pre-flight
                            │     ├─ Parse .ca.cer  → individual intermediate PEMs
                            │     ├─ Download from letsencrypt.org:
                            │     │     ISRG Root X1 (RSA root)
                            │     │     ISRG Root X2 (ECDSA root)
                            │     │     R10, R11     (RSA intermediates)
                            │     │     E5, E6       (ECDSA intermediates)
                            │     ├─ GET  /api/certificate/trust-list
                            │     ├─ Compare SHA-256 fingerprints
                            │     ├─ POST /api/certificate/trust-list  (upload missing)
                            │     │       enable_for_eap    = true
                            │     │       enable_for_others = true
                            │     └─ PATCH /api/certificate/trust-list/{id}
                            │             (if present but flags are disabled)
                            │
                            ├─ Step 1: openssl pkcs12 -export (PEM -> PKCS12)
                            │          POST /api/server-certificate  (HTTPS cert)
                            │
                            ├─ Step 2: POST /api/radius/service-certificate
                            │
                            └─ Step 3: GET  /api/server-certificate (verify)
```

### Automatic Renewal (cron)

```
crond (02:00 and 14:00 UTC)
    └─► renew.sh
            └─ acme.sh --renew
                    ├─ [cert not yet due] → exits 2, nothing happens
                    └─ [cert within 30 days of expiry]
                            ├─ renews via Cloudflare DNS-01
                            ├─ acme.sh --install-cert (updates flat files)
                            └─ --reloadcmd → deploy_hook.sh → clearpass_upload.py
```

Let's Encrypt certificates are valid for **90 days**. acme.sh renews when
**≤30 days** remain. In normal operation this happens automatically ~60 days
after issuance.

---

## Certificate Files

After successful issuance, these files appear at `/opt/cppm-data/certs/`:

| File | Contents | Use |
|---|---|---|
| `cppm.sinemalab.com.cer` | Domain certificate (leaf) | Verification |
| `cppm.sinemalab.com.key` | Private key (**chmod 600**) | Never leave this host |
| `cppm.sinemalab.com.fullchain.cer` | Leaf + intermediate CA | Used for PKCS12 export to CPPM |
| `cppm.sinemalab.com.ca.cer` | Issuer CA chain only | Trust anchor |

> **Security:** The private key is never transmitted to CPPM directly.  
> It is bundled into an ephemeral PKCS12 file (written to `/tmp`, deleted immediately
> after upload) along with the passphrase in `CPPM_CERT_PASSPHRASE`.

---

## Verifying the Certificate in CPPM

After the upload script runs, verify in the CPPM Admin UI:

**HTTPS certificate:**
> Administration → Certificates → Server Certificate

**RADIUS certificate:**
> Administration → Certificates → Service Certificates → RADIUS

You should see the new Let's Encrypt certificate with the correct expiry date.

To verify via CLI from your workstation:

```bash
# Check HTTPS cert
openssl s_client -connect cppm.sinemalab.com:443 -servername cppm.sinemalab.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates

# Check RADIUS EAP cert (requires radtest or eapol_test)
openssl s_client -connect cppm.sinemalab.com:1812 -starttls radius </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -dates
```

---

## Maintenance

### View Logs

```bash
# Container startup / first-run log
tail -100 /opt/cppm-data/logs/startup.log

# Renewal cron log (daily acme.sh output)
tail -100 /opt/cppm-data/logs/renewal.log

# ClearPass API upload log
tail -100 /opt/cppm-data/logs/upload.log

# When was the last successful upload?
cat /opt/cppm-data/logs/last_upload.txt

# Docker container logs (crond + any stdout)
docker compose logs --tail=100

# Live tail all logs
docker compose logs -f
```

### Force Manual Renewal

Use this if you need to rotate the certificate before expiry (e.g., after a
CPPM migration):

```bash
# Method 1: Environment flag (preferred – uses existing container)
docker compose stop
FORCE_RENEW=true docker compose up -d
docker compose logs -f

# After the cert is issued, reset the flag:
# Edit .env → FORCE_RENEW=false → docker compose up -d

# Method 2: exec into the container
docker exec -it cppm-cert-manager /opt/cppm/issue_cert.sh
```

### Manually Trigger Upload Only

If the cert is already up-to-date but you need to re-upload to CPPM
(e.g., after a CPPM rebuild):

```bash
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
```

### Update Credentials

If you rotate the CPPM API secret or Cloudflare token:

```bash
# 1. Update .env
nano /opt/cppm-cert-manager/.env

# 2. Recreate the container to pick up new env vars
docker compose up -d --force-recreate
```

### Enable SSL Verification

After the Let's Encrypt certificate is installed and trusted by your workstation:

```bash
# 1. Update .env
CPPM_VERIFY_SSL=true

# 2. Recreate container
docker compose up -d --force-recreate
```

### Rebuilding the Container

Safe to do at any time – the certificate state lives on the host volume:

```bash
docker compose build --no-cache
docker compose up -d
# All certs, acme.sh state, and logs are preserved in /opt/cppm-data/
```

### Checking Certificate Expiry

```bash
openssl x509 -in /opt/cppm-data/certs/cppm.sinemalab.com.cer \
    -noout -subject -issuer -dates
```

---

## Troubleshooting

### Container exits immediately

Check environment variables:
```bash
docker compose logs
# Look for: [ERROR] Required environment variable not set: ...
```

### DNS-01 challenge fails

```bash
# Verify Cloudflare credentials
docker exec -it cppm-cert-manager sh -c '
    curl -s -H "Authorization: Bearer $CF_Token" \
    "https://api.cloudflare.com/client/v4/zones/$CF_Zone_ID/dns_records" \
    | python3 -m json.tool | head -20
'

# Common causes:
# - CF_Token doesn't have Zone:DNS:Edit on sinemalab.com
# - CF_Zone_ID is wrong (must be for sinemalab.com, not the account root)
# - DNS propagation too slow (rare with Cloudflare)
```

### CPPM API returns 401 Unauthorized

```bash
# Test authentication directly
docker exec -it cppm-cert-manager python3 - <<'EOF'
import requests, os
r = requests.post(
    f"https://{os.environ['CPPM_HOST']}/api/oauth",
    json={
        "grant_type": "client_credentials",
        "client_id": os.environ["CPPM_CLIENT_ID"],
        "client_secret": os.environ["CPPM_CLIENT_SECRET"],
    },
    verify=False,
)
print(r.status_code, r.json())
EOF

# Common causes:
# - CPPM_CLIENT_SECRET is wrong (re-check in CPPM Admin UI)
# - API Client is disabled in CPPM
# - API Client grant type is not set to client_credentials
```

### CPPM API returns 404 on certificate endpoint

Your CPPM version may use a different endpoint path. Check the Swagger UI:

```
https://cppm.sinemalab.com/api-docs/
```

Search for "certificate" in the Swagger UI and identify the correct
`POST` endpoint. Then update `clearpass_upload.py` → `upload_https_certificate()`
method, `endpoints` list.

### CPPM API returns 403 Forbidden

The API client's Operator Profile lacks certificate write permission.
In CPPM Admin UI, verify the profile attached to your API client includes:
> **Allow** → **All** → **Certificate Management**

### Trust list upload returns 400 / cert not appearing in UI

CPPM validates that the uploaded PEM is a CA certificate (Basic Constraints: CA=TRUE).
Let's Encrypt end-entity certs will be rejected — only roots and intermediates are valid.
This is expected behaviour; the script only submits CA-type certs.

If a specific cert fails and you need to add it manually:
1. Download from letsencrypt.org (URLs in `clearpass_upload.py → LE_CERT_SOURCES`)
2. CPPM Admin UI → **Administration → Certificates → Trust List → Import**
3. Select the PEM file
4. Enable **EAP** and **Others** checkboxes
5. Click **Save**

### EAP authentication fails after cert install

This almost always means the LE intermediate or root is not in the trust list with
EAP enabled.  Force a re-run of Step 0 only:

```bash
docker exec -it cppm-cert-manager python3 /opt/cppm/clearpass_upload.py \
    --cert      /data/certs/cppm.sinemalab.com.cer \
    --key       /data/certs/cppm.sinemalab.com.key \
    --fullchain /data/certs/cppm.sinemalab.com.fullchain.cer \
    --ca        /data/certs/cppm.sinemalab.com.ca.cer \
    --skip-radius
```

Then check the upload log:
```bash
tail -50 /opt/cppm-data/logs/upload.log
```

### acme.sh rate limit error

Let's Encrypt limits: 5 duplicate certificate orders per week per domain.
If you're testing, switch to the staging CA:

```bash
# In .env:
ACME_SERVER=letsencrypt_test

# Rebuild container
docker compose up -d --force-recreate
```

Do not use staging certs in production – CPPM will reject them unless you
install the staging CA in CPPM's trust store.

### openssl pkcs12 error during upload

```bash
# Verify cert and key match
docker exec -it cppm-cert-manager sh -c '
    CERT_MD5=$(openssl x509 -noout -modulus -in /data/certs/cppm.sinemalab.com.cer | md5sum)
    KEY_MD5=$(openssl rsa -noout -modulus -in /data/certs/cppm.sinemalab.com.key | md5sum)
    echo "Cert modulus: $CERT_MD5"
    echo "Key modulus:  $KEY_MD5"
    [ "$CERT_MD5" = "$KEY_MD5" ] && echo "MATCH ✓" || echo "MISMATCH ✗ – re-issue cert"
'
```

---

## Security Considerations

| Item | Recommendation |
|---|---|
| `.env` file permissions | `chmod 600 .env` — readable only by root |
| `/opt/cppm-data` permissions | `chmod 750` — readable only by root and docker group |
| Private key | Never extracted from the container; PKCS12 is ephemeral (`/tmp`) |
| `CPPM_CERT_PASSPHRASE` | Change from default; used only transiently |
| `CPPM_VERIFY_SSL` | Set `true` after initial cert install |
| API Client scope | Create a dedicated CPPM Operator Profile with *only* cert write permissions |
| Cloudflare token scope | Restrict token to `sinemalab.com` zone only, `DNS:Edit` only |
| Container user | Runs as root (required by crond on Alpine); mitigated by no exposed ports |
| Secrets in Docker | Managed via `.env` file; do not hard-code in `Dockerfile` |

---

## ClearPass API Reference

### Authentication

```
POST https://cppm.sinemalab.com/api/oauth
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "cppm-cert-manager",
  "client_secret": "<secret>"
}

Response:
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 28800
}
```

### Server Certificate Upload (HTTPS + RADIUS)

```
POST https://cppm.sinemalab.com/api/server-certificate
Authorization: Bearer <token>
Content-Type: multipart/form-data

Fields:
  certificate_file  (binary .pfx / PKCS12)
  passphrase        (the export passphrase used by openssl)

Response 200/201:
{
  "id": <cert-id>,
  "subject": "CN=cppm.sinemalab.com",
  "issuer": "CN=R10, O=Let's Encrypt, ...",
  "valid_from": "...",
  "valid_until": "...",
  "status": "active"
}
```

### RADIUS Service Certificate (separate binding, 6.9+)

```
POST https://cppm.sinemalab.com/api/radius/service-certificate
Authorization: Bearer <token>
Content-Type: multipart/form-data

Fields:
  certificate_file  (binary .pfx / PKCS12)
  passphrase
```

### Endpoint Differences by CPPM Version

| CPPM Version | HTTPS Cert Endpoint | RADIUS Cert Endpoint |
|---|---|---|
| 6.8.x | `/api/certificate/service-cert` | Not separately configurable |
| 6.9.x | `/api/server-certificate` | `/api/radius/service-certificate` |
| 6.11.x | `/api/server-certificate` | `/api/radius/service-certificate` |

> The upload script tries both HTTPS endpoints automatically. For RADIUS,
> a 404 response is treated as "unified cert mode" and silently skipped.

### Browse Your Instance's API

Every CPPM instance exposes an interactive Swagger UI:

```
https://cppm.sinemalab.com/api-docs/
```

Use this to discover exact endpoint paths for your specific version.

---

## Quick Reference

```bash
# Start container
docker compose up -d

# Stop container
docker compose down

# View live logs
docker compose logs -f

# Force certificate re-issue
FORCE_RENEW=true docker compose up -d --force-recreate

# Manually re-upload cert to CPPM
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh

# Check cert expiry
openssl x509 -in /opt/cppm-data/certs/cppm.sinemalab.com.cer -noout -dates

# Shell into container
docker exec -it cppm-cert-manager bash

# View last upload time
cat /opt/cppm-data/logs/last_upload.txt

# Rebuild image (preserves all cert data)
docker compose build --no-cache && docker compose up -d
```
