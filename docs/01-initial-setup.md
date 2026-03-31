# Initial Setup

Run these steps once on the host before the container is ever started.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine ≥ 24.x | With Compose v2 plugin (`docker compose`) |
| Linux host | Ubuntu 22.04 LTS recommended |
| DNS | `cppm.sinemalab.com` managed by Cloudflare |
| CPPM version | 6.9.x through 6.12.x (confirmed on 6.11.13, SDK valid for all) |
| Outbound HTTPS | Container needs access to `api.cloudflare.com` and `cppm.sinemalab.com` |

---

## Step 1 – Prepare the host directory

```bash
cd /opt/cppm-cert-manager
chmod +x setup.sh && ./setup.sh
```

`setup.sh` does three things:
- Verifies Docker and the Compose plugin are present
- Creates `/opt/cppm-certs` (the persistent cert directory)
- Copies `.env.example` to `.env` if it does not already exist

---

## Step 2 – Create the Cloudflare API token

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. **Create Token → Custom token**
3. Configure:
   - **Token name:** `acme-cppm-dns`
   - **Permissions:** `Zone > DNS > Edit`
   - **Zone Resources:** `Include > Specific zone > sinemalab.com`
4. Copy the token and note your **Account ID** and **Zone ID**
   (both shown on the Overview page of your zone)

---

## Step 3 – Create the ClearPass API client

1. CPPM Admin UI → **Administration → API Services → API Clients → Add**
2. Configure:

   | Field | Value |
   |---|---|
   | Client ID | `cppm-cert-manager` |
   | Enabled | ✓ |
   | Operator Profile | `Super Administrator` (or custom — see note) |
   | Grant Types | `client_credentials` |
   | Access Token Lifetime | `28800` (8 hours) |

3. Click **Create Client** and **copy the client secret** — shown only once.

> **Minimum permissions for a custom Operator Profile:**
> Administration → Operator Logins → Operator Profiles → Add
> Enable **Allow → All → Certificate Management**

---

## Step 4 – Fill in `.env`

```bash
nano /opt/cppm-cert-manager/.env
```

Required values:

```ini
# Cloudflare
CF_Token=<your-scoped-api-token>
CF_Account_ID=<cloudflare-account-id>
CF_Zone_ID=<zone-id-for-sinemalab.com>

# ACME
ACME_EMAIL=admin@sinemalab.com
ACME_SERVER=letsencrypt

# Domain
DOMAIN=cppm.sinemalab.com

# ClearPass
CPPM_HOST=cppm.sinemalab.com
CPPM_CLIENT_ID=cppm-cert-manager
CPPM_CLIENT_SECRET=<secret-from-step-3>
CPPM_VERIFY_SSL=false       # set true after the cert is installed
```

Secure the file:

```bash
chmod 600 /opt/cppm-cert-manager/.env
```

---

## Step 5 – Build the image

```bash
docker compose build --no-cache
```

The build fetches acme.sh from GitHub and downloads all six Let's Encrypt
CA certificates from letsencrypt.org. Both are baked into the image so the
running container needs no access to either site at runtime.

Expected build time: 2–4 minutes depending on network speed.

---

## Step 6 – Start and verify

```bash
docker compose up -d
docker compose logs -f
```

Watch for these lines to confirm a successful first run:

```
[INFO ] No certificate found – starting first-time issuance
[ISSUE] Running acme.sh --issue ...
[OK   ] New certificate issued via Cloudflare DNS-01
[OK   ] Cert installed – expires <date>
[OK   ] HTTPS + RADIUS cert uploaded to cppm.sinemalab.com
[INFO ] crond started – renewal checks at 02:00 and 14:00 UTC
```

First-run time including DNS propagation: approximately 2–5 minutes.

---

## Step 7 – Enable SSL verification

Once the certificate is installed and you can confirm CPPM is accessible via
HTTPS with the new cert:

```bash
# Verify the cert is trusted
openssl s_client -connect cppm.sinemalab.com:443 -servername cppm.sinemalab.com \
    </dev/null 2>/dev/null | openssl x509 -noout -subject -dates

# Update .env
CPPM_VERIFY_SSL=true

# Recreate the container to pick up the change
docker compose up -d --force-recreate
```
