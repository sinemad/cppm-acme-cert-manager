# Initial Setup

Run these steps once on the host before the container is ever started.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine ≥ 24.x | With Compose v2 plugin (`docker compose`) |
| Linux host | Ubuntu 22.04 LTS recommended |
| DNS provider | Domain managed by a supported provider (Cloudflare, Porkbun, Route53, DigitalOcean, GoDaddy, or any acme.sh dnsapi plugin) |
| CPPM version | 6.9.x through 6.12.x (confirmed on 6.11.13, SDK valid for all) |
| Outbound HTTPS | Container needs access to your DNS provider's API and `cppm.example.com` |

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

## Step 2 – Create DNS provider credentials

The container uses the ACME DNS-01 challenge to issue certificates.
Set `DNS_PROVIDER` in `.env` to your provider, then create the required credentials.

### Cloudflare (default)

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. **Create Token → Custom token**
3. Configure:
   - **Token name:** `acme-cppm-dns`
   - **Permissions:** `Zone > DNS > Edit`
   - **Zone Resources:** `Include > Specific zone > example.com`
4. Copy the token and note your **Account ID** and **Zone ID**
   (both shown on the Overview page of your zone)

```ini
DNS_PROVIDER=cloudflare
CF_Token=<your-scoped-api-token>
CF_Account_ID=<account-id>
CF_Zone_ID=<zone-id>
```

### Porkbun

1. Log in to [Porkbun](https://porkbun.com/account/api)
2. Enable API access and create an API key pair
3. Ensure **API access** is enabled on the domain under Domain Management

```ini
DNS_PROVIDER=porkbun
PORKBUN_API_KEY=pk1_...
PORKBUN_SECRET_API_KEY=sk1_...
```

### Route53 / AWS

Create an IAM user with the following inline policy, then generate access keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["route53:ChangeResourceRecordSets", "route53:ListHostedZones",
                 "route53:GetChange", "route53:ListResourceRecordSets"],
      "Resource": "*"
    }
  ]
}
```

```ini
DNS_PROVIDER=route53
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
```

### DigitalOcean

1. Log in to [DigitalOcean](https://cloud.digitalocean.com/account/api/tokens)
2. Generate a **Personal Access Token** with **Write** scope

```ini
DNS_PROVIDER=digitalocean
DO_API_KEY=dop_v1_...
```

### GoDaddy

1. Log in to [GoDaddy Developer Portal](https://developer.godaddy.com/keys)
2. Create a Production API key

```ini
DNS_PROVIDER=godaddy
GD_Key=...
GD_Secret=...
```

### Other providers

Any acme.sh dnsapi plugin can be used. Set `DNS_PROVIDER` to the plugin name
without the `dns_` prefix and ensure the plugin's credential variables are set
in `.env`. For example:

```ini
DNS_PROVIDER=linode_v4
LINODE_V4_API_KEY=...
```

See the [acme.sh dnsapi docs](https://github.com/acmesh-official/acme.sh/wiki/dnsapi)
for the full list of supported providers and their variable names.

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

Required values (example using Cloudflare):

```ini
# DNS provider
DNS_PROVIDER=cloudflare
CF_Token=<your-scoped-api-token>
CF_Account_ID=<cloudflare-account-id>
CF_Zone_ID=<zone-id-for-example.com>

# ACME
ACME_EMAIL=admin@example.com
ACME_SERVER=letsencrypt

# Domain
DOMAIN=cppm.example.com

# ClearPass
CPPM_HOST=cppm.example.com
CPPM_CLIENT_ID=cppm-cert-manager
CPPM_CLIENT_SECRET=<secret-from-step-3>
CPPM_VERIFY_SSL=false       # set true after the cert is installed

# Callback – Docker host LAN IP that CPPM can route to
CPPM_CALLBACK_HOST=<docker-host-ip>
CPPM_CALLBACK_PORT=8765
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

The build fetches acme.sh from GitHub and downloads all Let's Encrypt
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
[INFO ] No certificates found – starting first-time issuance
[ISSUE] Issuing ECC (ec-256) certificate via <provider> DNS-01
[ISSUE] Issuing RSA (2048) certificate via <provider> DNS-01
[OK   ] ECC+RSA certificates issued
[OK   ] ECC+RSA certs installed – expires <date>
[OK   ] ECC→HTTPS + RSA→RADIUS uploaded to cppm.example.com
[INFO ] supercronic started – renewal checks at 02:00 and 14:00 UTC
```

First-run time including DNS propagation: approximately 2–5 minutes.

---

## Step 7 – Enable SSL verification

Once the certificate is installed and CPPM is accessible via HTTPS with the
new cert:

```bash
# Verify the cert is trusted
openssl s_client -connect cppm.example.com:443 -servername cppm.example.com \
    </dev/null 2>/dev/null | openssl x509 -noout -subject -dates

# Update .env
CPPM_VERIFY_SSL=true

# Recreate the container to pick up the change
docker compose up -d --force-recreate
```
