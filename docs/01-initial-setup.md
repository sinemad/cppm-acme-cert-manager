# Initial Setup

Run these steps once on the host before the container is ever started.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine ≥ 24.x | With Compose v2 plugin (`docker compose`) |
| Linux host | Ubuntu 22.04 LTS recommended |
| DNS provider | Domain managed by a supported provider (Cloudflare, Porkbun, Route53, DigitalOcean, or GoDaddy) |
| CPPM version | 6.9.x through 6.12.x (confirmed on 6.11.13, SDK valid for all) |
| Outbound HTTPS | Container needs access to your DNS provider's API and your ACME CA |

---

## Step 1 – Prepare the host directory

```bash
cd /opt/cppm-acme-cert-manager
chmod +x setup.sh && ./setup.sh
```

`setup.sh` does three things:
- Verifies Docker and the Compose plugin are present
- Creates `/opt/cppm-certs` (the persistent storage directory)
- Copies `docker-compose.override.yml.example` to `docker-compose.override.yml` if it does not already exist

---

## Step 2 – Configure local overrides (optional)

`docker-compose.override.yml` controls **container-level behaviour only** —
timezone, ports, and operational flags. ClearPass server credentials, DNS
provider, domain, and ACME settings are all configured through the web UI
after the container starts.

Docker Compose automatically merges `docker-compose.override.yml` with
`docker-compose.yml` — no flags or extra commands needed. Only uncomment and
change what you need; everything else uses the defaults from `docker-compose.yml`.

```bash
nano /opt/cppm-acme-cert-manager/docker-compose.override.yml
```

The most commonly changed value:

```yaml
environment:
  TZ: America/New_York    # container timezone for logs and cron (default: UTC)
```

Optional flags (uncomment to enable):

```yaml
  # FORCE_RENEW: "true"    # force certificate re-issuance on next container start
  # SKIP_UPLOAD: "true"    # issue/renew without uploading to ClearPass
  # LOG_LEVEL: DEBUG       # Python log verbosity for upload script
```

> **Changing a port requires updating two places** in the override file: the
> `environment` section (tells the app which port to listen on inside the
> container) and the `ports` section (tells Docker which host port to forward).
> The override template includes a step-by-step checklist for port changes.

> **What docker-compose.override.yml does NOT configure:** DNS provider
> credentials, ClearPass host/credentials, domain, ACME email, and ACME server
> are all managed through the web UI and stored in `/opt/cppm-certs/servers.json`.

---

## Step 3 – Create the ClearPass API client

1. CPPM Admin UI → **Administration → API Services → API Clients → Add**
2. Configure:

   | Field | Value |
   |---|---|
   | Client ID | `cppm-acme-cert-manager` |
   | Enabled | ✓ |
   | Operator Profile | `Super Administrator` (or custom — see note) |
   | Grant Types | `client_credentials` |
   | Access Token Lifetime | `28800` (8 hours) |

3. Click **Create Client** and **copy the client secret** — shown only once.

> **Minimum permissions for a custom Operator Profile:**
> Administration → Operator Logins → Operator Profiles → Add
> Enable **Allow → All → Certificate Management**

---

## Step 4 – Build the image

```bash
docker compose build --no-cache
```

The build downloads the Lego binary from GitHub and CA certificates from supported ACME providers. Both are baked into the image so the running container needs no access to either site at runtime.

Expected build time: 2–4 minutes depending on network speed.

---

## Step 5 – Start the container

```bash
docker compose up -d
docker compose logs -f
```

Watch for:
```
[INFO ] Starting status web server on port 8080
[INFO ] Starting supercronic
[INFO ] Startup complete
```

If `servers.json` is empty (first run) you will also see:
```
[WARN ] No servers configured.
[WARN ]   Add one via the web UI after startup: http://<host>:8080/settings
```

This is expected — the container stays running and waits for you to add a server.

---

## Step 6 – Web UI first-time setup

Open a browser to `http://<docker-host>:8080/`. On first access the navigation
bar shows a **Setup** link because no admin accounts exist yet.

1. Click **Setup** (or navigate to `http://<docker-host>:8080/setup`).
2. Enter a username and a password of at least 8 characters.
3. Click **Create Admin Account** — you will be redirected to the sign-in page.
4. Sign in with the credentials you just created.

Once signed in you will see the full navigation bar:
**Dashboard · Servers · Users · Sign Out**

### CLI alternative (no browser needed)

```bash
docker exec -it cppm-acme-cert-manager cppm-users add admin
```

---

## Step 7 – Add your ClearPass server

All ClearPass server configuration — credentials, DNS provider, domain, and ACME settings — is entered through the web UI and stored in `servers.json`.

1. Click **Servers** in the navigation bar.
2. Click **+ Add Server**.
3. Fill in all sections:

| Section | Fields |
|---|---|
| **Identity** | Friendly label (e.g. `Production ClearPass`) |
| **ClearPass** | Host/IP, Client ID, Client Secret (from Step 3), Cert Passphrase, Callback Host, Callback Port, Verify SSL |
| **Domain & ACME** | Domain (e.g. `cppm.example.com`), ACME email, Certificate Authority |
| **DNS Provider** | Provider selector + credentials (see below) |

4. Click **Add Server** to save.

The configuration is stored in `/opt/cppm-certs/servers.json` (chmod 600).

### DNS provider credential reference

| Provider | Required credentials |
|---|---|
| **Cloudflare** | API Token + Zone ID (recommended), or Global API Key + Email |
| **Porkbun** | API Key + Secret API Key |
| **AWS Route 53** | Access Key ID + Secret Access Key + Region |
| **DigitalOcean** | API Token |
| **GoDaddy** | API Key + API Secret |

#### Obtaining Cloudflare credentials

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. **Create Token → Custom token**
3. Configure:
   - **Token name:** `acme-cppm-dns`
   - **Permissions:** `Zone > DNS > Edit`
   - **Zone Resources:** `Include > Specific zone > example.com`
4. Copy the token; find your **Account ID** and **Zone ID** on the zone Overview page.

#### Obtaining Porkbun credentials

1. Log in to [Porkbun](https://porkbun.com/account/api) and enable API access.
2. Ensure **API access** is enabled on the domain under Domain Management.

#### Obtaining Route53 credentials

Create an IAM user with this inline policy, then generate access keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["route53:ChangeResourceRecordSets","route53:ListHostedZones",
               "route53:GetChange","route53:ListResourceRecordSets"],
    "Resource": "*"
  }]
}
```

#### Obtaining DigitalOcean credentials

Generate a **Personal Access Token** with **Write** scope at
[cloud.digitalocean.com/account/api/tokens](https://cloud.digitalocean.com/account/api/tokens).

#### Obtaining GoDaddy credentials

Create a Production API key at the
[GoDaddy Developer Portal](https://developer.godaddy.com/keys).

#### Other / custom providers

The five providers listed above are natively supported. For other DNS providers,
refer to the [Lego DNS provider documentation](https://go-acme.github.io/lego/dns/)
for supported providers and their required environment variable names.

### CLI alternative (no browser needed)

```bash
docker exec -it cppm-acme-cert-manager cppm-servers add
```

Once the first server is saved the container picks it up on the **next startup**.
Restart to trigger first-run certificate issuance:

```bash
docker compose restart
docker compose logs -f
```

Watch for:
```
[INFO ] No certificates found – starting first-time issuance
[ISSUE] Issuing ECC (ec-256) certificate via <provider> DNS-01
[ISSUE] Issuing RSA (2048) certificate via <provider> DNS-01
[OK   ] ECC+RSA certificates issued
[OK   ] ECC+RSA certs installed – expires <date>
[OK   ] ECC→HTTPS + RSA→RADIUS uploaded to cppm.example.com
```

First-run time including DNS propagation: approximately 2–5 minutes.

---

## Step 8 – Enable SSL verification

Once the certificate is installed and CPPM is accessible via HTTPS with the
new cert:

```bash
# Verify the cert is trusted
openssl s_client -connect cppm.example.com:443 -servername cppm.example.com \
    </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

Then edit the server entry in the web UI:
**Servers → Edit → Verify SSL → enable → Save Changes**

Or via CLI:
```bash
docker exec -it cppm-acme-cert-manager cppm-servers edit <id>
# Toggle Verify SSL to yes
```
