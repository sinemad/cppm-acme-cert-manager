# Quick Reference

## Setup (run once)

```bash
./setup.sh                           # create /opt/cppm-certs, copy .env.example
nano .env                            # set DNS_PROVIDER + credentials + CPPM settings
docker compose build --no-cache      # build image (downloads acme.sh + LE certs)
docker compose up -d                 # start container
docker compose logs -f               # watch first-run progress

# Open http://<docker-host>:8080/setup in a browser to create the admin account
# Then go to Servers → Add Server to register your ClearPass server
```

---

## Daily operations

```bash
# Web dashboard — easiest way to check status (open in browser)
# http://<docker-host>:8080/

# Check current status (CLI)
cat /opt/cppm-certs/status.log

# Check cert expiry (ECC and RSA)
openssl x509 -in /opt/cppm-certs/cppm.example.com.ecc.cer -noout -dates
openssl x509 -in /opt/cppm-certs/cppm.example.com.rsa.cer -noout -dates

# View live logs
docker compose logs -f

# Container health
docker compose ps
```

---

## Web UI

```bash
# Dashboard (public by default)
# http://<docker-host>:8080/

# First-time admin setup wizard
# http://<docker-host>:8080/setup

# Sign in
# http://<docker-host>:8080/login

# Servers — manage ClearPass server entries (sign-in required)
# http://<docker-host>:8080/settings

# Admin user management (sign-in required)
# http://<docker-host>:8080/admin/users
```

---

## Server management (CLI)

```bash
# List all configured servers (shows IDs needed for other commands)
docker exec -it cppm-acme-cert-manager cppm-servers list

# Add a new server (interactive prompts)
docker exec -it cppm-acme-cert-manager cppm-servers add

# Show full configuration for a server
docker exec -it cppm-acme-cert-manager cppm-servers show <id>

# Edit an existing server
docker exec -it cppm-acme-cert-manager cppm-servers edit <id>

# Delete a server
docker exec -it cppm-acme-cert-manager cppm-servers delete <id>
```

---

## Admin user management (CLI)

```bash
# Create first admin account (also works for subsequent accounts)
docker exec -it cppm-acme-cert-manager cppm-users add <username>

# Change a password
docker exec -it cppm-acme-cert-manager cppm-users passwd <username>

# Delete a user
docker exec -it cppm-acme-cert-manager cppm-users delete <username>

# List all users
docker exec -it cppm-acme-cert-manager cppm-users list
```

---

## Maintenance commands

```bash
# Rebuild image (cert data preserved)
docker compose down
docker compose build --no-cache
docker compose up -d

# Update credentials (.env changed)
docker compose up -d --force-recreate

# Re-upload cert to CPPM (certs unchanged)
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh

# Install flat files from acme.sh state (no re-issue)
docker exec -it cppm-acme-cert-manager /opt/cppm/install_cert.sh

# Run trust list check manually (verify/upload CA certs, no cert renewal)
docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh

# Edit trust list exclusions (takes effect at next check, no restart needed)
nano /opt/cppm-certs/trust-exclusions.conf

# Force full certificate re-issue
# Edit .env: FORCE_RENEW=true
docker compose up -d --force-recreate
# Edit .env: FORCE_RENEW=false
docker compose up -d --force-recreate

# View the full cron schedule (renewal + trust check)
docker exec -it cppm-acme-cert-manager cat /etc/crontabs/root

# Check active DNS provider
docker exec -it cppm-acme-cert-manager sh -c 'echo "DNS_PROVIDER=${DNS_PROVIDER}"'

# List certs known to acme.sh
docker exec -it cppm-acme-cert-manager acme.sh --list

# Shell into container
docker exec -it cppm-acme-cert-manager bash
```

---

## Log locations and persistent files

| What | Where |
|---|---|
| Web dashboard | `http://<docker-host>:8080/` |
| Status summary | `/opt/cppm-certs/status.log` |
| Startup detail | `/opt/cppm-certs/.logs/startup.log` |
| Renewal detail | `/opt/cppm-certs/.logs/renewal.log` |
| Upload + trust check detail | `/opt/cppm-certs/.logs/upload.log` |
| Cron log | `/opt/cppm-certs/.logs/cron.log` |
| Dashboard log | `/opt/cppm-certs/.logs/status_server.log` |
| Trust exclusion config | `/opt/cppm-certs/trust-exclusions.conf` |
| ClearPass server config | `/opt/cppm-certs/servers.json` |
| Admin credentials | `/opt/cppm-certs/admin.htpasswd` |
| Session signing secret | `/opt/cppm-certs/.session-secret` |

---

## Scheduled tasks

All times are container-local (controlled by the `TZ` env var, default UTC).

| Schedule | Script | Action |
|---|---|---|
| 02:00 daily | `renew.sh` | Checks ECC + RSA cert expiry; renews if ≤30 days remain |
| 14:00 daily | `renew.sh` | Same as above |
| ~60 days after issue | *(automatic on renewal)* | Issues new certs → installs flat files → uploads to CPPM |
| Sunday 03:00 weekly | `trust_check.sh` | Verifies all LE CA certs in CPPM trust list; uploads any missing |
| On renewal | *(automatic)* | Full upload: trust check + HTTPS(ECC) cert + RADIUS cert |

---

## DNS provider quick switch

To change DNS provider, update `.env` and recreate the container. The existing
certificates on the volume are unaffected — only new issuances and renewals
use the new provider.

```bash
# Example: switch from Cloudflare to Porkbun
# Edit .env:
#   DNS_PROVIDER=porkbun
#   PORKBUN_API_KEY=pk1_...
#   PORKBUN_SECRET_API_KEY=sk1_...
docker compose up -d --force-recreate
```

---

## Troubleshooting shortcuts

```bash
# Show only failures in status log
grep FAILED /opt/cppm-certs/status.log

# Test ClearPass authentication (uses form-encoded POST per RFC 6749)
docker exec -it cppm-acme-cert-manager python3 -c "
import os, requests
r = requests.post(
    'https://' + os.environ['CPPM_HOST'] + '/api/oauth',
    data={
        'grant_type':    'client_credentials',
        'client_id':     os.environ['CPPM_CLIENT_ID'],
        'client_secret': os.environ['CPPM_CLIENT_SECRET'],
    },
    verify=False,
)
print(r.status_code, r.json())
"

# Verify ECC cert and key match
docker exec -it cppm-acme-cert-manager sh -c '
    CM=$(openssl x509 -noout -pubkey -in /data/certs/cppm.example.com.ecc.cer | sha256sum)
    KM=$(openssl pkey  -noout -pubout -in /data/certs/cppm.example.com.ecc.key | sha256sum)
    [ "$CM" = "$KM" ] && echo "ECC: MATCH" || echo "ECC: MISMATCH"
'

# Verify RSA cert and key match
docker exec -it cppm-acme-cert-manager sh -c '
    CM=$(openssl x509 -noout -pubkey -in /data/certs/cppm.example.com.rsa.cer | sha256sum)
    KM=$(openssl pkey  -noout -pubout -in /data/certs/cppm.example.com.rsa.key | sha256sum)
    [ "$CM" = "$KM" ] && echo "RSA: MATCH" || echo "RSA: MISMATCH"
'

# List acme.sh cert state (both ECC and RSA)
docker exec -it cppm-acme-cert-manager acme.sh --list
```
