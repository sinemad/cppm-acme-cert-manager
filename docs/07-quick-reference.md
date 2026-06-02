# Quick Reference

## Setup (run once)

```bash
./setup.sh                           # create /opt/cppm-certs, copy env-example → .env
nano .env                            # set TZ, STATUS_PORT, CPPM_CALLBACK_PORT (ports only)
docker compose build --no-cache      # build image (downloads acme.sh + ACME CA certs)
docker compose up -d                 # start container
docker compose logs -f               # watch startup

# 1. Open http://<docker-host>:8080/setup — create the admin account
# 2. Go to Servers → Add Server — enter ClearPass host, DNS credentials, domain, ACME settings
# 3. docker compose restart && docker compose logs -f — watch first-run cert issuance
```

### What .env configures

`.env` controls container-level behaviour only. All server-specific settings
live in `servers.json` and are managed through the web UI.

| Variable | Purpose | Default |
|---|---|---|
| `TZ` | Container timezone for logs and cron | `UTC` |
| `STATUS_PORT` | Web UI port (must match docker-compose.yml) | `8080` |
| `CPPM_CALLBACK_PORT` | Callback port for PKCS12 delivery (must match docker-compose.yml) | `8765` |
| `REQUIRE_AUTH_FOR_STATUS` | Require login to view the dashboard | `false` |
| `SESSION_LIFETIME_HOURS` | Web UI session length in hours | `8` |
| `FORCE_RENEW` | Force certificate re-issue on next startup | `false` |
| `SKIP_UPLOAD` | Issue/renew without uploading to ClearPass | `false` |
| `LOG_LEVEL` | Python log verbosity for upload script | `INFO` |

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

## Web UI routes

```
http://<docker-host>:8080/              Dashboard (public by default)
http://<docker-host>:8080/setup         First-time admin setup wizard
http://<docker-host>:8080/login         Sign in
http://<docker-host>:8080/settings      Servers — manage ClearPass server entries
http://<docker-host>:8080/admin/users   Admin user management
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
# Rebuild image (cert data and servers.json preserved)
docker compose down
docker compose build --no-cache
docker compose up -d

# Apply .env changes (port or timezone change)
docker compose up -d --force-recreate

# Re-upload cert to CPPM (certs unchanged)
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh

# Install flat files from acme.sh state (no re-issue)
docker exec -it cppm-acme-cert-manager /opt/cppm/install_cert.sh

# Run trust list check manually (verify/upload CA certs, no cert renewal)
docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh

# Force full certificate re-issue
# Edit .env: FORCE_RENEW=true → recreate → Edit .env: FORCE_RENEW=false → recreate
docker compose up -d --force-recreate

# View the full cron schedule (renewal + trust check)
docker exec -it cppm-acme-cert-manager cat /etc/crontabs/root

# List certs known to acme.sh
docker exec -it cppm-acme-cert-manager acme.sh --list

# Shell into container
docker exec -it cppm-acme-cert-manager bash
```

---

## Trust exclusion management

```bash
# Configure per-server exclusions (recommended) — web UI
# Servers → Trust Exclusions (on the server row) → check boxes → Save Exclusions

# Global fallback file — applies to servers with no per-server exclusions configured
nano /opt/cppm-certs/trust-exclusions.conf   # takes effect at next trust check, no restart needed

# Run trust check immediately to apply changes
docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh
```

**Priority:** per-server exclusions (web UI → `servers.json`) take precedence
over the global file. The file is only read for servers that have no per-server
exclusions configured.

---

## Updating credentials or DNS provider

All server-specific settings (ClearPass credentials, DNS provider, domain,
ACME server) are managed in the web UI and stored in `servers.json`:

```bash
# Web UI
# Servers → Edit → change fields → Save Changes

# CLI
docker exec -it cppm-acme-cert-manager cppm-servers edit <id>
```

No container restart is needed after updating server credentials.

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
| ClearPass server config | `/opt/cppm-certs/servers.json` |
| Global trust exclusion config | `/opt/cppm-certs/trust-exclusions.conf` |
| Admin credentials | `/opt/cppm-certs/admin.htpasswd` |
| Session signing secret | `/opt/cppm-certs/.session-secret` |

---

## Scheduled tasks

All times are container-local (controlled by the `TZ` env var, default UTC).

| Schedule | Script | Action |
|---|---|---|
| 02:00 daily | `renew.sh` | Checks ECC + RSA cert expiry; renews if ≤30 days remain |
| 14:00 daily | `renew.sh` | Same as above |
| ~60 days after issue | *(automatic on renewal)* | Issues new certs → installs → uploads to CPPM |
| Sunday 03:00 weekly | `trust_check.sh` | Verifies all CA certs in CPPM trust list; uploads any missing |
| On renewal | *(automatic)* | Full upload: trust check + HTTPS(ECC) cert + RADIUS cert |

---

## Troubleshooting shortcuts

```bash
# Show only failures in status log
grep FAILED /opt/cppm-certs/status.log

# Test ClearPass authentication for a specific server
# (get credentials from servers.json or cppm-servers show <id>)
docker exec -it cppm-acme-cert-manager python3 -c "
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
