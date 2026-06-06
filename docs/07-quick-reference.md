# Quick Reference

## Setup (run once)

```bash
./setup.sh                           # create /opt/cppm-certs, copy override template
# Optional: nano docker-compose.override.yml   # set TZ and any port/flag overrides
docker compose build --no-cache      # build image (downloads Lego + ACME CA certs)
docker compose up -d                 # start container
docker compose logs -f               # watch startup

# 1. Open http://<docker-host>:8080/setup — create the admin account
# 2. Go to Servers → Add Server — enter ClearPass host, DNS credentials, domain, ACME settings
# 3. docker compose restart && docker compose logs -f — watch first-run cert issuance
```

### What docker-compose.override.yml configures

Container-level behaviour only. All server-specific settings live in
`servers.json` and are managed through the web UI.

| Variable | Purpose | Default |
|---|---|---|
| `TZ` | Container timezone for logs and cron | `UTC` |
| `STATUS_PORT` | Web UI port (must match ports section) | `8080` |
| `CPPM_CALLBACK_PORT` | Callback port for PKCS12 delivery (must match ports section) | `8765` |
| `REQUIRE_AUTH_FOR_STATUS` | Require login to view the dashboard | `false` |
| `SESSION_LIFETIME_HOURS` | Web UI session length in hours | `8` |
| `FORCE_RENEW` | Force certificate re-issue on next startup | `false` |
| `SKIP_UPLOAD` | Issue/renew without uploading to ClearPass | `false` |
| `LOG_LEVEL` | Python log verbosity for upload script | `INFO` |

> Changing `STATUS_PORT` or `CPPM_CALLBACK_PORT` requires updating both the
> `environment` section and the `ports` section in the override file.

---

## Daily operations

```bash
# Web dashboard — easiest way to check status (open in browser)
# http://<docker-host>:8080/

# Check per-server activity log (replace hostname)
cat /opt/cppm-certs/cppm.example.com/status.log

# Check cert expiry (ECC and RSA)
openssl x509 -in /opt/cppm-certs/cppm.example.com/cppm.example.com.ecc.cer -noout -dates
openssl x509 -in /opt/cppm-certs/cppm.example.com/cppm.example.com.rsa.cer -noout -dates

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

# Apply docker-compose.override.yml changes (port or timezone change)
docker compose up -d --force-recreate

# Re-upload cert to CPPM (certs unchanged)
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh

# Install flat files from Lego state (no re-issue)
docker exec -it cppm-acme-cert-manager /opt/cppm/install_cert.sh

# Run trust list check manually (verify/upload CA certs, no cert renewal)
docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh

# Force full certificate re-issue
# Edit docker-compose.override.yml: FORCE_RENEW: "true" → recreate
# → Edit: FORCE_RENEW: "false" → recreate
docker compose up -d --force-recreate

# View the full cron schedule (renewal + trust check)
docker exec -it cppm-acme-cert-manager cat /etc/crontabs/root

# List certs known to Lego (replace hostname/path as needed)
docker exec -it cppm-acme-cert-manager \
    lego --path /data/certs/cppm.example.com/lego-ecc list

# Shell into container
docker exec -it cppm-acme-cert-manager bash
```

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
| Per-server activity log | `/opt/cppm-certs/<cppm_host>/status.log` |
| Per-server Lego renewal detail | `/opt/cppm-certs/<cppm_host>/.logs/acme_renewal.log` |
| Per-server ClearPass upload detail | `/opt/cppm-certs/<cppm_host>/.logs/cppm_upload.log` |
| Container startup detail | `/opt/cppm-certs/.logs/startup.log` |
| Web UI process log | `/opt/cppm-certs/.logs/status_server.log` |
| Container-level startup events | `/opt/cppm-certs/status.log` |
| ClearPass server config | `/opt/cppm-certs/servers.json` |
| Admin credentials | `/opt/cppm-certs/admin.htpasswd` |
| Session signing secret | `/opt/cppm-certs/.session-secret` |

---

## Scheduled tasks

All times are container-local (controlled by the `TZ` env var, default UTC).

| Schedule | Script | Action |
|---|---|---|
| 02:00 daily | `renew.sh` → `acme_cli.py renew` | Checks ECC + RSA cert expiry via Lego; renews if ≤30 days remain |
| 14:00 daily | `renew.sh` → `acme_cli.py renew` | Same as above |
| ~60 days after issue | *(automatic on renewal)* | Issues new certs via Lego → installs → uploads to CPPM |
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

# List Lego cert state (replace hostname as needed)
docker exec -it cppm-acme-cert-manager \
    lego --path /data/certs/cppm.example.com/lego-ecc list
```
