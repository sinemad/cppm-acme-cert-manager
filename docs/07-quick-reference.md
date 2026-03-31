# Quick Reference

## Setup (run once)

```bash
./setup.sh                           # create /opt/cppm-certs, copy .env.example
nano .env                            # fill in credentials
docker compose build --no-cache      # build image (downloads acme.sh + LE certs)
docker compose up -d                 # start container
docker compose logs -f               # watch first-run progress
```

---

## Daily operations

```bash
# Check current status
cat /opt/cppm-certs/status.log

# Check cert expiry
openssl x509 -in /opt/cppm-certs/cppm.sinemalab.com.cer -noout -dates

# View live logs
docker compose logs -f

# Container health
docker compose ps
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

# Re-upload cert to CPPM (cert unchanged)
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh

# Install flat files from acme.sh state (no re-issue)
docker exec -it cppm-cert-manager /opt/cppm/install_cert.sh

# Force full certificate re-issue
# Edit .env: FORCE_RENEW=true
docker compose up -d --force-recreate
# Edit .env: FORCE_RENEW=false
docker compose up -d --force-recreate

# Shell into container
docker exec -it cppm-cert-manager bash
```

---

## Log locations

| What | Host path |
|---|---|
| Status summary | `/opt/cppm-certs/status.log` |
| Startup detail | `/opt/cppm-certs/.logs/startup.log` |
| Renewal detail | `/opt/cppm-certs/.logs/renewal.log` |
| Upload detail | `/opt/cppm-certs/.logs/upload.log` |
| Cron log | `/opt/cppm-certs/.logs/cron.log` |

---

## Renewal schedule

| Time (UTC) | Action |
|---|---|
| 02:00 daily | `renew.sh` — checks expiry |
| 14:00 daily | `renew.sh` — checks expiry |
| ~60 days after issue | Actual renewal occurs (when ≤30 days remain) |
| On renewal | Install cert → upload to ClearPass |

---

## Troubleshooting shortcuts

```bash
# Show only failures in status log
grep FAILED /opt/cppm-certs/status.log

# Test ClearPass authentication (pyclearpass SDK)
docker exec -it cppm-cert-manager python3 -c "
import os
from pyclearpass.api_apioperations import ApiApiOperations
api = ApiApiOperations(
    server='https://' + os.environ['CPPM_HOST'] + '/api',
    granttype='client_credentials',
    clientid=os.environ['CPPM_CLIENT_ID'],
    clientsecret=os.environ['CPPM_CLIENT_SECRET'],
    verify_ssl=False, timeout=30)
print(api.get_oauth_me())
"

# Verify cert and key match
docker exec -it cppm-cert-manager sh -c '
    CM=$(openssl x509 -noout -modulus -in /data/certs/cppm.sinemalab.com.cer | md5sum)
    KM=$(openssl rsa  -noout -modulus -in /data/certs/cppm.sinemalab.com.key | md5sum)
    [ "$CM" = "$KM" ] && echo "MATCH" || echo "MISMATCH"
'

# List certs known to acme.sh
docker exec -it cppm-cert-manager acme.sh --list
```
