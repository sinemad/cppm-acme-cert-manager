# Quick Reference

## Setup (run once)

```bash
./setup.sh                           # create /opt/cppm-certs, copy .env.example
nano .env                            # set DNS_PROVIDER + credentials + CPPM settings
docker compose build --no-cache      # build image (downloads acme.sh + LE certs)
docker compose up -d                 # start container
docker compose logs -f               # watch first-run progress
```

---

## Daily operations

```bash
# Check current status
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

## Maintenance commands

```bash
# Rebuild image (cert data preserved)
docker compose down
docker compose build --no-cache
docker compose up -d

# Update credentials (.env changed)
docker compose up -d --force-recreate

# Re-upload cert to CPPM (certs unchanged)
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh

# Install flat files from acme.sh state (no re-issue)
docker exec -it cppm-cert-manager /opt/cppm/install_cert.sh

# Force full certificate re-issue
# Edit .env: FORCE_RENEW=true
docker compose up -d --force-recreate
# Edit .env: FORCE_RENEW=false
docker compose up -d --force-recreate

# Check active DNS provider
docker exec -it cppm-cert-manager sh -c 'echo "DNS_PROVIDER=${DNS_PROVIDER}"'

# List certs known to acme.sh
docker exec -it cppm-cert-manager acme.sh --list

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
| 02:00 daily | `renew.sh` — checks expiry for both ECC and RSA certs |
| 14:00 daily | `renew.sh` — checks expiry for both ECC and RSA certs |
| ~60 days after issue | Actual renewal occurs (when ≤30 days remain) |
| On renewal | Install ECC + RSA → upload ECC→HTTPS(ECC), RSA→RADIUS |

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

# Test ClearPass authentication
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

# Verify ECC cert and key match
docker exec -it cppm-cert-manager sh -c '
    CM=$(openssl x509 -noout -pubkey -in /data/certs/cppm.example.com.ecc.cer | sha256sum)
    KM=$(openssl pkey  -noout -pubout -in /data/certs/cppm.example.com.ecc.key | sha256sum)
    [ "$CM" = "$KM" ] && echo "ECC: MATCH" || echo "ECC: MISMATCH"
'

# Verify RSA cert and key match
docker exec -it cppm-cert-manager sh -c '
    CM=$(openssl x509 -noout -pubkey -in /data/certs/cppm.example.com.rsa.cer | sha256sum)
    KM=$(openssl pkey  -noout -pubout -in /data/certs/cppm.example.com.rsa.key | sha256sum)
    [ "$CM" = "$KM" ] && echo "RSA: MATCH" || echo "RSA: MISMATCH"
'

# List acme.sh cert state (both ECC and RSA)
docker exec -it cppm-cert-manager acme.sh --list
```
