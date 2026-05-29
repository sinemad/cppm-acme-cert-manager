# Maintenance

## Rebuilding the container

Safe to do at any time. The certificate data in `/opt/cppm-certs/` is never
touched by a rebuild.

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

On restart the container sees the existing flat `.cer` file, logs the expiry,
and starts crond. No re-issue, no upload — nothing happens until renewal is due.

---

## Updating credentials

If you rotate the CPPM API secret, Cloudflare token, or any other `.env` value:

```bash
nano /opt/cppm-acme-cert-manager/.env
docker compose up -d --force-recreate
```

---

## Enabling SSL verification

After the Let's Encrypt certificate is installed and CPPM is accessible via
trusted HTTPS:

```bash
# Confirm CPPM is serving the new cert
openssl s_client -connect cppm.example.com:443 \
    -servername cppm.example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -dates

# Enable verification
# Edit .env: CPPM_VERIFY_SSL=true
docker compose up -d --force-recreate
```

---

## Manually re-upload to ClearPass

Use this if the cert is already current but needs to be re-uploaded
(e.g. after a CPPM rebuild or restore):

```bash
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh
```

This runs the full upload sequence: trust list pre-flight, HTTPS cert upload,
RADIUS cert upload.

---

## Manually run install-cert only

If acme.sh has the cert in its internal state but the flat files are missing
(visible in `status.log` as "Flat files missing"):

```bash
docker exec -it cppm-acme-cert-manager /opt/cppm/install_cert.sh
```

No DNS challenge is performed. No contact with Let's Encrypt.

---

## Force a full certificate re-issue

Use this to rotate the certificate before it is due (e.g. key compromise,
CPPM migration):

```bash
# 1. Set the flag
#    Edit .env: FORCE_RENEW=true
docker compose up -d --force-recreate
docker compose logs -f
# Wait for "New certificate issued" and "Upload succeeded" in the logs

# 2. Clear the flag when done
#    Edit .env: FORCE_RENEW=false
docker compose up -d --force-recreate
```

---

## Rotate the PKCS12 export passphrase

The passphrase is only used transiently during the PEM → PKCS12 conversion
and is never stored on disk. To change it:

```bash
# Edit .env: CPPM_CERT_PASSPHRASE=<new-passphrase>
docker compose up -d --force-recreate
# Force a re-upload so CPPM gets the new PKCS12
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh
```

---

## Trust list verification

The Let's Encrypt CA and intermediate CA certificates in the ClearPass trust
list are checked and repaired automatically on two schedules:

| Schedule | Trigger | What runs |
|---|---|---|
| After every cert issuance or renewal | Automatic via `deploy_hook.sh` | Trust check + HTTPS + RADIUS upload |
| Weekly — Sunday 03:00 container-local | Automatic via `trust_check.sh` | Trust check only (no cert upload) |

### Run the trust list check manually

```bash
docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh
```

Output appends to `/opt/cppm-certs/.logs/upload.log` and records a `TRUST`
entry in `status.log`.

### Exclude specific CA or intermediate certs from upload

A config file on the persistent volume controls which certs are excluded from
all trust list operations. It is seeded automatically from the image default
on first container start:

```
/opt/cppm-certs/trust-exclusions.conf   (host path — edit this one)
/data/certs/trust-exclusions.conf       (same file, container path)
```

Edit it on the host — no container restart required; changes take effect at
the next scheduled or manual trust check:

```bash
nano /opt/cppm-certs/trust-exclusions.conf
```

Each non-comment line is matched case-insensitively against the certificate's
Subject CN. Partial matches are supported:

```
# Exclude Let's Encrypt R11 (already managed separately in this environment)
R11

# Exclude the ECDSA root — not needed if RADIUS uses RSA-only EAP
ISRG Root X2
```

The file has a comprehensive header explaining every option. If you delete or
corrupt it, the container will restore the default from the image on next
restart.

---

## Check the scheduled task list

```bash
# View the full cron schedule inside the container
docker exec -it cppm-acme-cert-manager cat /etc/crontabs/root
```

---

## Automatic log review

`status.log` records the outcome of every scheduled operation. During normal
operation you will see entries like the following — no action is required.

**Daily renewal checks (02:00 and 14:00):**
```
2026-04-01 02:00:01 | INFO   | RENEW   | Not due for renewal – 75 days remaining (next check in 12h)
```

**Weekly trust list check (Sunday 03:00):**
```
2026-06-08 03:00:07 | OK     | TRUST   | 9 LE CA certs verified – 0 uploaded, 0 patched, 9 already trusted
```

The first `OK | RENEW` entry confirms a successful certificate renewal.
The weekly `OK | TRUST` entry confirms the ClearPass trust list is complete.

---

## Shell into the container

```bash
docker exec -it cppm-acme-cert-manager bash

# Useful commands once inside:
acme.sh --list                         # show all certs managed by acme.sh
acme.sh --info -d cppm.example.com   # show detail for this domain
cat /data/certs/status.log             # view status log
```
