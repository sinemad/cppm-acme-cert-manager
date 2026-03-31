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
nano /opt/cppm-cert-manager/.env
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
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
```

This runs the full upload sequence: trust list pre-flight, HTTPS cert upload,
RADIUS cert upload.

---

## Manually run install-cert only

If acme.sh has the cert in its internal state but the flat files are missing
(visible in `status.log` as "Flat files missing"):

```bash
docker exec -it cppm-cert-manager /opt/cppm/install_cert.sh
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
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
```

---

## Check renewal schedule

Renewals run at 02:00 and 14:00 UTC. acme.sh only contacts Let's Encrypt
when 30 or fewer days remain on the cert.

```bash
# See the cron schedule inside the container
docker exec -it cppm-cert-manager cat /etc/crontabs/root

# Check when the next renewal will actually fire
openssl x509 -in /opt/cppm-certs/cppm.example.com.ecc.cer -noout -enddate
openssl x509 -in /opt/cppm-certs/cppm.example.com.rsa.cer -noout -enddate
```

---

## Automatic renewal log review

After each cron run, `status.log` records the outcome. During the ~60 days
between issue and renewal you will see twice-daily entries like:

```
2026-04-01 02:00:01 | INFO   | RENEW   | Not due for renewal – 75 days remaining (next check in 12h)
```

No action is required. The first `OK | RENEW` entry indicates a successful
renewal has occurred.

---

## Shell into the container

```bash
docker exec -it cppm-cert-manager bash

# Useful commands once inside:
acme.sh --list                         # show all certs managed by acme.sh
acme.sh --info -d cppm.example.com   # show detail for this domain
cat /data/certs/status.log             # view status log
```
