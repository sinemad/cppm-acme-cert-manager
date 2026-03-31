# Monitoring

## status.log — the quick view

`status.log` lives directly in `/opt/cppm-certs/` and is readable on the host
without `docker exec`. It records one line per significant event using a fixed
column format:

```
TIMESTAMP           | LEVEL  | CATEGORY | MESSAGE
2026-03-17 10:43:07 | INFO   | STARTUP  | Container started – domain=cppm.sinemalab.com
2026-03-17 10:43:07 | INFO   | CERT     | No certificate found – starting first-time issuance
2026-03-17 10:43:34 | OK     | CERT     | New certificate issued via Cloudflare DNS-01
2026-03-17 10:43:34 | OK     | CERT     | Cert installed – expires Jun 15 2026 (89 days remaining)
2026-03-17 10:43:38 | OK     | TRUST    | 6 LE CA certs verified – 2 uploaded, 4 already trusted
2026-03-17 10:43:42 | OK     | UPLOAD   | HTTPS + RADIUS cert uploaded to cppm.sinemalab.com
2026-03-17 10:43:42 | INFO   | STARTUP  | crond started – renewal checks at 02:00 and 14:00 UTC
```

```bash
# View on the host
cat /opt/cppm-certs/status.log

# Live tail
tail -f /opt/cppm-certs/status.log

# Show only failures
grep FAILED /opt/cppm-certs/status.log

# Show only upload events
grep UPLOAD /opt/cppm-certs/status.log

# Show last 10 events
tail -10 /opt/cppm-certs/status.log
```

---

## Log levels

| Level | Meaning |
|---|---|
| `OK` | Task completed successfully |
| `INFO` | Informational — no action required |
| `WARN` | Something unexpected but recoverable (e.g. trust cert flags needed patching) |
| `FAILED` | Task failed — check the detailed log for the corresponding category |

## Categories

| Category | Written by | Covers |
|---|---|---|
| `STARTUP` | `entrypoint.sh` | Container start, crond launch, env validation |
| `CERT` | `entrypoint.sh`, `issue_cert.sh`, `install_cert.sh` | Issuance, install-cert, expiry status |
| `RENEW` | `renew.sh` | Daily renewal check results |
| `TRUST` | `clearpass_upload.py` | Let's Encrypt trust list pre-flight summary |
| `UPLOAD` | `deploy_hook.sh`, `clearpass_upload.py` | ClearPass API upload results |

---

## Expected status.log patterns

### Normal restart (cert already installed)

```
2026-03-18 09:00:01 | INFO   | STARTUP | Container started – domain=cppm.sinemalab.com
2026-03-18 09:00:02 | OK     | CERT    | Certificate valid – expires Jun 15 2026 (88 days remaining)
2026-03-18 09:00:02 | INFO   | STARTUP | crond started – renewal checks at 02:00 and 14:00 UTC
```

### Daily renewal check (not yet due)

```
2026-03-19 02:00:01 | INFO   | RENEW   | Not due for renewal – 87 days remaining (next check in 12h)
```

### Successful renewal (~day 60)

```
2026-06-01 02:00:01 | OK     | RENEW   | Certificate renewed – running install and upload
2026-06-01 02:00:08 | OK     | CERT    | Cert installed – expires Sep 13 2026 (89 days remaining)
2026-06-01 02:00:11 | OK     | TRUST   | 6 LE CA certs verified – 0 uploaded, 6 already trusted
2026-06-01 02:00:15 | OK     | UPLOAD  | HTTPS + RADIUS cert uploaded to cppm.sinemalab.com
```

### Upload failure

```
2026-06-01 02:00:15 | FAILED | UPLOAD  | ClearPass upload failed (exit 1) – check upload.log
```

---

## Detailed logs

The `.logs/` directory contains verbose output for deeper investigation:

```bash
# Container startup and cert state decisions
tail -100 /opt/cppm-certs/.logs/startup.log

# acme.sh issuance and renewal full output
tail -100 /opt/cppm-certs/.logs/renewal.log

# ClearPass API upload detail (OAuth, PKCS12, API responses)
tail -100 /opt/cppm-certs/.logs/upload.log

# crond execution timestamps
tail -50 /opt/cppm-certs/.logs/cron.log
```

---

## Docker container logs

```bash
# Live
docker compose logs -f

# Last 100 lines
docker compose logs --tail=100

# Since a specific time
docker compose logs --since="2026-03-17T10:00:00"
```

---

## Verify the certificate directly

```bash
# Check expiry of the installed flat cert file
openssl x509 -in /opt/cppm-certs/cppm.sinemalab.com.cer -noout -subject -dates

# Verify what CPPM is actually serving over HTTPS
openssl s_client -connect cppm.sinemalab.com:443 \
    -servername cppm.sinemalab.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates
```
