# Troubleshooting

## Quick diagnosis checklist

```bash
# 1. Check the status log first
grep FAILED /opt/cppm-certs/status.log

# 2. Check the detailed logs
tail -50 /opt/cppm-certs/.logs/startup.log   # startup issues
tail -50 /opt/cppm-certs/.logs/renewal.log   # issuance / renewal
tail -50 /opt/cppm-certs/.logs/upload.log    # ClearPass API issues

# 3. Check Docker container state
docker compose ps
docker compose logs --tail=50
```

---

## Container exits immediately on start

**Cause:** A required environment variable is missing.

```bash
docker compose logs | grep "Missing required env var"
```

Add the missing variable to `.env` and recreate:
```bash
docker compose up -d --force-recreate
```

---

## `[: DEBUG: integer expression expected` in logs

**Cause:** The `DEBUG` environment variable is set to a non-numeric string.
acme.sh uses `$DEBUG` as a numeric log level internally.

The scripts run `unset DEBUG` before every acme.sh invocation. If you still
see this, check your host environment or `.env` for a string-valued `DEBUG`.

---

## DNS provider credential error

**Symptom:** Container exits at startup with `Missing required env var` or
`<PROVIDER> credentials missing`.

**Cause:** `DNS_PROVIDER` is set but the required credential variables for
that provider are missing or empty.

| Provider | Required variables |
|---|---|
| `cloudflare` | `CF_Token` **or** `CF_Key` + `CF_Email` |
| `porkbun` | `PORKBUN_API_KEY` + `PORKBUN_SECRET_API_KEY` |
| `route53` | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| `digitalocean` | `DO_API_KEY` |
| `godaddy` | `GD_Key` + `GD_Secret` |

Fix: add the missing variables to `.env` and recreate:
```bash
docker compose up -d --force-recreate
```

---

## DNS-01 challenge fails — `DNS_API_ERROR` or TXT record not found

**Cause:** The DNS provider API credentials are valid but the TXT record
was not created, or did not propagate before the ACME server checked.

Common causes by provider:

- **Cloudflare:** Zone ID mismatch — `CF_Zone_ID` must match the zone that
  contains the domain, not a parent zone.
- **Porkbun:** API access not enabled for the domain. Check
  **Domain Management → API Access** on the Porkbun dashboard.
- **Route53:** IAM policy missing `route53:GetChange` — the script cannot
  wait for the record to propagate.
- **DigitalOcean:** Token has read-only scope — must be write scope.

Check the renewal log for the full acme.sh error:
```bash
tail -100 /opt/cppm-certs/.logs/renewal.log
```

---

## Authentication failed

**Symptom:** `upload.log` contains `HTTP 400 invalid_client`.

**Cause:** `CPPM_CLIENT_SECRET` is wrong, or the API client is disabled.
Test directly:

```bash
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
```

Fix: verify the client secret in CPPM Admin UI under
**Administration → API Services → API Clients**.

---

## ClearPass API returns 403 Forbidden

**Cause:** The API client's Operator Profile lacks Certificate Management permission.

Fix: in CPPM Admin UI, verify the profile attached to your API client includes:
**Allow → All → Certificate Management**

---

## Trust list upload returns 400 — cert is not a CA certificate

**Cause:** CPPM requires Basic Constraints: CA=TRUE for trust list entries.
End-entity (leaf) certificates cannot be added to the trust list.

The bundled LE PEM files in the image are all CA/intermediate certs. If a chain
cert parsed from `.ca.cer` fails this check, add it manually:

1. CPPM Admin UI → **Administration → Certificates → Trust List → Import**
2. Upload the PEM file
3. Set `cert_usage` to include **EAP** and **Others** → Save

---

## Trust list entries show wrong cert_usage flags

**Symptom:** `upload.log` shows `[PATCH]` lines, then PATCH fails or EAP still not working.

The trust list pre-flight detects entries with incomplete flags (e.g. `EAP=True` but
`Others=False`) and patches them automatically. If CPPM drops the connection during
patching (which can happen if a cert upload triggered a service reload), the script
retries up to 3 times with backoff before marking the entry as failed.

If patches continue to fail, update manually in CPPM Admin UI:
**Administration → Certificates → Trust List** → select entry → enable EAP and Others.

---

## Trust list entry not found by fingerprint

**Symptom:** `upload.log` shows `422 already exists` then
`422 'already exists' but fingerprint lookup missed it`.

The script computes SHA-256 fingerprints from the raw `cert_file` PEM returned
by CPPM for each trust list entry. If the PEM in CPPM has different line endings
or whitespace than expected, the fingerprint may not match.

Force a fresh upload run — on the next run the cert will POST with the correct
`cert_usage` and CPPM will return 422 again. If the mismatch persists, verify the
flags manually in the CPPM Admin UI.

---

## HTTPS upload fails — `GET /api/cluster/server/publisher` returns error

**Symptom:** `upload.log` shows an error fetching the publisher UUID.

**Cause:** The API client's Operator Profile does not include read access to
cluster/server configuration.

Fix: ensure the Operator Profile attached to your API client includes read
access to **Administration → Server Manager** or equivalent.

---

## HTTPS/RADIUS upload fails — 422 "Cert File is empty or invalid post body"

**Cause:** The `PUT /api/server-cert/name/{uuid}/{service_name}` endpoint is
JSON-only. CPPM must fetch the PKCS12 from the `pkcs12_file_url` provided in
the request body. If CPPM cannot reach that URL, it times out and returns 422.

**Fix:** Ensure `CPPM_CALLBACK_HOST` and `CPPM_CALLBACK_PORT` are set correctly
in `.env`, and that the port is published in `docker-compose.yml`:

```ini
CPPM_CALLBACK_HOST=<docker-host-ip>    # Docker host's LAN IP that CPPM can route to
CPPM_CALLBACK_PORT=8765
```

```yaml
ports:
  - "8765:8765"
```

Find the correct callback IP:
```bash
ip route get <cppm-ip>
# Look for 'src X.X.X.X' — that's the interface toward CPPM
```

After updating `.env` and `docker-compose.yml`, restart the container:
```bash
docker compose down && docker compose up -d
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
```

---

## RADIUS upload skipped — unified certificate mode

**Symptom:** `upload.log` shows `RADIUS step skipped – unified_cert_mode`.

This is **not an error.** It means `get_server_cert()` returned no entry with
`service_name` containing "RADIUS" or "EAP". CPPM is configured to use one
certificate for both HTTPS and RADIUS. The HTTPS upload in Step 1 already
covers RADIUS authentication.

---

## PKCS12 conversion fails

**Symptom:** `upload.log` contains `openssl pkcs12 conversion failed`.

Verify the cert and key belong to the same keypair:
```bash
docker exec -it cppm-cert-manager sh -c '
    CERT=/data/certs/cppm.example.com.ecc.cer
    KEY=/data/certs/cppm.example.com.ecc.key
    CM=$(openssl x509 -noout -pubkey -in $CERT | sha256sum)
    KM=$(openssl pkey  -noout -pubout -in $KEY  | sha256sum)
    [ "$CM" = "$KM" ] && echo "MATCH" || echo "MISMATCH – re-issue cert"
'
```

If mismatched, set `FORCE_RENEW=true` in `.env` and recreate the container.

---

## EAP authentication fails after cert install

**Cause:** A Let's Encrypt CA cert is not in the trust list with EAP enabled.

```bash
# Force a re-run of the trust list pre-flight
docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh
tail -f /opt/cppm-certs/status.log
```

Check the `TRUST` status lines. If any show `FAILED`, add the cert manually:

1. Copy the missing cert from the container:
   ```bash
   docker cp cppm-cert-manager:/opt/cppm/le-certs/isrg-root-x1.pem .
   ```
2. CPPM Admin UI → **Administration → Certificates → Trust List → Import**
3. Set `cert_usage` to include **EAP** and **Others** → Save.

---

## Let's Encrypt rate limit

**Symptom:** `renewal.log` contains `too many certificates already issued`.

Switch to staging to test without hitting rate limits:
```bash
# Edit .env: ACME_SERVER=letsencrypt_test
docker compose up -d --force-recreate
```

Do not use staging certs in production. Switch back to `ACME_SERVER=letsencrypt`
and wait 7 days before re-issuing.

---

## Testing the pyclearpass SDK manually

```bash
# Drop into the container
docker exec -it cppm-cert-manager python3

>>> import os, requests
>>> token = requests.post(
...     'https://' + os.environ['CPPM_HOST'] + '/api/oauth',
...     json={'grant_type': 'client_credentials',
...           'client_id': os.environ['CPPM_CLIENT_ID'],
...           'client_secret': os.environ['CPPM_CLIENT_SECRET']},
...     verify=False).json()['access_token']
>>> from pyclearpass.api_platformcertificates import ApiPlatformCertificates
>>> api = ApiPlatformCertificates(
...     server='https://' + os.environ['CPPM_HOST'] + '/api',
...     api_token=token, verify_ssl=False, timeout=30)
>>> api.get_server_cert()          # list server cert entries
>>> api.get_cert_trust_list()      # list trust list entries
```

---

## Browsing the API on your CPPM instance

Interactive Swagger UI:
```
https://cppm.example.com/api-docs/
```

Official API reference (v6.9 – v6.12):
```
https://developer.arubanetworks.com/cppm/reference
```

pyclearpass SDK source:
```
https://github.com/aruba/pyclearpass
```
