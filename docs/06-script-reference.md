# Script Reference

All scripts live in `/opt/cppm/` inside the container and in `scripts/` in
the project directory.

---

## entrypoint.sh

**Called by:** Docker on container start — never call manually.

Runs the certificate state decision tree, seeds acme.sh state, registers
the ACME account, and starts supercronic.

Decision order:
1. `FORCE_RENEW=true` → `issue_cert.sh`
2. Flat `.cer` file exists → log expiry, start supercronic, nothing else
3. acme.sh internal cert exists, flat files missing → `install_cert.sh`
4. No cert anywhere → `issue_cert.sh`

---

## issue_cert.sh

**Manual:** `docker exec -it cppm-cert-manager /opt/cppm/issue_cert.sh`

Runs `acme.sh --issue` with the Cloudflare DNS-01 plugin.

- Exit 0 → new cert issued, calls `install_cert.sh`
- Exit 2 → cert in acme.sh state, not due — calls `install_cert.sh` without contacting Let's Encrypt
- Other → logs error and exits non-zero

---

## install_cert.sh

**Manual:** `docker exec -it cppm-cert-manager /opt/cppm/install_cert.sh`

Runs `acme.sh --install-cert --cert-home /data/certs` to copy flat files from
acme.sh internal state to `/data/certs/`. Verifies all four files are present,
then calls `deploy_hook.sh`. No DNS challenge, no Let's Encrypt contact.

---

## renew.sh

**Called by:** supercronic at 02:00 and 14:00 UTC.
**Manual:** `docker exec -it cppm-cert-manager /opt/cppm/renew.sh`

Runs `acme.sh --renew`. On success calls `install_cert.sh`. Exit 2 (not due)
is logged and treated as clean exit.

---

## deploy_hook.sh

**Called by:** `install_cert.sh` (via `--reloadcmd`).
**Manual:** `docker exec -it cppm-cert-manager /opt/cppm/deploy_hook.sh`

Resolves cert file paths and invokes `clearpass_upload.py`. Set
`SKIP_UPLOAD=true` in `.env` to disable the upload without removing the hook.

---

## clearpass_upload.py

**Called by:** `deploy_hook.sh`
**Manual:** `docker exec -it cppm-cert-manager python3 /opt/cppm/clearpass_upload.py --help`

Uses the **official Aruba pyclearpass SDK** (`github.com/aruba/pyclearpass`)
for all ClearPass API operations.

### SDK class used

```python
from pyclearpass import ApiPlatformCertificates
```

Source file in the image: `pyclearpass/api_platformcertificates.py`

### Step 0 — Trust List Pre-flight

| SDK Method | HTTP | Path |
|---|---|---|
| `get_cert_trust_list(limit="1000")` | `GET` | `/api/cert-trust-list` |
| `new_cert_trust_list(body)` | `POST` | `/api/cert-trust-list` |
| `update_cert_trust_list_by_cert_trust_list_id(id, body)` | `PATCH` | `/api/cert-trust-list/{id}` |

The CPPM trust list response contains only `id`, `cert_file`, `enabled`,
`cert_usage`, and `_links` — no fingerprint or subject field. The script
computes SHA-256 fingerprints from the `cert_file` PEM in each entry to
build a lookup map for matching. PATCH calls include retry logic with
backoff to handle transient connection drops after a service reload.

**POST body schema:**
```json
{
  "cert_file":  "<PEM text of CA certificate — plain string, not base64>",
  "enabled":    true,
  "cert_usage": ["EAP", "Others"]
}
```

`cert_usage` is an **array of strings**. Valid values per CPPM API docs:
`"AD/LDAP Servers"`, `"Aruba Infrastructure"`, `"Aruba Services"`,
`"Database"`, `"EAP"`, `"Endpoint Context Servers"`, `"RadSec"`,
`"SAML"`, `"SMTP"`, `"EST"`, `"Others"`

**PATCH body schema** (for existing entries with incomplete flags):
```json
{
  "enabled":    true,
  "cert_usage": ["EAP", "Others"]
}
```

### Step 1 — HTTPS(ECC) Server Certificate

The `PUT /api/server-cert/name/{uuid}/{service_name}` endpoint is JSON-only.
CPPM fetches the PKCS12 from `pkcs12_file_url` at import time. The script
serves the PKCS12 from a temporary HTTP server bound to `0.0.0.0` on the
fixed port defined by `CPPM_CALLBACK_PORT`, exposed via `docker-compose.yml`.
`CPPM_CALLBACK_HOST` must be the Docker host's LAN IP that CPPM can route to.

| Method | Path |
|---|---|
| `GET` | `/api/cluster/server/publisher` |
| `GET` | `/api/server-cert` |
| `PUT` | `/api/server-cert/name/{server_uuid}/HTTPS(ECC)` |

The publisher server UUID is fetched via
`ApiLocalServerConfiguration.get_cluster_server_by_uuid(uuid="publisher")`.
The script prefers `HTTPS(ECC)` (service_id=2) then falls back to `HTTPS(RSA)`
(service_id=7) then any HTTPS variant.

**PUT body schema:**
```json
{
  "pkcs12_file_url":  "http://<CPPM_CALLBACK_HOST>:<CPPM_CALLBACK_PORT>/<file>.pfx",
  "pkcs12_passphrase": "<passphrase>"
}
```

### Step 2 — RADIUS (RSA) Service Certificate

Same PUT mechanism as Step 1 targeting the RADIUS service name (service_id=1).
If no RADIUS entry exists in `get_server_cert()` the step skips cleanly.

| Method | Path |
|---|---|
| `PUT` | `/api/server-cert/name/{server_uuid}/RADIUS` |

### Step 3 — Verification

`get_server_cert()` is called and the response is searched for the domain name
as a sanity check.

### CLI flags

```
--https-cert        ECC domain cert (.ecc.cer)
--https-key         ECC private key (.ecc.key)
--https-fullchain   ECC fullchain (.ecc.fullchain.cer)
--https-ca          ECC CA chain (.ecc.ca.cer)  [optional]
--radius-cert       RSA domain cert (.rsa.cer)
--radius-key        RSA private key (.rsa.key)
--radius-fullchain  RSA fullchain (.rsa.fullchain.cer)
--radius-ca         RSA CA chain (.rsa.ca.cer)  [optional]
--domain        Domain name  [default: $DOMAIN env var]
--skip-trust-check  Skip Step 0
--skip-radius       Skip Step 2
```

---

## status.sh

Sourced by all scripts (`source /opt/cppm/status.sh`). Never call directly.

Provides `status_write LEVEL CATEGORY MESSAGE` which writes to
`/data/certs/status.log`.

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DOMAIN` | Yes | — | FQDN for the certificate |
| `ACME_EMAIL` | Yes | — | Let's Encrypt account email |
| `ACME_SERVER` | No | `letsencrypt` | ACME CA (`letsencrypt`, `letsencrypt_test`, `zerossl`) |
| `CF_Token` | Yes | — | Cloudflare scoped API token |
| `CF_Account_ID` | Yes | — | Cloudflare account ID |
| `CF_Zone_ID` | Yes | — | Cloudflare zone ID for the domain |
| `CPPM_HOST` | Yes | — | ClearPass hostname |
| `CPPM_CLIENT_ID` | Yes | — | ClearPass API client ID |
| `CPPM_CLIENT_SECRET` | Yes | — | ClearPass API client secret |
| `CPPM_VERIFY_SSL` | No | `false` | Verify CPPM TLS cert (`true` after install) |
| `CPPM_CERT_PASSPHRASE` | No | `CppmCert!2024` | PKCS12 export passphrase (transient, used in fallback only) |
| `FORCE_RENEW` | No | `false` | Force re-issue on next start |
| `SKIP_UPLOAD` | No | `false` | Disable ClearPass upload |
| `LOG_LEVEL` | No | `INFO` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `TZ` | No | `UTC` | Container timezone |
