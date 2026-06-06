# Script Reference

All scripts live in `/opt/cppm/` inside the container and in `scripts/` in
the project directory.

---

## entrypoint.sh

**Called by:** Docker on container start — never call manually.

On startup:
1. Runs `migrate_from_env()` — if `servers.json` is empty and legacy server
   vars are present in the environment, auto-migrates them into `servers.json`
   (one-time).
2. Iterates over each server in `servers.json`, exporting per-server
   environment variables via `eval "$(cppm-servers env <id>)"`.
3. For each server, runs the certificate state decision tree:
   - `FORCE_RENEW=true` → `issue_cert.sh`
   - Flat `.cer` files exist → log expiry, nothing else
   - Lego state exists but flat files missing → `install_cert.sh`
   - No cert found → `issue_cert.sh`
4. Performs one-time cleanup of legacy acme.sh state directories
   (`<domain>_ecc/` and `<domain>/`) if certs are already present (guard
   condition ensures this never fires on a fresh container with no certs).
5. Seeds `trust-exclusions.conf` to the volume if not already present.
6. Starts `status_server.py` in the background.
7. `exec supercronic` (becomes PID 1 subprocess).

---

## issue_cert.sh

**Manual:** `docker exec -it cppm-acme-cert-manager /opt/cppm/issue_cert.sh`

Delegates to `acme_cli.py issue` (which calls `LegoProvider.issue_cert()`).
The server context must be set via `eval "$(cppm-servers env <id>)"` before
manual invocation.

- Exit 0 → new cert issued, calls `install_cert.sh`
- Other → logs error and exits non-zero

To force re-issue of an already valid cert set `FORCE_RENEW=true` (or use the
`docker-compose.override.yml` flag and recreate the container).

---

## install_cert.sh

**Manual:** `docker exec -it cppm-acme-cert-manager /opt/cppm/install_cert.sh`

Delegates to `acme_cli.py install` (which calls `LegoProvider.install_cert()`).
Copies the four flat cert files from Lego's internal state directories
(`lego-ecc/` and `lego-rsa/`) to the server cert directory. Verifies all eight
files (four per key type) are present, then calls `deploy_hook.sh`. No DNS
challenge, no Let's Encrypt contact.

---

## renew.sh

**Called by:** supercronic at 02:00 and 14:00 UTC.
**Manual:** `docker exec -it cppm-acme-cert-manager /opt/cppm/renew.sh`

Delegates to `acme_cli.py renew` (which calls `LegoProvider.renew_cert()`).
Lego always exits 0 from `lego renew`; true renewal is detected by comparing
the cert file mtime before and after the call. Exit codes propagated by
`acme_cli.py`:

- Exit 0 → cert renewed → calls `install_cert.sh`
- Exit 2 → not due (>30 days remaining) → logged and treated as clean exit
- Other → error → status_write FAILED

---

## deploy_hook.sh

**Called by:** `install_cert.sh` after cert files are verified.
**Manual:** `docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh`

Resolves cert file paths and invokes `clearpass_upload.py`. Set
`SKIP_UPLOAD: "true"` in `docker-compose.override.yml` to disable the upload
without removing the hook.

---

## clearpass_upload.py

**Called by:** `deploy_hook.sh`
**Manual:** `docker exec -it cppm-acme-cert-manager python3 /opt/cppm/clearpass_upload.py --help`

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

## trust_check.sh

**Called by:** supercronic every Sunday at 03:00 container-local time.
**Manual:** `docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh`

Iterates over every server in `servers.json`. For each server, verifies that
every required ACME CA and intermediate CA certificate is present in the
ClearPass trust list and uploads any that are missing — without issuing or
renewing certificates.

Behaviour:
1. Skips a server if its domain certificates have not yet been issued.
2. Calls `clearpass_upload.py --only-trust-check` with both the ECC and RSA
   CA chain paths, so intermediates unique to either chain are always checked.
3. Applies trust exclusions: per-server exclusions from `servers.json` take
   precedence; falls back to `trust-exclusions.conf` if none are configured.
4. Appends output to each server's `/data/certs/<cppm_host>/.logs/cppm_upload.log`
   and writes a `TRUST` entry to the per-server `status.log`.

---

## trust-exclusions.conf

**Global fallback file (admin-editable):**
```
/opt/cppm-certs/trust-exclusions.conf   (host path)
/data/certs/trust-exclusions.conf       (container path)
```

**Image default (read-only reference):**
```
/opt/cppm/acme-ca-certs/trust-exclusions.conf
```

**Priority:** Per-server exclusions configured in the web UI
(**Servers → Edit → ACME Provider → Trust Exclusions**) and stored in `servers.json` always take
precedence. This file is only read when a server has no per-server exclusions
configured — it acts as a global fallback for backwards compatibility.

Controls which ACME CA and intermediate CA certificates are excluded from all
trust list operations (both post-renewal uploads and weekly checks). Excluded
certificates are silently skipped — they are never uploaded, never patched,
and no error is raised if they are absent from the trust list.

The file is seeded to the persistent volume by `entrypoint.sh` on first start.
Edit the host-side copy — changes take effect at the next scheduled or manual
trust check without restarting the container.

**Format:** one entry per line, matched case-insensitively as a partial
substring against the certificate's Subject CN. Lines starting with `#` are
comments.

```
# Exclude R11 — already managed separately in this environment
R11

# Exclude ECDSA intermediates — RADIUS uses RSA-only EAP
E5
E6
E7
E8
```

---

## status_server.py

**Started by:** `entrypoint.sh` as a background process before `exec supercronic`.
**Never call manually** — it runs for the lifetime of the container.

Serves an authenticated web interface on `STATUS_PORT` (default `8080`):

| Route | Auth required | Description |
|---|---|---|
| `GET /` | No (configurable) | Multi-server certificate dashboard |
| `GET /server/<id>` | No (configurable) | Per-server detail with connectivity status |
| `GET /settings` | Yes | ClearPass server list — add, edit, delete |
| `GET /settings/add` | Yes | Add server form |
| `GET /settings/edit/<id>` | Yes | Edit server form |
| `GET /settings/trust-exclusions/<id>` | Yes | Per-server trust exclusions (reached via Edit → ACME Provider) |
| `GET /admin/users` | Yes | Admin user management |
| `GET /api/status` | No (configurable) | JSON status payload |
| `GET /api/status/<id>` | No (configurable) | JSON status for one server |

All server configuration (ClearPass credentials, DNS provider, domain, ACME
settings, trust exclusions) is stored in `/data/certs/servers.json` and
managed through these routes. Admin credentials are stored in
`/data/certs/admin.htpasswd` (bcrypt). Sessions are HMAC-SHA256 signed cookies
using a secret in `/data/certs/.session-secret`.

Logs to `/data/certs/.logs/status_server.log`.

---

## acme_provider.py

**Used by:** `acme_cli.py`, `lego_provider.py`, `acme_sh_provider.py`. Not called directly.

Abstract base class and shared result types that define the common interface
for all ACME certificate providers.

### Types

| Type | Description |
|---|---|
| `AcmeError` | Exception raised by all provider operations on failure |
| `KeyTypeResult(key_type, issued)` | Outcome for a single key type (`"ecc"` or `"rsa"`). `issued=True` = new cert issued; `issued=False` = skipped (not due / already exists) |
| `IssueResult(results)` | Combined result from an issue or renew call. `.newly_issued` is `True` if any key type produced a new cert |

### AcmeProvider interface

| Method | Description |
|---|---|
| `register_account(email, server)` | Register or verify an ACME account (idempotent) |
| `issue_cert(*, domain, acme_server, cert_dir, key_types, dns_provider, dns_env, log_file, force)` | Issue new certificates via DNS-01 challenge |
| `renew_cert(*, domain, acme_server, cert_dir, key_types, dns_provider, dns_env, log_file)` | Renew existing certificates; attempts all key types before raising |
| `install_cert(*, domain, cert_dir, key_types, log_file)` | Copy provider-managed state to flat `.cer`/`.key` files; verifies all expected files exist |
| `revoke_cert(*, domain, cert_dir, key_types, log_file)` | Revoke issued certificates; attempts all key types before raising |

### Factory

```python
from acme_provider import get_provider

provider = get_provider("lego")      # LegoProvider (default)
provider = get_provider("acme_sh")   # AcmeShProvider (legacy)
```

All path arguments must be absolute. `key_types` is a list containing any combination of `"ecc"` and `"rsa"`. `dns_env` is a dict of DNS provider credential env vars (e.g. `{"CF_Token": "..."}`) merged into the subprocess environment so credentials are never globally exported.

---

## acme_sh_provider.py

**Status:** Legacy — not the active code path. Kept for reference.

Concrete `AcmeProvider` implementation backed by the `acme.sh` CLI. Accepts
`dns_provider` and `dns_env` on `renew_cert()` for interface compatibility
(acme.sh stores DNS credentials in per-cert `.conf` files so they are not
needed at renewal time and are silently ignored).

### Behaviour notes

- **`register_account`** — any non-zero exit is tolerated (idempotent).
- **`issue_cert`** — acme.sh exit 2 (cert exists, not due) maps to `issued=False`, not an error.
- **`renew_cert`** — tries all requested key types before raising; an ECC failure does not prevent RSA from being attempted.
- **`DEBUG` env var** — stripped from the subprocess environment before every call.
- **Subprocess timeout** — defaults to 600 seconds.

---

## lego_provider.py

**Status:** Active — the default `AcmeProvider` implementation.

Concrete `AcmeProvider` backed by the `lego` CLI at `/usr/local/bin/lego`.

### DNS plugin mapping

Translates the `dns_provider` value from `servers.json` to the Lego plugin name:

| `dns_provider` value | Lego plugin |
|---|---|
| `cloudflare`, `cf` | `cloudflare` |
| `porkbun` | `porkbun` |
| `route53`, `aws`, `r53` | `route53` |
| `digitalocean`, `do` | `digitalocean` |
| `godaddy`, `gd` | `godaddy` |
| anything else | passthrough as-is |

### Credential remapping

`servers.json` stores credentials using acme.sh-style names for backward
compatibility. `_map_dns_env()` translates them to Lego names at runtime:

| servers.json key | Lego env var |
|---|---|
| `CF_Token` | `CF_DNS_API_TOKEN` |
| `CF_Key` | `CF_API_KEY` |
| `CF_Email` | `CF_API_EMAIL` |
| `DO_API_KEY` | `DO_AUTH_TOKEN` |
| `GD_Key` | `GODADDY_API_KEY` |
| `GD_Secret` | `GODADDY_API_SECRET` |
| `AWS_DEFAULT_REGION` | `AWS_REGION` |
| `CF_Zone_ID`, `CF_Account_ID` | dropped (not used by Lego) |

### Behaviour notes

- **`issue_cert`** — for `force=True`, deletes the domain's cert files from
  `lego-{ecc,rsa}/certificates/` before `lego run` to ensure a fresh issue.
- **`renew_cert`** — uses mtime comparison before/after `lego renew --days 30`
  to detect true renewal (Lego always exits 0 regardless of whether it renewed).
- **`install_cert`** — copies `.crt` → `.fullchain.cer`, extracts first PEM → `.cer`,
  `.key` → `.key` (chmod 600), `.issuer.crt` → `.ca.cer` (fallback: strip leaf
  from fullchain).
- **`DEBUG` env var** — popped from subprocess environment before each call.
- **Subprocess timeout** — defaults to 600 seconds; `TimeoutExpired` is caught
  and re-raised as `AcmeError`.

### acme_cli.py

**Called by:** `issue_cert.sh`, `renew.sh`, `install_cert.sh`. Also callable manually.

CLI bridge between the shell scripts and the Python provider layer.

```bash
docker exec -it cppm-acme-cert-manager python3 /opt/cppm/acme_cli.py issue
docker exec -it cppm-acme-cert-manager python3 /opt/cppm/acme_cli.py issue --force
docker exec -it cppm-acme-cert-manager python3 /opt/cppm/acme_cli.py renew
docker exec -it cppm-acme-cert-manager python3 /opt/cppm/acme_cli.py install
docker exec -it cppm-acme-cert-manager python3 /opt/cppm/acme_cli.py revoke
```

Exit codes: `0` = action taken (issued/renewed/installed), `2` = not due
(renew only — used by `renew.sh` to distinguish "not due" from "error"),
`1` = error.

Reads server context from environment variables set by
`eval "$(cppm-servers env <id>)"` — the same env block used by all shell scripts.

---

## config_utils.py

**Used by:** `status_server.py`, `cppm_acme_manager_servers.py`, all shell scripts (via `cppm-servers env`).
**Never call directly.**

Python module providing the `servers.json` CRUD layer:

| Function | Description |
|---|---|
| `load_servers()` | Return all server entries as a list |
| `get_server(id)` | Return a single server entry by UUID |
| `add_server(entry)` | Validate, check for duplicate host, write |
| `update_server(id, entry)` | Replace an existing entry |
| `delete_server(id)` | Remove an entry |
| `get_server_shell_env(id)` | Return `export KEY='VALUE'` lines for `eval` in shell scripts |
| `migrate_from_env()` | One-time migration: reads legacy `.env` vars, writes first `servers.json` entry |

---

## cppm_acme_manager_servers.py (cppm-servers)

**Symlinked to:** `/usr/local/bin/cppm-servers`
**Usage:** `docker exec -it cppm-acme-cert-manager cppm-servers <command>`

CLI tool for managing ClearPass server entries in `servers.json`.

| Command | Description |
|---|---|
| `list` | Show all configured servers with ID, label, host, domain, DNS, and ACME CA |
| `ids` | Print one UUID per line — used internally by shell scripts |
| `show <id>` | Show full configuration; secrets displayed as `(set)` / `(empty)` |
| `add` | Interactive prompts to add a new server entry |
| `edit <id>` | Interactive prompts to edit an existing entry; Enter keeps current value |
| `delete <id>` | Prompt for confirmation then delete |
| `env <id>` | Print shell-sourceable `export KEY='VALUE'` lines — used by `entrypoint.sh`, `renew.sh`, `trust_check.sh` |

---

## cppm_acme_manager_users.py (cppm-users)

**Symlinked to:** `/usr/local/bin/cppm-users`
**Usage:** `docker exec -it cppm-acme-cert-manager cppm-users <command>`

CLI tool for managing web UI admin accounts stored in `admin.htpasswd`.

| Command | Description |
|---|---|
| `list` | Show all usernames |
| `add <username>` | Create a new user (prompts for password twice) |
| `passwd <username>` | Change an existing user's password |
| `delete <username>` | Delete a user (cannot delete your own account) |

---

## status.sh

Sourced by all scripts (`source /opt/cppm/status.sh`). Never call directly.

Provides `status_write LEVEL CATEGORY MESSAGE` which writes to the per-server
`/data/certs/<cppm_host>/status.log` (after `eval "$SERVER_ENV"` switches the
`STATUS_LOG` variable to the per-server path). Container-level startup events
write to the global `/data/certs/status.log`.

---

## Environment variables

Variables are split into two categories depending on where they are configured.

### Set in `docker-compose.override.yml` — container-level

These control Docker-level behaviour and must be known before the container
starts. They apply to the whole container, not to individual servers. Defaults
are defined in `docker-compose.yml`; override only what you need to change.

| Variable | Default | Description |
|---|---|---|
| `TZ` | `UTC` | Container timezone — used in log timestamps and cron scheduling |
| `STATUS_PORT` | `8080` | Web UI port (must match the host-side port in `docker-compose.yml`) |
| `CPPM_CALLBACK_PORT` | `8765` | PKCS12 delivery port (must match host-side port in `docker-compose.yml`) |
| `REQUIRE_AUTH_FOR_STATUS` | `false` | Require login to view the certificate dashboard |
| `SESSION_LIFETIME_HOURS` | `8` | Web UI session cookie lifetime in hours |
| `FORCE_RENEW` | `false` | Force certificate re-issuance on the next container start |
| `SKIP_UPLOAD` | `false` | Issue/renew certificates without uploading to ClearPass |
| `LOG_LEVEL` | `INFO` | Python log level for `clearpass_upload.py` (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

### Set per server in `servers.json` — managed via web UI or CLI

These are stored in `servers.json` and exported into the shell environment
by `eval "$(cppm-servers env <id>)"` before each server's cert pipeline runs.
Configure them through the web UI (**Servers → Add/Edit Server**) or via
`cppm-servers add` / `cppm-servers edit <id>`.

| Variable | Description |
|---|---|
| `DOMAIN` | FQDN for the certificate (e.g. `cppm.example.com`) |
| `ACME_EMAIL` | ACME account contact email |
| `ACME_SERVER` | ACME CA — `letsencrypt`, `letsencrypt_test`, `zerossl`, `buypass` |
| `DNS_PROVIDER` | Lego DNS plugin selector (e.g. `cloudflare`, `porkbun`, `route53`) |
| `CPPM_HOST` | ClearPass hostname or IP |
| `CPPM_CLIENT_ID` | ClearPass API client ID |
| `CPPM_CLIENT_SECRET` | ClearPass API client secret |
| `CPPM_VERIFY_SSL` | `true` / `false` — verify CPPM TLS certificate |
| `CPPM_CERT_PASSPHRASE` | PKCS12 export passphrase (transient — never stored on disk) |
| `CPPM_CALLBACK_HOST` | Docker host LAN IP that ClearPass can route to |
| `CPPM_CALLBACK_PORT` | Mirrors the container-level value for per-server use |
| `TRUST_EXCLUSIONS` | Newline-separated CA CN patterns to exclude from trust list operations |
| `CF_Token`, `CF_Zone_ID`, … | DNS provider credentials — keys vary by provider |
