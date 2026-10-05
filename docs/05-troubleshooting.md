# Troubleshooting

## Quick diagnosis checklist

```bash
# 1. Check the status log first
grep FAILED /opt/cppm-certs/status.log

# 2. Check the detailed logs
tail -50 /opt/cppm-certs/logs/startup.log                              # startup issues
tail -50 /opt/cppm-certs/<cppm_host>/logs/acme_renewal.log             # issuance / renewal
tail -50 /opt/cppm-certs/<cppm_host>/logs/cppm_upload.log              # ClearPass API issues

# 3. Check Docker container state
docker compose ps
docker compose logs --tail=50
```

> If you're asking someone else for help (or filing an issue), the web UI's
> server detail page has a **⬇ Download Logs** button (sign-in required)
> that zips up all of the logs above in one file — see
> [Downloading logs for support](03-monitoring.md#downloading-logs-for-support).
> No need to `docker exec` anything.

---

## Container exits immediately on start

**Cause:** A required environment variable is missing (`TZ`, `STATUS_PORT`, or
`CPPM_CALLBACK_PORT`) or the Lego binary is not found in the image.

```bash
docker compose logs | head -20
```

If the error is about a missing env var, set it in `docker-compose.override.yml`
and recreate:
```bash
docker compose up -d --force-recreate
```

If Lego is not found, rebuild the image:
```bash
docker compose build --no-cache && docker compose up -d
```

> **Note:** If no servers are configured in `servers.json`, the container logs
> a warning but stays running — it is waiting for you to add a server via the
> web UI or CLI. This is expected on a fresh install.

---

## `[: DEBUG: integer expression expected` in logs

**Cause:** The `DEBUG` environment variable is set to a non-numeric string.
Lego's Python wrapper pops `DEBUG` from the subprocess environment before each
invocation. If you still see this, check your host environment for a
string-valued `DEBUG` leaking into the container.

---

## DNS provider credential error

**Symptom:** Startup log shows `missing required field` for a server, or
`<PROVIDER> credentials missing`.

**Cause:** A server entry in `servers.json` is missing required DNS credential
fields. This is logged as a warning and the container skips that server — it
does not exit.

Fix: update the server entry in the web UI (**Servers → Edit**) or CLI:

```bash
docker exec -it cppm-acme-cert-manager cppm-servers edit <id>
```

| Provider | Required fields |
|---|---|
| Cloudflare | `CF_Token` **or** `CF_Key` + `CF_Email` |
| Porkbun | `PORKBUN_API_KEY` + `PORKBUN_SECRET_API_KEY` |
| Route53 | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| DigitalOcean | `DO_API_KEY` |
| GoDaddy | `GD_Key` + `GD_Secret` |
| Infoblox | `INFOBLOX_HOST` + `INFOBLOX_USERNAME` + `INFOBLOX_PASSWORD` |
| RFC 2136 | `RFC2136_NAMESERVER` (TSIG fields optional) |

---

## DNS-01 challenge fails — `DNS_API_ERROR` or TXT record not found

**Cause:** The DNS provider API credentials are valid but the TXT record
was not created, or did not propagate before the ACME server checked.

Common causes by provider:

- **Cloudflare:** Token missing `Zone:DNS:Edit` permission on the target zone.
- **Porkbun:** API access not enabled for the domain. Check
  **Domain Management → API Access** on the Porkbun dashboard.
- **Route53:** IAM policy missing `route53:GetChange` — Lego cannot poll for
  propagation without it.
- **DigitalOcean:** Token has read-only scope — must be write scope.
- **Infoblox:** Check that `INFOBLOX_HOST` is the Grid Master address (not a
  Grid Member), and that the user account has DNS record write permission on the
  target view. Set `INFOBLOX_SSL_VERIFY=false` if the Grid Master uses a
  self-signed certificate.
- **RFC 2136:** Verify the nameserver address and port are reachable from the
  container. If TSIG is configured, confirm the key name, secret, and algorithm
  match exactly what is configured on the DNS server. Unsigned updates
  (no TSIG) work if the nameserver allows them from the container IP.

Check the renewal log for the full Lego error:
```bash
tail -100 /opt/cppm-certs/<cppm_host>/logs/acme_renewal.log
```

---

## Authentication failed

**Symptom:** `upload.log` contains `HTTP 400 invalid_client`.

**Cause:** The `Client Secret` stored for the server is wrong, or the API
client is disabled in CPPM. The credentials are stored in `servers.json`
and configured via the web UI (**Servers → Edit**).

Test the credentials directly (the container's `eval` loop sets the env vars
from `servers.json` before this runs):

```bash
# First get a shell with the server's env vars set
eval "$(docker exec cppm-acme-cert-manager cppm-servers env <server-id>)"

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
```

Fix: verify the client secret in CPPM Admin UI under
**Administration → API Services → API Clients**, then update it in the web UI:
**Servers → Edit → Client Secret → Save Changes**.

---

## ClearPass API returns 403 Forbidden

**Cause:** The API client's Operator Profile lacks Certificate Management permission.

Fix: in CPPM Admin UI, verify the profile attached to your API client includes:
**Allow → All → Certificate Management**

---

## Container cannot resolve ClearPass hostname (DNS failure)

**Symptom:** The dashboard CPPM health dot shows red with a message like
*"Cannot resolve 'cppm.example.com'"*, or the Slack notification says
*"DNS resolution failed"*. The `acme_renewal.log` or `status.log` contains
`[Errno -3] Try again` or `Name or service not known`.

**Cause:** The container uses the DNS resolvers listed in the `dns:` block of
`docker-compose.yml`. By default these are the public resolvers `1.1.1.1` and
`8.8.8.8`, which cannot resolve internal/private hostnames such as
`cppm.corp.example.com`.

**Fix — option 1 (recommended): use the IP address**

Set the ClearPass host to the server's IP address in the web UI
(**Servers → Edit → ClearPass Host**). No Docker changes needed.

**Fix — option 2: add your internal DNS server**

Override the `dns:` setting in `docker-compose.override.yml` to include a
resolver that can reach your internal zone:

```yaml
# docker-compose.override.yml
services:
  cppm-acme-cert-manager:
    dns: !override
      - 192.168.1.53      # your internal DNS resolver — required
      - 1.1.1.1           # public resolver — also required, see note below
```

> **You must include both entries, not just the internal one.** Compose
> normally *appends* an override's `dns:` list to the defaults rather than
> replacing them — the `!override` tag here forces a full replacement. Without
> `!override`, the default public resolvers (`1.1.1.1`, `8.8.8.8`) would still
> be tried first, and since a resolver stops at the first answer it gets
> (even "no such name"), your internal resolver would never actually get
> queried. With `!override` in place, the two entries now split the work: the
> internal resolver handles your ClearPass hostname, the public one handles
> `acme-v02.api.letsencrypt.org` and your DNS provider API (Cloudflare,
> Route53, etc.) — dropping either one breaks that half of the lookups. Omit
> the public entry only if your internal resolver already forwards public
> queries itself.

After saving the override file:

```bash
docker compose down && docker compose up -d
```

**Fix — option 3: add a static host entry**

If you cannot change DNS, map the hostname directly:

```yaml
# docker-compose.override.yml
services:
  cppm-acme-cert-manager:
    extra_hosts:
      - "cppm.example.com:192.168.10.34"
```

Verify the hostname resolves from inside the container:

```bash
docker exec cppm-acme-cert-manager python3 -c "import socket; print(socket.gethostbyname('cppm.example.com'))"
```

---

## Outbound DNS (port 53) blocked by a firewall — common in DMZ deployments

**Symptom:** Same as the DNS failure above (`Cannot resolve '<host>'`), but the
dashboard/Slack message specifically says *"outbound DNS (port 53) appears
blocked"* and lists the nameservers it tried. This is distinct from the
previous case: there the resolver answered but didn't know the hostname; here
the resolver was **never reached at all**.

**Cause:** Containers run in a DMZ or other restricted network segment often
have egress firewall rules that only permit specific ports (e.g. 443). If
outbound UDP/TCP port 53 is blocked, **no DNS resolver configuration can fix
this** — the health check detects it by attempting a raw TCP connection to
each configured nameserver on port 53 and finding every attempt times out
(rather than failing fast with "connection refused" or a quick answer), which
is the signature of a firewall silently dropping the packets.

> **Important:** this doesn't only affect ClearPass hostname resolution. If
> port 53 is blocked, the ACME CA (`acme-v02.api.letsencrypt.org`) and your
> DNS provider's API (Cloudflare, Route53, etc.) will also fail to resolve,
> breaking certificate issuance and renewal entirely — not just the upload
> step.

**Fix — option 1 (required for full functionality): open port 53 outbound**

Ask your network/firewall team to permit outbound UDP and TCP port 53 from
the Docker host (or the container's network) to your DNS resolver. This is
the only fix that restores DNS-01 issuance/renewal, since those steps always
need to resolve the ACME CA and DNS provider API over DNS.

**Fix — option 2 (partial workaround): bypass DNS for the ClearPass hostname only**

If opening port 53 isn't possible and you only need ClearPass connectivity to
work (DNS-01 challenges are already succeeding some other way, or you're
troubleshooting upload specifically), pin the hostname with `extra_hosts`:

```yaml
# docker-compose.override.yml
services:
  cppm-acme-cert-manager:
    extra_hosts:
      - "cppm.example.com:192.168.10.34"
```

This does **not** fix ACME CA or DNS provider lookups — use option 1 for that.

**Verify port 53 reachability manually:**

```bash
docker exec cppm-acme-cert-manager python3 -c "
import socket
for ip in ('1.1.1.1', '8.8.8.8'):   # replace with your configured resolvers
    try:
        socket.create_connection((ip, 53), timeout=2).close()
        print(ip, 'reachable')
    except Exception as e:
        print(ip, 'blocked:', e)
"
```

A `timed out` result (as opposed to an immediate `refused` or success) points
to a firewall silently dropping the traffic.

---

## Cluster node returns 403 Forbidden

**Symptom:** The dashboard shows a cluster node with error
*"403 Forbidden — API client is not authorised on this cluster node"*.
The `status_server.log` contains `403 Client Error: Forbidden for url: https://<node-ip>/api/server-cert`.

**Cause:** In a ClearPass cluster, each node maintains its own API client
database. The API client created on the publisher may not yet exist (or may not
have been synced) on subscriber nodes. When the tool tries to query
`/api/server-cert` on a subscriber using a publisher-issued OAuth token, the
subscriber rejects it with 403.

**Fix:**

1. Log in to the ClearPass Admin UI at `https://<publisher-ip>/`.
2. Go to **Administration → API Services → API Clients**.
3. Confirm your API client exists and has the **Certificate Management**
   operator profile assigned.
4. Go to **Administration → Server Manager → Server Configuration** and check
   the **Cluster Sync** status for the subscriber node — this is where
   ClearPass reports whether that node is currently up to date with the
   publisher, rather than guessing from the outside.
5. If the node shows as synchronized there but the dashboard still shows 403,
   refresh the dashboard — this tool's own cluster-status cache can lag up to
   2 minutes behind ClearPass's actual state (see `_CLUSTER_TTL` in
   `status_server.py`).
6. If the node shows as **not yet synchronized**, give it time rather than
   intervening: ClearPass replicates configuration changes (including new API
   clients) on a batch interval — 5 seconds by default, configurable up to 60
   seconds under **Administration → Server Manager → Server Configuration →
   Cluster-Wide Parameters**. In practice, allow a few minutes end-to-end on
   top of that interval, since propagation across a larger cluster or a
   WAN-linked subscriber can take longer than the raw interval suggests.
   Re-check the Cluster Sync status on that page rather than timing it
   yourself — it will tell you definitively once the node has caught up.

If the subscriber node still returns 403 after replication:

- Check that the subscriber node is not in **Standby** mode — standby nodes
  may not serve the `/api/server-cert` endpoint.
- Verify the API client operator profile includes read access to
  **Administration → Server Manager** (needed to enumerate cluster nodes).
- As a workaround, disable Cluster Mode for this server in the web UI
  (**Servers → Edit → Cluster Mode**). The tool will continue to renew and
  upload certificates to the publisher; subscribers sync the certificate
  automatically via ClearPass cluster replication.

**Alternate cause — node has no FQDN set in ClearPass:** Per-node requests
are sent to the node's IP but with a `Host` header set to its FQDN, so
ClearPass can route/vhost-match the request correctly. That FQDN comes from
ClearPass's own cluster node list (`GET /api/cluster/server` —
`fqdn`/`server_dns_name`). If a node only has a short name configured
(e.g. `cppm02`, not `cppm02.example.com`), the tool falls back to deriving an
FQDN from the primary server's domain suffix (and logs a `WARNING` to
`status_server.log` / `cppm_upload.log` naming the node when it does), or
falls back to the short name as-is if no domain suffix is available. Either
fallback can still be rejected by ClearPass as a vhost mismatch.

**Fix:** In the ClearPass Admin UI, go to **Administration → Server Manager →
Server Configuration → `<node>` → General** and set a full FQDN for the node
(not just a short hostname). This removes the ambiguity the fallback is
compensating for and is the more reliable fix.

**Alternate cause — a call succeeds, then a later call on the same node 403s,
even using a token that was just validated:** If `cppm_upload.log` shows a
successful `POST /api/oauth → 200 OK` for a cluster node, and ANY subsequent
call to that same node 403s — this is different from the "client not yet
synced" case above, since the token mint itself proves the client already
exists on that node. On slower clusters, the node's local database can still
be a beat behind in propagating a config change (the token itself, or
something it depends on), so the node momentarily rejects a call it should
otherwise accept. This tends to be intermittent — the same run can succeed on
one call and fail moments later on the next, and it isn't necessarily limited
to the very first call after authenticating.

**Automatic handling:** the upload run retries a 403 from a cluster node up to
3 times, 5 seconds apart, for every call to that node. The **Check nodes**
status check checks all cluster nodes at the same time and waits up to 20
seconds in total. A lagging subscriber is retried up to 7 times, 2 seconds
apart. If a node is still being retried when the 20 seconds run out, it shows
with a blue **Still syncing** badge rather than an error, so you can press
**Check nodes** again in a minute. A node that accepts the API client after
one or more retries is marked "Accepted after N attempts (replication lag)". A
node that still returns 403 after all retries is shown as an error.

**Cluster timing in the status log:** each dashboard refresh of a cluster
server, and each **Check nodes** run on a saved server, writes `CLUSTER` lines
to that server's `status.log`. These give the
total check time and the slowest node, and record any node that was still
syncing, needed retries, or rejected the API client. Use them to find which
subscriber is slow to replicate before changing anything on the cluster. If a node keeps failing after these retries, the
cause is more likely a setup problem (API client, permissions, or an incomplete
Let's Encrypt or DNS configuration) than replication lag.

**To confirm a fix worked:** after making any of the changes above, check the
**Debug** checkbox next to **Upload to ClearPass** on the Servers page
(`/settings`) and click it. This sets `LOG_LEVEL=DEBUG` for that one run only
and logs the full per-node request/response detail — including the exact
`Host` header and HTTP status for each cluster node — to the **ClearPass
Upload** log tab (and the downloaded log bundle). See
[Debug checkbox](03-monitoring.md#server-list-actions) for details.

---

## Trust list upload returns 400 — cert is not a CA certificate

**Cause:** CPPM requires Basic Constraints: CA=TRUE for trust list entries.
End-entity (leaf) certificates cannot be added to the trust list.

The bundled ACME CA PEM files in the image are all CA/intermediate certs. If a chain
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

## HTTPS upload fails — `GET /api/cluster/server/this` returns error

**Symptom:** `upload.log` shows an error fetching the server's own UUID.

**Cause:** The API client's Operator Profile does not include read access to
cluster/server configuration.

Fix: ensure the Operator Profile attached to your API client includes read
access to **Administration → Server Manager** or equivalent.

---

## HTTPS/RADIUS upload fails — 422 "Cert File is empty or invalid post body"

**Cause:** The `PUT /api/server-cert/name/{uuid}/{service_name}` endpoint is
JSON-only. CPPM must fetch the PKCS12 from the `pkcs12_file_url` provided in
the request body. If CPPM cannot reach that URL, it times out and returns 422.

**Fix:** Ensure `CPPM_CALLBACK_HOST` is set correctly in the web UI (Servers →
Edit → Callback Host), `CPPM_CALLBACK_PORT` is correct in
`docker-compose.override.yml`, and the port is published:

```yaml
# docker-compose.override.yml
environment:
  CPPM_CALLBACK_PORT: "8765"
ports:
  - "8765:8765"
```

Find the correct callback IP:
```bash
ip route get <cppm-ip>
# Look for 'src X.X.X.X' — that's the interface toward CPPM
```

After updating the override file, restart the container:
```bash
docker compose down && docker compose up -d
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh
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
docker exec -it cppm-acme-cert-manager sh -c '
    CERT=/data/certs/cppm.example.com.ecc.cer
    KEY=/data/certs/cppm.example.com.ecc.key
    CM=$(openssl x509 -noout -pubkey -in $CERT | sha256sum)
    KM=$(openssl pkey  -noout -pubout -in $KEY  | sha256sum)
    [ "$CM" = "$KM" ] && echo "MATCH" || echo "MISMATCH – re-issue cert"
'
```

If mismatched, set `FORCE_RENEW: "true"` in `docker-compose.override.yml` and recreate the container.

---

## EAP authentication fails after cert install

**Cause:** An ACME CA cert is not in the trust list with EAP enabled.

```bash
# Force a re-run of the trust list pre-flight
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh
tail -f /opt/cppm-certs/<cppm_host>/status.log
```

Check the `TRUST` status lines. If any show `FAILED`, add the cert manually:

1. Copy the missing cert from the container (example for Let's Encrypt):
   ```bash
   docker cp cppm-acme-cert-manager:/opt/cppm/acme-ca-certs/isrg-root-x1.pem .
   ```
2. CPPM Admin UI → **Administration → Certificates → Trust List → Import**
3. Set `cert_usage` to include **EAP** and **Others** → Save.

> **Custom / Private CA:** If using a custom ACME CA, the bundled CA PEM files
> will not include your private CA chain. Add the root and intermediate certs
> manually to the CPPM trust list. The tool will only attempt to manage certs
> present in its bundled image set; unknown CA certs in the trust list are left
> untouched.

---

## ACME rate limit hit

**Symptom:** `acme_renewal.log` contains `too many certificates already issued`.

Switch to staging to test without hitting rate limits. Update the server entry
in the web UI: **Servers → Edit → Certificate Authority → Let's Encrypt (Staging) → Save Changes**,
then force a re-issue:

```bash
# Edit docker-compose.override.yml: FORCE_RENEW: "true"
docker compose up -d --force-recreate
```

Do not use staging certs in production. Switch back to **Let's Encrypt** in
the server edit form and wait 7 days before re-issuing production certs.

---

## Testing the pyclearpass SDK manually

```bash
# Drop into the container
docker exec -it cppm-acme-cert-manager python3

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

## Traefik troubleshooting

### Status card shows "Not reachable" after running compose

**Cause:** The compose command hasn't completed, Traefik is still issuing its
certificate, or the hostname does not resolve to this host.

Check the Traefik container state and log:

```bash
docker compose -f docker-compose.yml -f /opt/cppm-certs/docker-compose.traefik.yml ps
docker compose -f docker-compose.yml -f /opt/cppm-certs/docker-compose.traefik.yml logs traefik --tail=50
```

Or read the log from the web UI: **Settings → Traefik → Traefik Log** (bottom of page).

---

### Certificate stays "pending" — ACME issuance never completes

**HTTP-01:** Port 80 must be publicly reachable from the internet. Check your
firewall, router port-forwarding, and that no other process binds port 80.

```bash
# Verify port 80 is free before starting Traefik
ss -tlnp | grep ':80'
```

**DNS-01:** Check the Traefik log for `DNS_API_ERROR`. Common causes:

- Credentials in the compose overlay are wrong — re-save via **Settings → Traefik**
  to regenerate the file with current credentials.
- API token missing write permission on the target zone (same as ACME DNS troubleshooting above).
- DNS propagation timeout — increase `LEGO_CA_SERVER_TIMEOUT` or wait and retry.

---

### `no such file or directory` volume error on compose up

**Symptom:** `error while mounting volume... no such file or directory` for
`/opt/cppm-certs/traefik/dynamic` or similar.

**Cause:** The web UI has not written the config yet (compose file generated
before first Save), or `CPPM_DATA_PATH` is set to a path that doesn't exist.

**Fix:** Open **Settings → Traefik**, confirm the hostname and email are filled
in, and click **Save** again. Then re-run the compose command.

---

### Traefik starts but web UI shows HTTP (port 8080), not HTTPS

Port 8080 remains accessible directly — this is expected. Traefik serves
HTTPS on port 443 at your configured hostname. Navigate to
`https://<hostname>/` to use the secure URL. Port 8080 is kept open for
local/fallback access.

---

### Traefik container exits immediately

```bash
docker compose -f docker-compose.yml -f /opt/cppm-certs/docker-compose.traefik.yml logs traefik
```

Common causes:

- **Port conflict:** Another process (nginx, Apache, existing Traefik) is
  already bound to port 80 or 443. Stop it first.
- **Dynamic config missing:** Traefik's file provider watches
  `/opt/cppm-certs/traefik/dynamic/` — if the directory is empty or missing,
  Traefik still starts but logs a warning. Open **Settings → Traefik** and
  Save to regenerate the dynamic config.
- **Malformed compose overlay:** Re-save via **Settings → Traefik** to
  regenerate `docker-compose.traefik.yml` from the current settings.

---

### Hostname change not taking effect

Hostname changes are picked up immediately via Traefik's file-provider
hot-reload — no restart needed. If the new hostname is not working:

1. Confirm the new hostname resolves in DNS.
2. Check the Traefik log for a reload event: look for `Starting provider` or
   `Configuration reloaded`.
3. If using DNS-01, the new certificate issuance may take 1–2 minutes.

---

### PKCS12 callback still uses old HTTP address after enabling Traefik

The PKCS12 callback port (8765) is **not** routed through Traefik — ClearPass
connects to it directly. The **Callback Host** in **Servers → Edit** should
always be the Docker host LAN IP, not the Traefik hostname. This is expected
and does not need to change when enabling HTTPS.

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
