# Maintenance

## Rebuilding the container

Safe to do at any time. The certificate data and server configuration in
`/opt/cppm-certs/` are never touched by a rebuild.

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

On restart the container sees the existing flat `.cer` files, logs the expiry,
and starts crond. No re-issue, no upload — nothing happens until renewal is due.

---

## Updating server credentials

ClearPass credentials, DNS provider keys, domain, and ACME settings are all
stored in `servers.json`. Update them through the web UI — no container restart
is needed for credential changes.

1. Browse to `http://<docker-host>:8080/`
2. Navigate to **Servers → Edit** on the server you want to update.
3. Change the relevant fields and click **Save Changes**.

The updated credentials are used on the next cert pipeline run (renewal, manual
upload, or container restart).

### CLI alternative

```bash
docker exec -it cppm-acme-cert-manager cppm-servers edit <id>
```

---

## Updating docker-compose.override.yml settings

`docker-compose.override.yml` controls container-level behaviour — ports,
timezone, and operational flags. If you change `STATUS_PORT`,
`CPPM_CALLBACK_PORT`, or `TZ`, recreate the container to pick up the changes:

```bash
docker compose up -d --force-recreate
```

> When changing a port, update **both** the `environment` section and the
> `ports` section in the override file so the two sides stay in sync.

---

## Enabling SSL verification

After the certificate is installed and CPPM is accessible via trusted HTTPS:

```bash
# Confirm CPPM is serving the new cert
openssl s_client -connect cppm.example.com:443 \
    -servername cppm.example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -dates
```

Then enable SSL verification in the web UI:
**Servers → Edit → Verify SSL → enable → Save Changes**

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

## Manually run install only

If Lego has the cert in its internal state but the flat files are missing
(visible in `status.log` as "Flat files missing"):

```bash
docker exec -it cppm-acme-cert-manager /opt/cppm/install_cert.sh
```

No DNS challenge is performed. No contact with the ACME CA.

---

## Force a full certificate re-issue

Use this to rotate the certificate before it is due (e.g. key compromise,
CPPM migration):

```bash
# 1. Set the flag in docker-compose.override.yml:
#      FORCE_RENEW: "true"
docker compose up -d --force-recreate
docker compose logs -f
# Wait for "New certificate issued" and "Upload succeeded" in the logs

# 2. Clear the flag when done:
#      FORCE_RENEW: "false"
docker compose up -d --force-recreate
```

---

## Rotate the PKCS12 export passphrase

Update the passphrase in the web UI: **Servers → Edit → Cert Passphrase → Save Changes**,
then re-upload so CPPM receives a PKCS12 encrypted with the new passphrase:

```bash
docker exec -it cppm-acme-cert-manager /opt/cppm/deploy_hook.sh
```

---

## Trust list verification

The ACME CA and intermediate CA certificates in the ClearPass trust list are
checked and repaired automatically on two schedules:

| Schedule | Trigger | What runs |
|---|---|---|
| After every cert issuance or renewal | Automatic via `deploy_hook.sh` | Trust check + HTTPS + RADIUS upload |
| Weekly — Sunday 03:00 container-local | Automatic via `trust_check.sh` | Trust check only (no cert upload) |

### Run the trust list check manually

```bash
docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh
```

Output appends to each server's `/opt/cppm-certs/<cppm_host>/.logs/cppm_upload.log`
and records a `TRUST` entry in the per-server `status.log`.

---

---

## Switching DNS provider or ACME server

To change the DNS provider, ACME certificate authority, or any other per-server
setting, update the server entry in the web UI:

**Servers → Edit → change the relevant fields → Save Changes**

The existing certificates on the volume are unaffected. Only new issuances and
renewals use the updated settings.

### CLI alternative

```bash
docker exec -it cppm-acme-cert-manager cppm-servers edit <id>
```

---

## Check the scheduled task list

```bash
# View the full cron schedule inside the container
docker exec -it cppm-acme-cert-manager cat /etc/crontabs/root
```

---

## Automatic log review

Each ClearPass server has its own `status.log` at `/opt/cppm-certs/<cppm_host>/status.log`
(also viewable in the web UI under **Activity Log**). During normal operation
you will see entries like the following — no action is required.

**Connectivity health (on first check and whenever status changes):**
```
2026-06-03 01:00:00 | OK     | CPPM     | Connected
2026-06-03 01:00:00 | OK     | DNS      | Token valid
2026-06-03 01:00:00 | OK     | CALLBACK | Reachable at http://192.168.1.100:8765/
```

**Daily renewal checks (02:00 and 14:00):**
```
2026-04-01 02:00:01 | INFO   | RENEW   | Not due for renewal – 75 days remaining (next check in 12h)
```

**Weekly trust list check (Sunday 03:00):**
```
2026-06-08 03:00:07 | OK     | TRUST   | 9 CA certs verified – 0 uploaded, 0 patched, 9 already trusted
```

For detailed Lego renewal output see `acme_renewal.log`; for full ClearPass
API upload logs see `cppm_upload.log`. Both are in
`/opt/cppm-certs/<cppm_host>/.logs/` and are also accessible in the web UI
(sign-in required) on the server detail page.

---

## Admin user management

### Web UI

Navigate to **Users** in the top navigation bar (sign-in required).

| Action | How |
|---|---|
| Add user | Fill in the **Add User** form |
| Change password | Select a user in the **Change Password** form |
| Delete user | Click **Delete** on the user row → confirm inline |

You cannot delete your own account while signed in. If the last user is deleted
the setup wizard becomes available again on the next page load.

### CLI

```bash
# Add a user (prompts for password)
docker exec -it cppm-acme-cert-manager cppm-users add <username>

# Change a password
docker exec -it cppm-acme-cert-manager cppm-users passwd <username>

# Delete a user
docker exec -it cppm-acme-cert-manager cppm-users delete <username>

# List all users
docker exec -it cppm-acme-cert-manager cppm-users list
```

Credentials are stored in `/opt/cppm-certs/admin.htpasswd` (bcrypt hashed,
chmod 600) and survive container rebuilds.

---

## ClearPass server configuration

Server entries are managed via the **Servers** page in the web UI or the CLI.
They are stored in `/opt/cppm-certs/servers.json` (chmod 600) and persist
across container rebuilds alongside the certificates.

```bash
# View current server configurations (credentials stored as plaintext — handle carefully)
cat /opt/cppm-certs/servers.json

# Back up before changes
cp /opt/cppm-certs/servers.json /opt/cppm-certs/servers.json.bak
```

### CLI server management

```bash
# List all servers (shows IDs needed for other commands)
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

## Shell into the container

```bash
docker exec -it cppm-acme-cert-manager bash

# Useful commands once inside:
lego --path /data/certs/cppm.example.com/lego-ecc list  # show ECC certs known to Lego
lego --path /data/certs/cppm.example.com/lego-rsa list  # show RSA certs known to Lego
cat /data/certs/status.log             # view status log
cat /data/certs/servers.json           # view server configuration
```
