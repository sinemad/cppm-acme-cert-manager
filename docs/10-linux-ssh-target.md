# Linux SSH target

Deploy issued certificates to any Linux server over SSH — Apache, nginx,
Frigate, a Docker container, or anything else that reads a cert/key pair off
disk. No agent is required on the target; it uses the SSH server that's
already there.

---

## How it works

- **Transport**: plain `ssh`/`scp`/`ssh-keyscan` (no agent, no extra
  listening port on the target).
- **File layout**: one remote directory, two fixed filenames —
  `fullchain.pem` and `privkey.pem`. A deploy writes both as `.new` files,
  then atomically moves them into place.
- **Auth**: a pasted private key (recommended) or a password fallback.
  Either is accepted by `validate_server()` — at least one is required.
- **Reload**: an optional shell command run on the target immediately after
  a successful deploy (e.g. `sudo systemctl reload nginx`).
- **Cert type**: Linux SSH targets always issue and deploy the **ECC**
  certificate only, matching the single fullchain/privkey layout.

## Adding a target

In the web UI, **Add Server** → set **Target Type** to **Linux Server
(SSH)**. The CLI (`cppm-servers add`) offers the same choice.

| Field | Notes |
|---|---|
| Host / IP | The SSH server's address |
| Port | Defaults to 22 |
| SSH User | The account the private key/password authenticates as |
| Private Key | Pasted PEM — primary auth method |
| Password | Fallback, only needed if no key is set |
| Remote Cert Directory | Must already exist on the target, owned/writable by the SSH user |
| Reload Command | Optional — run on the target after each successful deploy |

## Host key verification (TOFU)

The first successful connection to a given host:port pins its SSH host key
to a dedicated `known_hosts` file under the servers.json directory
(`ssh_known_hosts/<host>_<port>.known_hosts`), shared by every server entry
that points at that host. Every later connection requires an exact match
(`StrictHostKeyChecking=yes`). If the host is ever reinstalled and its key
legitimately changes, the connection fails hard rather than silently
re-pinning — remove the stale file to allow re-pinning:

```bash
rm /opt/cppm-certs/ssh_known_hosts/<host>_<port>.known_hosts
```

Only do this after confirming the change was expected (a rebuild/reimage you
intended), not in response to an unexpected warning — a changed host key can
also mean a man-in-the-middle.

## Test Connection

Before (or after) saving a Linux SSH server, use the **Test Connection**
button in the form (or the CLI's "Test this connection now" prompt). It:

1. Pins the host key if not already pinned.
2. Writes, reads back, and deletes a probe file in the remote directory.
3. If the reload command starts with `sudo`, runs a non-destructive
   `sudo -n -l <command>` dry check — it never actually runs the reload
   command, since that can restart a live service.

On failure it reports the specific problem and a copy-pasteable fix, e.g.:

```bash
sudo mkdir -p /opt/acme-deploy/certs
sudo chown deploy:deploy /opt/acme-deploy/certs
sudo chmod 750 /opt/acme-deploy/certs
```

or, if the reload command needs a password:

```bash
echo 'deploy ALL=(root) NOPASSWD: systemctl reload nginx' | sudo tee /etc/sudoers.d/acme-deploy
```

## Target-side setup examples

All examples assume `remote_cert_dir` is `/opt/acme-deploy/certs`, owned by the
dedicated deploy account. This path is fully up to you (any directory the
deploy account can write to works) — `/opt/<app>` or `/var/lib/<app>` is used
here rather than `/etc` because `/etc` is conventionally root-owned host
configuration, not a location a low-privilege, unattended service account
should have write access to. Apache and nginx don't require certs to live
under `/etc/ssl` — their config directives accept any absolute path the
worker process can read.

### Apache (2.4.8+)

```apache
SSLCertificateFile      /opt/acme-deploy/certs/fullchain.pem
SSLCertificateKeyFile   /opt/acme-deploy/certs/privkey.pem
```

Reload command: `sudo systemctl reload apache2`

### nginx

```nginx
ssl_certificate      /opt/acme-deploy/certs/fullchain.pem;
ssl_certificate_key  /opt/acme-deploy/certs/privkey.pem;
```

Reload command: `sudo systemctl reload nginx` (nginx re-reads cert files on
reload without dropping connections).

**Optional — if other tooling on the box expects certs under the
conventional `/etc/ssl` path** (expiry monitors, config management, other
admins' muscle memory), symlink into it once, at setup time:

```bash
sudo ln -s /opt/acme-deploy/certs/fullchain.pem /etc/ssl/certs/myapp-fullchain.pem
sudo ln -s /opt/acme-deploy/certs/privkey.pem   /etc/ssl/private/myapp-privkey.pem
```

then point Apache/nginx at the `/etc/ssl/...` symlink paths instead. This
only needs to be done once — this tool's atomic `.new`-then-`mv` deploy keeps
overwriting the real file at the stable `/opt/acme-deploy/certs/...` path on
every renewal, so the symlink never goes stale and never needs to be
recreated.

### Frigate (docker-compose)

Frigate's TLS cert path is hardcoded to `/etc/letsencrypt/live/frigate`
inside the container — it is not configurable via `config.yml` or an env
var — so the container-side mount path must be that fixed path, not the
host's `remote_cert_dir`:

```yaml
services:
  frigate:
    volumes:
      - /opt/acme-deploy/certs:/etc/letsencrypt/live/frigate:ro
```

See Frigate's own [TLS docs](https://docs.frigate.video/configuration/tls/)
for the authoritative requirements. No reload command is needed: Frigate
compares the fingerprint of `fullchain.pem` against its running NGINX cert
once a minute and reloads NGINX itself when they differ. Frigate's docs
don't explicitly cover ECC certs or a key-only change (no fullchain
change), so leaving a `docker restart frigate` reload command configured
is a harmless fallback if you want to be certain a renewal takes effect
immediately rather than within a minute.

### Generic Docker container

Bind-mount the same host directory read-only into the container at whatever
path it expects. Reload command is whatever that container needs — a
`docker kill -s HUP <container>` for services that reload on SIGHUP, or
`docker restart <container>` otherwise.

The web UI's Add/Edit Server form includes a "Show me how to configure..."
helper that reproduces these same snippets inline, substituting your actual
`remote_cert_dir` path, with a button to copy the suggested reload command
directly into the form.

## Security note

Like ClearPass client secrets and DNS provider API tokens, the SSH private
key and password are stored in `/data/certs/servers.json` in plaintext,
`chmod 600`, never committed to the repo. This is the same trust boundary
already used for every other credential this tool manages — protect that
file (and the host it lives on) accordingly.

**Use a dedicated deploy key, not your personal SSH key.** Generate one just
for this tool:

```bash
ssh-keygen -t ed25519 -f ./acme-deploy-key -N "" -C "acme-deploy"
```

(no passphrase — the key is used unattended). Add only
`acme-deploy-key.pub` to a low-privilege account's `authorized_keys` on the
target, not `root` or your own account, and scope that account to just the
certificate directory (plus a narrow `sudoers` rule if the reload command
needs elevation — see [Test Connection](#test-connection) above). Paste the
private half into the Private Key field. This way, if `servers.json` or a
backup of it ever leaks, the exposure is limited to "can write certs to one
directory and run one reload command on one host" instead of every system
that trusts your personal key. The web UI's Add/Edit Server form and the
CLI's `add`/`edit` flow both surface this same guidance inline next to the
Private Key field.

**The deploy account needs a real login shell — not `nologin`/`false`.**
It's tempting to lock the account down with `/usr/sbin/nologin` the way
you would for most service accounts, but this tool's deploy step runs as
`ssh deploy@host 'mv ... && mv ...'` (and the reload command the same way)
— both are still shell invocations under the hood, even though nothing
about them looks like an interactive login. A `nologin` shell makes sshd
reject those commands, so every deploy fails at the `mv` step even though
the SSH connection itself succeeds — and the failure can be non-obvious
since the SCP upload before it still works. Give it `/bin/bash` or
`/bin/sh` instead. This doesn't weaken the account: it still can't get an
*interactive* login unless someone has its password (it has none — auth
is key-only) or physical/console access, and `authorized_keys` only
accepts the one key you installed.

**Scope the account to one directory, nothing else.** Give it its own
home directory and own the certificate directory under it (not something
shared like `/etc` or `/var/www`), so a compromised key can only write
certs to that one path and, if you added one, run the one reload command
your `sudoers` rule names — never arbitrary commands, never other users'
files.

See [Best practice: full setup walkthrough](#best-practice-full-setup-walkthrough)
below for the exact commands to set all of this up from scratch.

### Best practice: full setup walkthrough

Assumes you're comfortable at a Linux shell but haven't set this up
before. Run these on the **target** unless noted otherwise. See the
[Security note](#security-note) above for the reasoning behind each
choice.

**1. Create the deploy account:**

```bash
sudo useradd --system --create-home --home-dir /opt/acme-deploy \
    --shell /bin/bash deploy
```

**2. Create and lock down the certificate directory:**

```bash
sudo mkdir -p /opt/acme-deploy/certs
sudo chown deploy:deploy /opt/acme-deploy/certs
sudo chmod 750 /opt/acme-deploy/certs
```

**3. Generate the deploy keypair** — on your own machine, not the target:

```bash
ssh-keygen -t ed25519 -f ./acme-deploy-key -N "" -C "acme-deploy"
```

**4. Install the public key on the target**, into the deploy account's
`authorized_keys`:

```bash
sudo mkdir -p /opt/acme-deploy/.ssh
sudo cp acme-deploy-key.pub /opt/acme-deploy/.ssh/authorized_keys
sudo chown -R deploy:deploy /opt/acme-deploy/.ssh
sudo chmod 700 /opt/acme-deploy/.ssh
sudo chmod 600 /opt/acme-deploy/.ssh/authorized_keys
```

**5. (Optional) If the reload command needs root**, e.g.
`sudo systemctl reload nginx`, add a narrow `sudoers` rule scoped to
exactly that command — see the snippet under
[Test Connection](#test-connection) above. Skip this if the target
doesn't need a reload (e.g. a container that re-reads certs on its own).

**6. Verify the key works** before touching this tool at all:

```bash
ssh -i ./acme-deploy-key deploy@<host> 'touch /opt/acme-deploy/certs/probe && rm /opt/acme-deploy/certs/probe && echo OK'
```

**7. In this tool**, add the server with:
- **SSH User**: `deploy`
- **Private Key**: the private half from step 3
- **Remote Cert Directory**: `/opt/acme-deploy/certs`
- **Reload Command**: whatever step 5 scoped, or blank

Then use [Test Connection](#test-connection) to confirm read/write/delete
access (and the sudo dry-check, if a reload command is set) before saving.
