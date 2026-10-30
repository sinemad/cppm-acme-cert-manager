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
sudo mkdir -p /etc/ssl/cppm-acme
sudo chown deploy:deploy /etc/ssl/cppm-acme
sudo chmod 750 /etc/ssl/cppm-acme
```

or, if the reload command needs a password:

```bash
echo 'deploy ALL=(root) NOPASSWD: systemctl reload nginx' | sudo tee /etc/sudoers.d/cppm-acme-deploy
```

## Target-side setup examples

All examples assume `remote_cert_dir` is `/etc/ssl/cppm-acme`.

### Apache (2.4.8+)

```apache
SSLCertificateFile      /etc/ssl/cppm-acme/fullchain.pem
SSLCertificateKeyFile   /etc/ssl/cppm-acme/privkey.pem
```

Reload command: `sudo systemctl reload apache2`

### nginx

```nginx
ssl_certificate      /etc/ssl/cppm-acme/fullchain.pem;
ssl_certificate_key  /etc/ssl/cppm-acme/privkey.pem;
```

Reload command: `sudo systemctl reload nginx` (nginx re-reads cert files on
reload without dropping connections).

### Frigate (docker-compose)

```yaml
services:
  frigate:
    volumes:
      - /etc/ssl/cppm-acme:/etc/ssl/cppm-acme:ro
```

The container only reads the files, so the atomic `mv` on deploy is usually
enough on its own. Reload command (only if the service doesn't hot-reload):
`docker restart frigate`

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
