# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Certificate Profile editor: a first-class way to edit the ACME/DNS
  config shared by every server entry on the same Certificate Profile ID in
  one place (web `/settings/profiles` and `cppm-servers profiles` /
  `edit-profile` / `detach-profile`), instead of editing it per-server where
  a shared field silently got overwritten on save.
- Certificate Profile ID is now a required field (web and CLI), auto-
  suggested from the target's domain/host but editable, so every server
  entry always shows up under Certificate Profiles. Existing entries are
  backfilled automatically on container startup using the ID they were
  already implicitly grouped under.
- A warning is now shown before saving if a typed Certificate Profile ID
  matches a *different* existing profile, since that save will silently
  adopt that profile's ACME/DNS config.
- Rename Certificate Profile (web `/settings/profiles/edit/<id>` and CLI
  `cppm-servers rename-profile <old-id> <new-id>`): renames the Certificate
  Profile ID across every target that shares it, and moves the on-disk
  certificate directory to match, so already-issued certificates and Lego
  account state are kept rather than triggering a fresh issuance.
- Linux SSH target's Private Key field (web and CLI) now shows inline
  best-practice guidance to generate a dedicated deploy keypair rather than
  reusing a personal SSH key, with the `ssh-keygen` command and account
  scoping steps.
- Linux SSH target: a new `linux_ssh` target type that deploys issued
  certificates to any Linux server over SSH (Apache, nginx, Frigate, Docker
  containers, etc.) and runs a configurable reload command — no agent
  required on the target. Uses plain `ssh`/`scp`/`ssh-keyscan`, TOFU host-key
  pinning (shared per host across server entries, hard-fails rather than
  silently re-pinning if a host key ever changes), key-primary/
  password-fallback auth, and a fixed `fullchain.pem`/`privkey.pem` remote
  layout.
- Test Connection smoke test for Linux SSH targets: verifies read/write/
  delete access to the remote certificate directory and, for `sudo`-prefixed
  reload commands, a non-destructive `sudo -n -l` dry check — available
  live in the Add/Edit Server form (before the entry is even saved) and in
  the `cppm-servers add`/`edit` CLI flow. On failure it returns the specific
  problem plus copy-pasteable remediation commands (`mkdir`/`chown`/`chmod`,
  or a scoped sudoers snippet).
- "Show me how to configure..." inline helper in the Add/Edit Server form:
  Apache/nginx/Frigate/Docker config snippets and suggested reload commands,
  templated live from the server's own `remote_cert_dir` value.
- [Linux SSH Target](docs/10-linux-ssh-target.md) documentation.
- DNS Credentials: DNS vendor credentials (provider + API tokens/keys) are
  now a first-class, reusable entity separate from Certificate Profiles
  (web `/settings/dns-credentials` and `cppm-servers dns-credentials` /
  `add-dns-credential` / `edit-dns-credential` / `rename-dns-credential` /
  `delete-dns-credential`), so the same DNS vendor account can be shared
  across multiple Certificate Profiles without re-entering its credentials.
  Certificate Profiles now reference a DNS Credential by ID
  (`dns_credential_id`) instead of embedding `dns_provider`/
  `dns_credentials` directly. Existing entries are migrated automatically
  on container startup, deduplicating identical provider/credential pairs
  onto a single shared DNS Credential. The CLI's Infoblox and RFC 2136
  credential field prompts, previously missing, are now included.

### Fixed
- Linux SSH target: the dashboard overview, per-server detail page, and their
  live-refresh paths all read the host to display from `cppm_host` only, so
  a `linux_ssh` server's card/page showed a blank hostname and its status
  dot never updated after the first page load (the refresh loop only ever
  looked at the ClearPass health check, not the SSH one). Both now resolve
  `ssh_host` for `linux_ssh` targets. Also renamed the dashboard's "ClearPass
  Server" column header to "Server" and the per-server "ClearPass Upload"
  log tab to read "Linux Upload" for `linux_ssh` targets, matching the
  earlier Settings-page rename.
- Linux SSH target: the connection smoke test (dashboard health check and
  "Test Connection" button) named its remote probe file using only the
  server process's PID, which is constant for the lifetime of the
  long-running web process. Two overlapping checks for the same server
  (e.g. a background health-check poll racing a manual Test Connection
  click) shared one filename, so one call's cleanup could delete the probe
  file between another call's write and read, producing an intermittent,
  bogus "cannot read back" failure with no actual permission problem. The
  probe filename is now unique per call.
- Linux SSH target: a pasted private key with CRLF line endings or trailing
  per-line whitespace (common when copy/pasting through a browser textarea,
  especially from Windows) could fail to load with a misleading
  `error in libcrypto: unsupported` SSH error instead of a clear format
  error. The temp key file written for each SSH/SCP call is now normalized
  to LF-only before use.
- Linux SSH target's Frigate setup snippet (docs and the Add/Edit Server
  form's "Show me how to configure..." helper) mounted the host cert
  directory at the same path inside the container
  (`{{DIR}}:{{DIR}}:ro`), but Frigate's cert path is hardcoded to
  `/etc/letsencrypt/live/frigate` and is not configurable — the mount now
  targets that fixed path. Also notes that Frigate hot-reloads on its own
  (polls `fullchain.pem`'s fingerprint every minute), so the suggested
  `docker restart frigate` reload command is an optional fallback, not a
  requirement.

### Changed
- `openssh-client` and `sshpass` added to the container image for the Linux
  SSH target's SSH/SCP/password-auth support.
- Linux SSH target's suggested `remote_cert_dir` (form placeholder, CLI hint,
  docs, Test Connection's remediation commands) changed from
  `/etc/ssl/cppm-acme` to `/opt/acme-deploy/certs` — `/etc` is conventionally
  root-owned host config, not a location a low-privilege unattended deploy
  account should write to. Apache/nginx config directives accept any
  readable path, so this doesn't require a code change; docs note an
  optional one-time symlink into `/etc/ssl/...` for sites that want certs
  discoverable at the conventional path.
- Suggested deploy-key filename, SSH key comment, and sudoers rule name
  (web, CLI, docs) renamed from `cppm-deploy-key`/`cppm-acme-*` to
  `acme-deploy-key`/`acme-deploy` — these are example names written onto
  *target* Linux servers, and `cppm` is ClearPass-specific, not meaningful
  for non-ClearPass targets (Frigate, generic Docker, etc.) or in light of
  an eventual project rename. The container/CLI command names
  (`cppm-acme-cert-manager`, `cppm-servers`) are unchanged for now — that's
  a separate, larger rename tracked for later.

## [2.2.0] - 2026-10-19

### Added
- Cross-chain trust support: newly discovered ACME intermediate CAs are
  detected via chain-drift monitoring and automatically uploaded to the
  ClearPass trust list as they're observed, instead of waiting for the
  weekly trust check.
- Chain-drift (TOFU) detection: renewals/issuances now compare the signing
  intermediate's CN against a per-CA/key-type baseline and flag/log when a
  new one appears.
- Dependabot and Renovate bot support to track Lego and Traefik upstream
  releases.
- Split horizon DNS support, including an advanced UI option, a detection
  script that warns on split-horizon misconfiguration, and documentation.
- Split-horizon DNS pre-flight check: a server's domain is now also checked
  for a split-horizon mismatch right when it's added or edited (web UI and
  CLI), instead of only surfacing the warning later in the dashboard or
  renewal log.
- Cloudflare account- vs. profile-scoped API token support (auto-detected
  and cached at startup).
- Groundwork for non-ClearPass targets (HPE New Central NAC, Mist Access
  Assurance, generic Linux certificate consumers, etc.): a `target_type`
  field and per-type required-field validation, with `"clearpass"` as the
  only implemented type today. Existing `servers.json` entries are
  unaffected — ClearPass config can keep living as flat top-level fields,
  or (for future target types) move into a nested `target_config` block,
  without a migration step.

### Changed
- Migrated the ACME backend from Lego v4 to Lego v5.x, including a CLI
  flag/command rewrite, an arg builder with version-drift warnings, and
  automatic one-time account-storage migration on first v5 run.
- `deploy_hook.sh` renamed to `clearpass_deploy_hook.sh` and the cert
  pipeline's upload step now dispatches by `target_type`, so future target
  types register their own deploy script instead of patching this one.

### Removed
- Legacy `acme.sh` provider and all related dead code/docs (superseded by
  the Lego migration completed in earlier releases).
- Buypass CA option (its ACME service has been discontinued).

### Fixed
- Wildcard certificate filenames containing `*` no longer break on
  Linux/UNIX filesystems.
- Callback server status check now correctly inspects the upload lock and
  reports the real cause (port conflict vs. upload in progress).
- OAuth bearer token re-minting now uses `expires_on - 30s` (tunable via
  env var) instead of a fixed schedule, and tokens are shared/cached across
  the four places that previously minted them independently.

## [2.1.1] - 2026-10-02

### Added
- Docker/DNS override documentation: clarified that public DNS resolvers
  must be included alongside internal ones in `docker-compose.override.yml`.
- Detection for containers running where port 53 may be blocked (e.g. a
  DMZ), with a startup warning.
- Cluster node configuration consistency checks, with clearer DNS
  resolution warnings and new troubleshooting docs for clusters/DNS.
- Node FQDN derivation fallback — falls back to IP when a node has no FQDN
  configured.
- Instructions for pulling the latest version from git.

### Fixed
- Certificate status UI no longer wraps awkwardly and no longer shows
  status for disabled certificates.
- Certificate upload bug and DNS propagation delay (switched to recursive
  nameserver checks).
- ClearPass cluster API/login fixes: node IP/hostname mapping, callback URL
  resolution when hostname isn't resolvable, and `APILogin` error.
- Trust list certificate usage issues (RADIUS cert usage, general trust
  store usage).

### Changed
- Home page redesigned to show RADIUS/RadSec certificates and cluster
  nodes; add-server page reuses existing certificate profiles.
- Added cluster mode support for ClearPass cluster deployments.
- ACME renewal decoupled from the ClearPass upload step so the same
  certificate can be reused across targets; added renewal support for
  RADIUS, RadSec, HTTPS(RSA), and HTTPS(ECC).
- Added SAN DNS field support for ACME renewal and server add.
- Initial Traefik integration: setup wizard, status reporting, and reduced
  manual configuration steps.
- Online help added to the web UI.

## [2.1.0] - 2026-06-09

### Added
- Admin notification framework (ACME, DNS, and ClearPass success/error
  events).

### Fixed
- Notification bugs (email notifications temporarily disabled pending
  further work).

## [2.0.0] - 2026-06-08

### Added
- **Lego-based ACME client** (replacing the original implementation),
  chosen for its MIT license and to enable future Traefik integration for
  the web UI.
- Support for Infoblox, RFC2136 (Active Directory DNS, etc.), and private
  ACME server endpoints.
- "Renew cert" and "Upload to ClearPass" manual action buttons, with
  Let's Encrypt rate-limit warnings.
- Basic unit test suite.

### Changed
- Abstracted the ACME layer behind a provider interface ahead of the Lego
  migration.

### Removed
- Trust exclusion feature (removed as unnecessary — users don't control
  which CA ultimately issues the cert).

### Fixed
- RSA certificates not being uploaded; stale DNS TXT records left behind
  after failures; stale Lego state causing generation errors after a query
  failure; incorrect `--accept-tos` flag placement; callback server port
  race condition (now mutex-protected); date display bug in the activity
  log.

## [1.1.0] - 2026-06-03

### Changed
- Reorganized the persistent certificate directory to support multiple
  ClearPass servers and per-server logging.
- Added build versioning (introduced the `VERSION` file).

### Fixed
- Server status indicator ("status dot") display issues.

## [1.0.0] - 2026-06-03

Initial release.
