# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
- Cloudflare account- vs. profile-scoped API token support (auto-detected
  and cached at startup).

### Changed
- Migrated the ACME backend from Lego v4 to Lego v5.x, including a CLI
  flag/command rewrite, an arg builder with version-drift warnings, and
  automatic one-time account-storage migration on first v5 run.

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
