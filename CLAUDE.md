# Project Status & Task Handoff

## Core Architecture & Tech Stack
- **Purpose:** Dockerized ACME certificate manager. Issues/renews certs (Let's Encrypt, Let's Encrypt staging, ZeroSSL, or custom ACME directory URL) via DNS-01 and deploys them to HPE Aruba ClearPass (CPPM) servers and, via the `linux_ssh` target type, arbitrary Linux services (e.g. Frigate). Version `2.2.0` (`VERSION`).
- **Stack:** Alpine 3.24 container, Python 3 (stdlib web UI, `cryptography` lib), POSIX shell, cron (`config/crontab`), Lego `5.5.2` (`ENV LEGO_VERSION` in `Dockerfile`). Optional Traefik overlay (`docker-compose.traefik.yml`, `.env.traefik.example`).
- **Layout:**
  - `scripts/acme_provider.py` – provider ABC + result types (`KeyTypeResult.chain_drift`, `IssueResult.chain_drift_detected`)
  - `scripts/lego_provider.py` – Lego v5 provider: `_lego_run_args`/`_lego_revoke_args`/`_lego_migrate_args`, `_TESTED_LEGO_VERSION` + `lego_version_warning()`, legacy-storage migration, `chain_drift_warning()` (growing-set TOFU baseline in `chain_baseline.json`)
  - `scripts/acme_cli.py` – CLI (`issue`/`renew`/`revoke`/`migrate`); `renew` exit codes 0 ok, 1 error, 2 (existing), 3 = chain drift detected
  - `scripts/status_server.py` – web UI/dashboard; `build_server_status()` must resolve entries via `resolve_target_fields()`
  - `scripts/config_utils.py` – `servers.json`, `target_type`/`target_config` shim, `_REQUIRED_BY_TYPE`
  - `scripts/clearpass_upload.py`, `ssh_upload.py`, `*_deploy_hook.sh` – deploy targets (`_DEPLOY_SCRIPTS` dispatch in `status_server.py`)
  - `scripts/renew.sh`, `issue_cert.sh`, `install_cert.sh`, `trust_check.sh`, `entrypoint.sh`, `status.sh` – orchestration
  - `scripts/dns_persist01.py` – DNS-PERSIST-01 scaffolding only (`_CA_CAPABLE` all False; not wired into issuance)
  - `scripts/dns_utils.py`, `auth_utils.py`, `notify.py`, `cppm_acme_manager_{servers,users}.py`
  - `tests/` (pytest, `pythonpath = scripts`), `docs/01–10*.md`, `tools/screenshot_docs.py` (Playwright)
- **Local-only planning docs (gitignored, not synced):** `LINUX_SSH_TARGET_PLAN.md`, `NEW_CENTRAL_NAC_TODO.md`.
- **Git:** branch `lego-v5-migration`, main branch `main`.

## Current Active Objectives
- [ ] Phase 2: DNS-PERSIST-01 (real IETF draft challenge type) – blocked on a supported CA shipping stable support; keep scaffolding only. Re-check the draft before touching `dns_persist01.py`: https://ietf-wg-acme.github.io/draft-ietf-acme-dns-persist/draft-ietf-acme-dns-persist.html
- [ ] CI gate: real staging-CA issuance on `LEGO_VERSION` bumps – deferred until DNS-PERSIST-01 is stable (no DNS credential in CI secrets).
- [ ] Phase 3: generalize beyond ClearPass (New Central NAC target per `NEW_CENTRAL_NAC_TODO.md`: first resolve open API questions, then add `"new_central"` to `_DEPLOY_SCRIPTS`).
- [ ] Audit remaining code for raw `servers.json` reads of nested Linux-SSH fields that bypass `resolve_target_fields()`.
- [ ] Remove temporary "nothing to migrate" log line in `_migrate_legacy_storage()` (`TODO`) once fleet confirmed off v4 storage.
- [ ] Verify ZeroSSL RSA intermediate CN (currently unverified; do not guess).

## State of the System
- **Completed:**
  - Phase 1 Lego v5 migration: flag migration, legacy storage auto-migration (backup + rollback, runs at container start), arg-builder centralization, version-drift warning; validated on lab server.
  - Chain-drift detection with immediate out-of-band trust-list upload (`renew.sh` `run_trust_check_for_members()`).
  - Buypass removed entirely (dead ACME service).
  - Linux SSH target working end-to-end with Frigate (key normalization, probe-collision race fix, target-aware UI, hostname display fix, Frigate TLS docs).
  - DNS-PERSIST-01 scaffolding + `docs/09-dns-persist-01-draft.md` tracking doc.
- **Blockers/Bugs:**
  - DNS-PERSIST-01: no supported CA has stable production support (Let's Encrypt staging implements draft 00, lacks `accounturi`; Boulder #8708). Record format already changed once (plain URI → hash).
  - Editing `scripts/*.py` does not affect a running container; rebuild and force-recreate (see commands).
  - `reload_command` using `docker restart` fails unless the SSH `deploy` user is in the docker group; clearing it works for Frigate (self-reloads ~60s).
  - Git status clean at last check; no known open code bugs.
- **Standing rules:** never run `git add`/`git commit` (user commits); never make the tool trigger disruptive ClearPass cluster actions (e.g. `POST /api/cluster/db-sync`); don't reintroduce acme-dns, provider-scoped credentials as "DNS-PERSIST-01", Buypass, or a static chain-CN table.

## Git & Collaboration Rules
- **CRITICAL:** Do NOT automatically stage (`git add`) or commit (`git commit`) any files.
- The human developer must review all file modifications and execute all Git operations manually.
- You may suggest commit messages in the chat bubble, but you do not have permission to execute git write commands.

## Explicit Development Commands
```bash
# Tests
pip install -r requirements-dev.txt
python -m pytest                      # uses pytest.ini (testpaths=tests, pythonpath=scripts)
python -m pytest tests/test_lego_provider.py -k chain_drift

# Build / run (Docker Compose)
docker compose build --no-cache
docker compose up -d --force-recreate cppm-acme-cert-manager   # plain `up -d` may skip recreation
docker compose logs -f cppm-acme-cert-manager

# Traefik overlay
docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d

# Docs screenshots (one-time browser install)
playwright install chromium && python tools/screenshot_docs.py

# First-time setup
./setup.sh
```
