#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# entrypoint.sh – Container startup
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LEGO_BIN="/usr/local/bin/lego"
CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

[[ -x "$LEGO_BIN" ]] || { echo "[ERROR] lego not found at $LEGO_BIN. Rebuild the image."; exit 1; }

mkdir -p "$LOG_DIR" "$CERT_DIR"
LOG="${LOG_DIR}/startup.log"
touch "$LOG"

# Source status library. Container-level events write to the global status.log;
# per-server events write to <SERVER_CERT_DIR>/status.log after eval.
# shellcheck source=status.sh
source /opt/cppm/status.sh
GLOBAL_STATUS_LOG="$STATUS_LOG"

# A non-numeric DEBUG value inherited from the host (e.g. DEBUG=true) can
# cause Alpine ash to throw "sh: DEBUG: out of range" in child processes.
unset DEBUG

log()  { echo "[$(ts)] [INFO ] $*" | tee -a "$LOG"; }
warn() { echo "[$(ts)] [WARN ] $*" | tee -a "$LOG"; }
err()  { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }
die()  { err "$*"; status_write "FAILED" "STARTUP" "$*"; exit 1; }

LEGO_VER=$("$LEGO_BIN" --version 2>&1 | head -1 || echo "lego (version unknown)")
log "=== ClearPass Certificate Manager v2.0 ==="
log "lego    : $LEGO_VER"
status_write "INFO" "STARTUP" "Container started – lego=${LEGO_VER}"

# ── Migrate .env → servers.json (backwards compatibility) ─────────────────────
log "Checking server configuration..."
MIGRATE_MSG=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import migrate_from_env
result = migrate_from_env()
if result:
    print(result)
" 2>&1) || true
if [[ -n "$MIGRATE_MSG" ]]; then
    log "  Migrated .env configuration to servers.json: $MIGRATE_MSG"
fi

# ── Load server IDs from servers.json ─────────────────────────────────────────
SERVER_IDS=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import load_servers
for s in load_servers():
    sid = s.get('id', '')
    if sid:
        print(sid)
" 2>/dev/null || echo "")

if [[ -z "$SERVER_IDS" ]]; then
    warn "No servers configured."
    warn "  Add one via the web UI after startup: http://<host>:${STATUS_PORT:-8080}/settings"
    warn "  Or via CLI: docker exec -it cppm-acme-cert-manager cppm-servers add"
    status_write "WARN" "STARTUP" "No servers configured – add one via the web UI or cppm-servers add"
fi

# ── Helper – run a script and keep the container alive on failure ─────────────
run_with_guard() {
    local script="$1"
    if "$script" 2>&1 | tee -a "$LOG"; then
        return 0
    else
        local exit_code=${PIPESTATUS[0]}
        err "$script failed (exit $exit_code). Container will stay running."
        err "Retry manually: docker exec -it cppm-acme-cert-manager $script"
        return 1
    fi
}

# ── Validate DNS credentials for a provider ───────────────────────────────────
validate_dns_creds() {
    local provider="${DNS_PROVIDER:-}"
    local missing=0
    case "${provider,,}" in
        cloudflare|cf)
            if [[ -z "${CF_Token:-}" && ( -z "${CF_Key:-}" || -z "${CF_Email:-}" ) ]]; then
                err "Cloudflare credentials missing: set CF_Token (preferred) or CF_Key + CF_Email"
                missing=$((missing+1))
            fi
            ;;
        porkbun)
            [[ -z "${PORKBUN_API_KEY:-}" ]]        && { err "Missing: PORKBUN_API_KEY";        missing=$((missing+1)); }
            [[ -z "${PORKBUN_SECRET_API_KEY:-}" ]] && { err "Missing: PORKBUN_SECRET_API_KEY"; missing=$((missing+1)); }
            ;;
        route53|aws|r53)
            [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]     && { err "Missing: AWS_ACCESS_KEY_ID";     missing=$((missing+1)); }
            [[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]] && { err "Missing: AWS_SECRET_ACCESS_KEY"; missing=$((missing+1)); }
            ;;
        digitalocean|do)
            [[ -z "${DO_API_KEY:-}" ]] && { err "Missing: DO_API_KEY"; missing=$((missing+1)); }
            ;;
        godaddy|gd)
            [[ -z "${GD_Key:-}" ]]    && { err "Missing: GD_Key";    missing=$((missing+1)); }
            [[ -z "${GD_Secret:-}" ]] && { err "Missing: GD_Secret"; missing=$((missing+1)); }
            ;;
        *)
            log "Custom DNS provider '${provider}' – skipping credential pre-check"
            ;;
    esac
    return $missing
}

# ── Process certificates for each configured server ───────────────────────────
for SERVER_ID in $SERVER_IDS; do
    log "--- Server: ${SERVER_ID} ---"

    # Load server-specific env vars (overwrites any previous server's vars)
    SERVER_ENV=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import get_server_shell_env
output = get_server_shell_env('${SERVER_ID}')
if output:
    print(output)
" 2>/dev/null) || true

    if [[ -z "$SERVER_ENV" ]]; then
        err "Failed to load configuration for server ${SERVER_ID} – skipping"
        continue
    fi
    eval "$SERVER_ENV"

    # Switch to per-server cert and log directories (mkdir only — init after migration)
    mkdir -p "${SERVER_CERT_DIR}/.logs"

    # ── Migrate existing flat-file layout (one-time, per server) ─────────────
    # Triggers if either cert type exists at the old root level but not yet in
    # SERVER_CERT_DIR.  Must run before status_server_init so the global
    # status.log can be seeded into the per-server directory first.
    if [[ ( -f "${CERT_DIR}/${DOMAIN}.ecc.cer" || -f "${CERT_DIR}/${DOMAIN}.rsa.cer" ) \
          && ! -f "${SERVER_CERT_DIR}/${DOMAIN}.ecc.cer" \
          && ! -f "${SERVER_CERT_DIR}/${DOMAIN}.rsa.cer" ]]; then
        log "  Migrating certs for ${DOMAIN} → ${SERVER_CERT_DIR}/"
        for ext in ecc.cer ecc.key ecc.fullchain.cer ecc.ca.cer \
                   rsa.cer rsa.key rsa.fullchain.cer rsa.ca.cer; do
            [[ -f "${CERT_DIR}/${DOMAIN}.${ext}" ]] \
                && mv "${CERT_DIR}/${DOMAIN}.${ext}" "${SERVER_CERT_DIR}/" || true
        done
        # Move acme.sh state dirs so the per-server cleanup below can remove them
        [[ -d "${CERT_DIR}/${DOMAIN}" ]]     && mv "${CERT_DIR}/${DOMAIN}"     "${SERVER_CERT_DIR}/" || true
        [[ -d "${CERT_DIR}/${DOMAIN}_ecc" ]] && mv "${CERT_DIR}/${DOMAIN}_ecc" "${SERVER_CERT_DIR}/" || true
        # Seed per-server logs from global copies (status.log must be copied
        # before status_server_init creates a new empty one)
        [[ -f "${CERT_DIR}/status.log" ]] \
            && cp "${CERT_DIR}/status.log" "${SERVER_CERT_DIR}/status.log" || true
        # Copy logs to per-server dir, applying new filenames
        for task in "renewal.log:acme_renewal.log" "upload.log:cppm_upload.log"; do
            old="${task%%:*}"; new="${task##*:}"
            [[ -f "${CERT_DIR}/.logs/${old}" && ! -f "${SERVER_CERT_DIR}/.logs/${new}" ]] \
                && cp "${CERT_DIR}/.logs/${old}" "${SERVER_CERT_DIR}/.logs/${new}" || true
        done
        # Rename if a previous migration already copied under old names
        for task in "renewal.log:acme_renewal.log" "upload.log:cppm_upload.log"; do
            old="${task%%:*}"; new="${task##*:}"
            [[ -f "${SERVER_CERT_DIR}/.logs/${old}" && ! -f "${SERVER_CERT_DIR}/.logs/${new}" ]] \
                && mv "${SERVER_CERT_DIR}/.logs/${old}" "${SERVER_CERT_DIR}/.logs/${new}" || true
        done
        log "  Migration complete."
    fi

    status_server_init

    log "  Domain : ${DOMAIN:-NOT SET}"
    log "  CPPM   : ${CPPM_HOST:-NOT SET}"
    log "  CA     : ${ACME_SERVER:-letsencrypt}"

    # Validate required fields
    FIELD_MISSING=0
    for var in DOMAIN ACME_EMAIL DNS_PROVIDER CPPM_HOST CPPM_CLIENT_ID CPPM_CLIENT_SECRET CPPM_CALLBACK_HOST; do
        [[ -z "${!var:-}" ]] && { err "Server ${SERVER_ID}: missing required field: ${var}"; FIELD_MISSING=$((FIELD_MISSING+1)); }
    done
    validate_dns_creds || FIELD_MISSING=$((FIELD_MISSING+1))

    if [[ $FIELD_MISSING -gt 0 ]]; then
        err "Skipping server ${SERVER_ID} (${FIELD_MISSING} configuration issue(s) — fix via web UI)"
        continue
    fi

    # Certificate state decision (use per-server directory)
    FLAT_ECC="${SERVER_CERT_DIR}/${DOMAIN}.ecc.cer"
    FLAT_RSA="${SERVER_CERT_DIR}/${DOMAIN}.rsa.cer"
    LEGO_ECC_CERT="${SERVER_CERT_DIR}/lego-ecc/certificates/${DOMAIN}.crt"
    LEGO_RSA_CERT="${SERVER_CERT_DIR}/lego-rsa/certificates/${DOMAIN}.crt"

    # Determine which cert types are expected for this server
    NEED_ECC="${ISSUE_ECC:-true}"
    NEED_RSA="${ISSUE_RSA:-true}"

    # Check whether expected flat files are all present
    FLAT_OK=true
    [[ "$NEED_ECC" == "true" && ! -f "$FLAT_ECC" ]] && FLAT_OK=false
    [[ "$NEED_RSA" == "true" && ! -f "$FLAT_RSA" ]] && FLAT_OK=false

    # Check whether Lego cert state is present (files written by lego run/renew)
    LEGO_STATE_OK=true
    [[ "$NEED_ECC" == "true" && ! -f "$LEGO_ECC_CERT" ]] && LEGO_STATE_OK=false
    [[ "$NEED_RSA" == "true" && ! -f "$LEGO_RSA_CERT" ]] && LEGO_STATE_OK=false

    # ── Remove legacy acme.sh per-cert state dirs (one-time, post-upgrade) ───────
    # Guard: only run when certs are already present (flat or Lego state) so this
    # never fires on a first-run container that hasn't issued any certs yet.
    if [[ "$FLAT_OK" == "true" || "$LEGO_STATE_OK" == "true" ]]; then
        for legacy_dir in "${SERVER_CERT_DIR}/${DOMAIN}_ecc" "${SERVER_CERT_DIR}/${DOMAIN}"; do
            if [[ -d "$legacy_dir" ]]; then
                rm -rf "$legacy_dir"
                log "  Removed legacy acme.sh state: ${legacy_dir}"
                status_write "INFO" "STARTUP" "Removed legacy acme.sh state dir: ${legacy_dir}"
            fi
        done
    fi

    # Primary cert for expiry reporting (ECC preferred, else RSA)
    PRIMARY_FLAT="$FLAT_ECC"
    [[ "$NEED_ECC" != "true" ]] && PRIMARY_FLAT="$FLAT_RSA"

    if [[ "${FORCE_RENEW:-false}" == "true" ]]; then
        log "FORCE_RENEW=true – forcing full re-issuance for ${DOMAIN}..."
        status_write "INFO" "CERT" "FORCE_RENEW requested – starting re-issuance for ${DOMAIN}"
        run_with_guard /opt/cppm/issue_cert.sh || true

    elif [[ "$FLAT_OK" == "true" ]]; then
        PRIMARY_EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_FLAT" 2>/dev/null \
                         | cut -d= -f2 || echo "unknown")
        PRIMARY_SUBJECT=$(openssl x509 -subject -noout -in "$PRIMARY_FLAT" 2>/dev/null \
                          | sed 's/subject=//' || echo "unknown")
        DAYS_LEFT="unknown"
        EXPIRY_EPOCH=$(date -d "$PRIMARY_EXPIRY" +%s 2>/dev/null || echo 0)
        if [[ "$EXPIRY_EPOCH" -gt 0 ]]; then
            DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
        fi
        log "Cert(s) installed for ${DOMAIN} – no action needed."
        log "  Subject  : $PRIMARY_SUBJECT"
        log "  Expires  : $PRIMARY_EXPIRY ($DAYS_LEFT days remaining)"
        if [[ "$NEED_ECC" == "true" && "$NEED_RSA" == "true" ]]; then
            RSA_EXPIRY=$(openssl x509 -enddate -noout -in "$FLAT_RSA" 2>/dev/null \
                         | cut -d= -f2 || echo "unknown")
            log "  RSA Expires: $RSA_EXPIRY"
        fi
        status_write "OK" "CERT" "Cert(s) valid for ${DOMAIN} – expires ${PRIMARY_EXPIRY} (${DAYS_LEFT} days remaining)"

    elif [[ "$LEGO_STATE_OK" == "true" ]]; then
        log "Lego cert state present but flat files missing for ${DOMAIN} – running install only..."
        status_write "INFO" "CERT" "Flat files missing for ${DOMAIN} – running install (no re-issue needed)"
        run_with_guard /opt/cppm/install_cert.sh || true

    else
        log "Certificates not found for ${DOMAIN} – issuing for the first time..."
        status_write "INFO" "CERT" "No certificates found for ${DOMAIN} – starting first-time issuance"
        run_with_guard /opt/cppm/issue_cert.sh || true
    fi
done

# ── Remove legacy acme.sh shared state directory (one-time, post-upgrade) ────
ACME_LEGACY_SHARED="${CERT_DIR}/.acme-state"
if [[ -d "$ACME_LEGACY_SHARED" ]]; then
    rm -rf "$ACME_LEGACY_SHARED"
    log "Removed legacy acme.sh shared state: ${ACME_LEGACY_SHARED}"
    status_write "INFO" "STARTUP" "Removed legacy acme.sh shared state dir"
fi

# Restore global STATUS_LOG so post-loop container-level messages go to the
# right place regardless of how many servers were processed.
STATUS_LOG="$GLOBAL_STATUS_LOG"

# ── Start status web server ───────────────────────────────────────────────────
STATUS_PORT="${STATUS_PORT:-8080}"
log "Starting status web server on port ${STATUS_PORT}..."
python3 /opt/cppm/status_server.py >> "${LOG_DIR}/status_server.log" 2>&1 &
log "  Status server started (PID $!) – http://<host>:${STATUS_PORT}/"

# ── Start crond ───────────────────────────────────────────────────────────────
log "Starting supercronic (renewal checks at 02:00 and 14:00 UTC daily)..."
status_write "INFO" "STARTUP" "supercronic started – renewal checks at 02:00 and 14:00 UTC"
log "=== Startup complete ==="

exec /usr/local/bin/supercronic /etc/crontabs/root
