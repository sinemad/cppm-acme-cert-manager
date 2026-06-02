#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# entrypoint.sh – Container startup
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
ACME_SEED="/opt/acme-seed"
ACME_STATE="/data/certs/.acme-state"
CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

[[ -x "$ACME_BIN" ]] || { echo "[ERROR] acme.sh not found at $ACME_BIN. Rebuild the image."; exit 1; }

mkdir -p "$LOG_DIR" "$CERT_DIR"
LOG="${LOG_DIR}/startup.log"
touch "$LOG"

# Source status library (writes to /data/certs/status.log)
# shellcheck source=status.sh
source /opt/cppm/status.sh

log()  { echo "[$(ts)] [INFO ] $*" | tee -a "$LOG"; }
warn() { echo "[$(ts)] [WARN ] $*" | tee -a "$LOG"; }
err()  { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }
die()  { err "$*"; status_write "FAILED" "STARTUP" "$*"; exit 1; }

ACME_VER=$("$ACME_BIN" --version 2>&1 | head -1)
log "=== ClearPass Certificate Manager v2.0 ==="
log "acme.sh : $ACME_VER"
status_write "INFO" "STARTUP" "Container started – acme=${ACME_VER}"

# ── Seed acme.sh state ────────────────────────────────────────────────────────
log "Checking acme.sh state at ${ACME_STATE}..."
if [[ ! -d "${ACME_STATE}/dnsapi" ]]; then
    log "  First run – seeding acme.sh state from image..."
    rm -rf "${ACME_STATE}"
    cp -r "${ACME_SEED}/." "${ACME_STATE}/"
    log "  Seeded: $(ls "${ACME_STATE}/dnsapi/" | wc -l | tr -d ' ') dnsapi scripts"
else
    log "  State present. Refreshing dnsapi scripts from image..."
    cp -r "${ACME_SEED}/dnsapi/." "${ACME_STATE}/dnsapi/"
fi
# Patch acme.sh and all plugin scripts to use bash.
# Covers the main binary, dnsapi/, deploy/, and notify/ scripts.
# Runs on every start so existing volumes are fixed automatically.
sed -i '1s|#!/usr/bin/env sh|#!/usr/bin/env bash|' "${ACME_STATE}/acme.sh" 2>/dev/null || true
find "${ACME_STATE}/dnsapi" "${ACME_STATE}/deploy" "${ACME_STATE}/notify" \
    -name '*.sh' \
    -exec sed -i '1s|#!/usr/bin/env sh|#!/usr/bin/env bash|' {} \; 2>/dev/null || true
log "  acme.sh shebang verified: $(head -1 ${ACME_STATE}/acme.sh)"

if [[ ! -L /root/.acme.sh ]]; then
    rm -rf /root/.acme.sh
    ln -sfn "${ACME_STATE}" /root/.acme.sh
    log "  Symlink created: /root/.acme.sh -> ${ACME_STATE}"
else
    log "  Symlink in place: /root/.acme.sh -> $(readlink /root/.acme.sh)"
fi

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

    # Register ACME account (idempotent — safe to call even if already registered)
    unset DEBUG
    log "Registering ACME account (${ACME_EMAIL}) with ${ACME_SERVER:-letsencrypt}..."
    "$ACME_BIN" --register-account \
        -m "$ACME_EMAIL" \
        --server "${ACME_SERVER:-letsencrypt}" \
        2>&1 | tee -a "$LOG" || true

    # Certificate state decision
    FLAT_ECC="${CERT_DIR}/${DOMAIN}.ecc.cer"
    FLAT_RSA="${CERT_DIR}/${DOMAIN}.rsa.cer"
    ACME_ECC_CERT="${CERT_DIR}/${DOMAIN}_ecc/${DOMAIN}.cer"
    ACME_RSA_CERT="${CERT_DIR}/${DOMAIN}/${DOMAIN}.cer"

    if [[ "${FORCE_RENEW:-false}" == "true" ]]; then
        log "FORCE_RENEW=true – forcing full re-issuance for ${DOMAIN}..."
        status_write "INFO" "CERT" "FORCE_RENEW requested – starting re-issuance for ${DOMAIN}"
        run_with_guard /opt/cppm/issue_cert.sh || true

    elif [[ -f "$FLAT_ECC" && -f "$FLAT_RSA" ]]; then
        ECC_EXPIRY=$(openssl x509 -enddate -noout -in "$FLAT_ECC" 2>/dev/null \
                     | cut -d= -f2 || echo "unknown")
        ECC_SUBJECT=$(openssl x509 -subject -noout -in "$FLAT_ECC" 2>/dev/null \
                      | sed 's/subject=//' || echo "unknown")
        DAYS_LEFT="unknown"
        EXPIRY_EPOCH=$(date -d "$ECC_EXPIRY" +%s 2>/dev/null || echo 0)
        if [[ "$EXPIRY_EPOCH" -gt 0 ]]; then
            DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
        fi
        RSA_EXPIRY=$(openssl x509 -enddate -noout -in "$FLAT_RSA" 2>/dev/null \
                     | cut -d= -f2 || echo "unknown")
        log "Both certs installed for ${DOMAIN} – no action needed."
        log "  ECC Subject : $ECC_SUBJECT"
        log "  ECC Expires : $ECC_EXPIRY ($DAYS_LEFT days remaining)"
        log "  RSA Expires : $RSA_EXPIRY"
        status_write "OK" "CERT" "ECC+RSA valid for ${DOMAIN} – expires ${ECC_EXPIRY} (${DAYS_LEFT} days remaining)"

    elif [[ -f "$ACME_ECC_CERT" && -f "$ACME_RSA_CERT" ]]; then
        log "acme.sh state present but flat files missing for ${DOMAIN} – running install only..."
        status_write "INFO" "CERT" "Flat files missing for ${DOMAIN} – running install-cert (no re-issue needed)"
        run_with_guard /opt/cppm/install_cert.sh || true

    else
        log "Certificates not found for ${DOMAIN} – issuing for the first time..."
        status_write "INFO" "CERT" "No certificates found for ${DOMAIN} – starting first-time issuance"
        run_with_guard /opt/cppm/issue_cert.sh || true
    fi
done

# ── Seed trust exclusion config to volume ────────────────────────────────────
TRUST_EXCL_VOL="${CERT_DIR}/trust-exclusions.conf"
TRUST_EXCL_IMG="/opt/cppm/acme-ca-certs/trust-exclusions.conf"
if [[ ! -f "$TRUST_EXCL_VOL" && -f "$TRUST_EXCL_IMG" ]]; then
    cp "$TRUST_EXCL_IMG" "$TRUST_EXCL_VOL"
    log "  Seeded trust-exclusions.conf → ${TRUST_EXCL_VOL}"
fi

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
