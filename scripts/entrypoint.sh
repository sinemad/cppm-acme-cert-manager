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
DOMAIN="${DOMAIN:-cppm.sinemalab.com}"

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
log "Domain  : ${DOMAIN}"
log "CPPM    : ${CPPM_HOST:-NOT SET}"
log "CA      : ${ACME_SERVER:-letsencrypt}"
status_write "INFO" "STARTUP" "Container started – domain=${DOMAIN} acme=${ACME_VER}"

# ── Validate environment ──────────────────────────────────────────────────────
REQUIRED_VARS=(DOMAIN ACME_EMAIL DNS_PROVIDER CPPM_HOST CPPM_CLIENT_ID CPPM_CLIENT_SECRET CPPM_CALLBACK_HOST)
MISSING=0
for var in "${REQUIRED_VARS[@]}"; do
    [[ -z "${!var:-}" ]] && { err "Missing required env var: $var"; MISSING=$((MISSING+1)); }
done

# Validate DNS provider credentials
case "${DNS_PROVIDER:-cloudflare,,}" in
    cloudflare|cf)
        if [[ -z "${CF_Token:-}" && ( -z "${CF_Key:-}" || -z "${CF_Email:-}" ) ]]; then
            err "Cloudflare credentials missing: set CF_Token (preferred) or CF_Key + CF_Email"
            MISSING=$((MISSING+1))
        fi
        ;;
    porkbun)
        [[ -z "${PORKBUN_API_KEY:-}" ]]        && { err "Missing: PORKBUN_API_KEY"; MISSING=$((MISSING+1)); }
        [[ -z "${PORKBUN_SECRET_API_KEY:-}" ]] && { err "Missing: PORKBUN_SECRET_API_KEY"; MISSING=$((MISSING+1)); }
        ;;
    route53|aws|r53)
        [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]     && { err "Missing: AWS_ACCESS_KEY_ID"; MISSING=$((MISSING+1)); }
        [[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]] && { err "Missing: AWS_SECRET_ACCESS_KEY"; MISSING=$((MISSING+1)); }
        ;;
    digitalocean|do)
        [[ -z "${DO_API_KEY:-}" ]] && { err "Missing: DO_API_KEY"; MISSING=$((MISSING+1)); }
        ;;
    godaddy|gd)
        [[ -z "${GD_Key:-}" ]]    && { err "Missing: GD_Key"; MISSING=$((MISSING+1)); }
        [[ -z "${GD_Secret:-}" ]] && { err "Missing: GD_Secret"; MISSING=$((MISSING+1)); }
        ;;
    *)
        log "Custom DNS provider '${DNS_PROVIDER}' – skipping credential pre-check"
        ;;
esac

[[ $MISSING -gt 0 ]] && die "$MISSING required environment variable(s) missing – check .env"

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
# Ensure the persistent copy of acme.sh uses bash, not sh.
# acme.sh calls itself internally via LE_WORKING_DIR/acme.sh, so this copy
# must have the bash shebang or Alpine ash will run it and produce
# 'sh: DEBUG: out of range' errors. This re-patch guards against volumes
# seeded before the fix was applied.
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

# ── Register ACME account ─────────────────────────────────────────────────────
# Unset DEBUG before every acme.sh call.
# acme.sh uses $DEBUG as a *numeric* log level internally.
# If the host or container environment has DEBUG set to any non-numeric
# string (e.g. "DEBUG", "true", "1") the integer comparisons inside
# acme.sh produce "[: DEBUG: integer expression expected" on every line.
unset DEBUG
log "Registering ACME account ($ACME_EMAIL)..."
"$ACME_BIN" --register-account \
    -m "$ACME_EMAIL" \
    --server "${ACME_SERVER:-letsencrypt}" \
    2>&1 | tee -a "$LOG" || true

# ── Certificate state decision ────────────────────────────────────────────────
# ECC flat cert is the primary installed indicator.
# RSA flat cert must also exist for a fully-installed state.
FLAT_ECC="${CERT_DIR}/${DOMAIN}.ecc.cer"
FLAT_RSA="${CERT_DIR}/${DOMAIN}.rsa.cer"
# acme.sh internal state dirs
ACME_ECC_CERT="${CERT_DIR}/${DOMAIN}_ecc/${DOMAIN}.cer"
ACME_RSA_CERT="${CERT_DIR}/${DOMAIN}/${DOMAIN}.cer"

run_with_guard() {
    local script="$1"
    if "$script" 2>&1 | tee -a "$LOG"; then
        return 0
    else
        local exit_code=${PIPESTATUS[0]}
        err "$script failed (exit $exit_code). Container will stay running."
        err "Retry manually: docker exec -it cppm-cert-manager $script"
        return 1
    fi
}

if [[ "${FORCE_RENEW:-false}" == "true" ]]; then
    log "FORCE_RENEW=true – forcing full re-issuance..."
    status_write "INFO" "CERT" "FORCE_RENEW requested – starting re-issuance"
    run_with_guard /opt/cppm/issue_cert.sh || true

elif [[ -f "$FLAT_ECC" && -f "$FLAT_RSA" ]]; then
    # ── Normal restart – both certs fully installed ───────────────────────────
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
    log "Both ECC and RSA certificates installed – no action needed."
    log "  ECC Subject : $ECC_SUBJECT"
    log "  ECC Expires : $ECC_EXPIRY ($DAYS_LEFT days remaining)"
    log "  RSA Expires : $RSA_EXPIRY"
    log "  crond will renew automatically when ≤30 days remain."
    status_write "OK" "CERT" "ECC+RSA valid – expires ${ECC_EXPIRY} (${DAYS_LEFT} days remaining)"

elif [[ -f "$ACME_ECC_CERT" && -f "$ACME_RSA_CERT" ]]; then
    # ── acme.sh has both certs but flat files missing ─────────────────────────
    log "acme.sh state has certs but flat files missing – running install only..."
    status_write "INFO" "CERT" "Flat files missing – running install-cert (no re-issue needed)"
    run_with_guard /opt/cppm/install_cert.sh || true

else
    # ── First-ever issuance or partial state ──────────────────────────────────
    log "Certificate(s) not found – issuing for the first time..."
    status_write "INFO" "CERT" "No certificates found – starting first-time issuance"
    run_with_guard /opt/cppm/issue_cert.sh || true
fi

# ── Start crond ───────────────────────────────────────────────────────────────
log "Starting supercronic (renewal checks at 02:00 and 14:00 UTC daily)..."
status_write "INFO" "STARTUP" "supercronic started – renewal checks at 02:00 and 14:00 UTC"
log "=== Startup complete ==="

# supercronic is a container-native cron runner:
#   - No setpgid() required (avoids Docker permission errors)
#   - Logs to stdout/stderr (visible in docker compose logs)
#   - Exits cleanly on SIGTERM (proper container shutdown)
#   - Reads CRON_TZ from the environment for timezone awareness
exec /usr/local/bin/supercronic /etc/crontabs/root
