#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# renew.sh – Called by crond twice daily to check and renew certificates
#            Iterates over all servers configured in servers.json
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/renewal.log"

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { local m="[$(ts)] [RENEW] $*"; echo "$m";    echo "$m" >> "$LOG" 2>/dev/null; }
err() { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

source /opt/cppm/status.sh
# acme.sh uses $DEBUG as a numeric variable; a non-numeric value from
# the host environment causes integer comparison errors.
unset DEBUG

log "=== Renewal Check ==="

# Load server IDs from servers.json
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
    log "No servers configured – nothing to renew."
    log "=== Renewal Check Complete ==="
    exit 0
fi

for SERVER_ID in $SERVER_IDS; do
    log "--- Server: ${SERVER_ID} ---"

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

    # Switch to per-server cert and log directories
    CERT_DIR="${SERVER_CERT_DIR:-/data/certs}"
    LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
    LOG="${LOG_DIR}/renewal.log"
    mkdir -p "$LOG_DIR"
    status_server_init

    log "Domain: ${DOMAIN:-NOT SET}"

    if [[ -z "${DOMAIN:-}" ]]; then
        err "Server ${SERVER_ID}: DOMAIN is empty – skipping"
        continue
    fi

    ISSUE_ECC="${ISSUE_ECC:-true}"
    ISSUE_RSA="${ISSUE_RSA:-true}"

    # Check that flat cert files exist for each enabled type; re-issue if missing
    NEEDS_ISSUE=false
    [[ "$ISSUE_ECC" == "true" && ! -f "${CERT_DIR}/${DOMAIN}.ecc.cer" ]] && NEEDS_ISSUE=true
    [[ "$ISSUE_RSA" == "true" && ! -f "${CERT_DIR}/${DOMAIN}.rsa.cer" ]] && NEEDS_ISSUE=true
    if [[ "$NEEDS_ISSUE" == "true" ]]; then
        log "Flat cert(s) missing for ${DOMAIN} – delegating to issue_cert.sh..."
        status_write "WARN" "RENEW" "Flat cert(s) missing for ${DOMAIN} at renewal check – re-running issuance"
        /opt/cppm/issue_cert.sh 2>&1 | tee -a "$LOG" 2>/dev/null || \
            err "issue_cert.sh failed for ${DOMAIN} – check renewal.log"
        continue
    fi

    # Use the primary enabled cert type for expiry display
    PRIMARY_FLAT="${CERT_DIR}/${DOMAIN}.ecc.cer"
    [[ "$ISSUE_ECC" != "true" ]] && PRIMARY_FLAT="${CERT_DIR}/${DOMAIN}.rsa.cer"
    EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_FLAT" 2>/dev/null \
             | cut -d= -f2 || echo "unknown")
    DAYS_LEFT="unknown"
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
    if [[ "$EXPIRY_EPOCH" -gt 0 ]]; then
        DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
    fi
    log "Current cert for ${DOMAIN} expires: $EXPIRY ($DAYS_LEFT days remaining)"

    RENEWED=0
    RENEW_FAILED=0

    if [[ "$ISSUE_ECC" == "true" ]]; then
        log "Running acme.sh --renew (ECC) for ${DOMAIN}..."
        ECC_RENEW_EXIT=0
        "$ACME_BIN" --renew \
            --domain    "$DOMAIN" \
            --ecc \
            --server    "${ACME_SERVER:-letsencrypt}" \
            --cert-home "$CERT_DIR" \
            --home      /root/.acme.sh \
            --log       "$LOG" \
            --log-level 2 \
            2>&1 | tee -a "$LOG" 2>/dev/null || ECC_RENEW_EXIT=$?
        case $ECC_RENEW_EXIT in
            0) log "ECC certificate renewed for ${DOMAIN}."; RENEWED=$((RENEWED+1)) ;;
            2) log "ECC cert not due for renewal." ;;
            *) err "acme.sh --renew (ECC) exited $ECC_RENEW_EXIT for ${DOMAIN}"; RENEW_FAILED=$((RENEW_FAILED+1)) ;;
        esac
    fi

    if [[ "$ISSUE_RSA" == "true" ]]; then
        log "Running acme.sh --renew (RSA) for ${DOMAIN}..."
        RSA_RENEW_EXIT=0
        "$ACME_BIN" --renew \
            --domain    "$DOMAIN" \
            --server    "${ACME_SERVER:-letsencrypt}" \
            --cert-home "$CERT_DIR" \
            --home      /root/.acme.sh \
            --log       "$LOG" \
            --log-level 2 \
            2>&1 | tee -a "$LOG" 2>/dev/null || RSA_RENEW_EXIT=$?
        case $RSA_RENEW_EXIT in
            0) log "RSA certificate renewed for ${DOMAIN}."; RENEWED=$((RENEWED+1)) ;;
            2) log "RSA cert not due for renewal." ;;
            *) err "acme.sh --renew (RSA) exited $RSA_RENEW_EXIT for ${DOMAIN}"; RENEW_FAILED=$((RENEW_FAILED+1)) ;;
        esac
    fi

    if [[ $RENEW_FAILED -gt 0 ]]; then
        status_write "FAILED" "RENEW" "acme.sh --renew failed for ${DOMAIN} – check renewal.log"
    elif [[ $RENEWED -gt 0 ]]; then
        log "Certificate(s) renewed for ${DOMAIN}."
        status_write "OK" "RENEW" "Certificate renewed for ${DOMAIN} – running install and upload"
        /opt/cppm/install_cert.sh 2>&1 | tee -a "$LOG" 2>/dev/null || \
            err "install_cert.sh failed for ${DOMAIN}"
    else
        log "Certificate for ${DOMAIN} not due for renewal – no action needed."
        status_write "INFO" "RENEW" "Not due for renewal – ${DOMAIN} has ${DAYS_LEFT} days remaining (next check in 12h)"
    fi
done

log "=== Renewal Check Complete ==="
