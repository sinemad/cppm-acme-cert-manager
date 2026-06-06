#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# renew.sh – Called by supercronic twice daily to check and renew certificates.
#            Iterates over all servers configured in servers.json.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/acme_renewal.log"

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { local m="[$(ts)] [RENEW] $*"; echo "$m";     echo "$m" >> "$LOG" 2>/dev/null; }
err() { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

source /opt/cppm/status.sh
unset DEBUG

log "=== Renewal Check ==="

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

    CERT_DIR="${SERVER_CERT_DIR:-/data/certs}"
    LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
    LOG="${LOG_DIR}/acme_renewal.log"
    mkdir -p "$LOG_DIR"
    status_server_init

    log "=== Renewal Check ==="
    log "  Domain   : ${DOMAIN:-NOT SET}"
    log "  CPPM     : ${CPPM_HOST:-NOT SET}"
    log "  DNS      : ${DNS_PROVIDER:-NOT SET}"
    log "  ACME CA  : ${ACME_SERVER:-letsencrypt}"
    log "  Callback : http://${CPPM_CALLBACK_HOST:-not set}:${CPPM_CALLBACK_PORT:-8765}/"

    if [[ -z "${DOMAIN:-}" ]]; then
        err "Server ${SERVER_ID}: DOMAIN is empty – skipping"
        continue
    fi

    ISSUE_ECC="${ISSUE_ECC:-true}"
    ISSUE_RSA="${ISSUE_RSA:-true}"

    # If flat cert files are missing, re-issue rather than renew
    NEEDS_ISSUE=false
    [[ "$ISSUE_ECC" == "true" && ! -f "${CERT_DIR}/${DOMAIN}.ecc.cer" ]] && NEEDS_ISSUE=true
    [[ "$ISSUE_RSA" == "true" && ! -f "${CERT_DIR}/${DOMAIN}.rsa.cer" ]] && NEEDS_ISSUE=true
    if [[ "$NEEDS_ISSUE" == "true" ]]; then
        log "Flat cert(s) missing for ${DOMAIN} – delegating to issue_cert.sh..."
        status_write "WARN" "RENEW" "Flat cert(s) missing for ${DOMAIN} at renewal check – re-running issuance"
        /opt/cppm/issue_cert.sh 2>&1 | tee -a "$LOG" 2>/dev/null || \
            err "issue_cert.sh failed for ${DOMAIN} – check acme_renewal.log"
        continue
    fi

    # Log current expiry
    PRIMARY_FLAT="${CERT_DIR}/${DOMAIN}.ecc.cer"
    [[ "$ISSUE_ECC" != "true" ]] && PRIMARY_FLAT="${CERT_DIR}/${DOMAIN}.rsa.cer"
    EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_FLAT" 2>/dev/null \
             | cut -d= -f2 || echo "unknown")
    DAYS_LEFT="unknown"
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
    [[ "$EXPIRY_EPOCH" -gt 0 ]] && DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
    log "Current cert for ${DOMAIN} expires: $EXPIRY ($DAYS_LEFT days remaining)"

    RENEW_EXIT=0
    python3 /opt/cppm/acme_cli.py renew 2>&1 | tee -a "$LOG" 2>/dev/null || RENEW_EXIT=$?

    case $RENEW_EXIT in
        0)
            log "Certificate(s) renewed for ${DOMAIN}."
            status_write "OK" "RENEW" "Certificate renewed for ${DOMAIN} – running install and upload"
            /opt/cppm/install_cert.sh 2>&1 | tee -a "$LOG" 2>/dev/null || \
                err "install_cert.sh failed for ${DOMAIN}"
            ;;
        2)
            log "Certificate for ${DOMAIN} not due for renewal."
            status_write "INFO" "RENEW" "Not due for renewal – ${DOMAIN} has ${DAYS_LEFT} days remaining (next check in 12h)"
            ;;
        *)
            err "lego renew exited ${RENEW_EXIT} for ${DOMAIN} – check acme_renewal.log"
            status_write "FAILED" "RENEW" "lego renew failed for ${DOMAIN} – check acme_renewal.log"
            ;;
    esac
done

log "=== Renewal Check Complete ==="
