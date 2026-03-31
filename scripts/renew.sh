#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# renew.sh – Called by crond twice daily to check and renew certificates
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/renewal.log"
DOMAIN="${DOMAIN:-cppm.sinemalab.com}"

mkdir -p "$LOG_DIR"
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [RENEW] $*" | tee -a "$LOG"; }
err() { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }

source /opt/cppm/status.sh
# acme.sh uses $DEBUG as a numeric variable; a non-numeric value from
# the host environment causes integer comparison errors. Always unset it.
unset DEBUG

log "=== Renewal Check ==="

FLAT_CERT="${CERT_DIR}/${DOMAIN}.cer"
if [[ ! -f "$FLAT_CERT" ]]; then
    log "Flat cert missing – delegating to issue_cert.sh..."
    status_write "WARN" "RENEW" "Flat cert missing at renewal check – re-running issuance"
    exec /opt/cppm/issue_cert.sh
fi

EXPIRY=$(openssl x509 -enddate -noout -in "$FLAT_CERT" 2>/dev/null \
         | cut -d= -f2 || echo "unknown")
DAYS_LEFT="unknown"
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
if [[ "$EXPIRY_EPOCH" -gt 0 ]]; then
    DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
fi
log "Current cert expires: $EXPIRY ($DAYS_LEFT days remaining)"

log "Running acme.sh --renew ..."
RENEW_EXIT=0
"$ACME_BIN" --renew \
    --domain    "$DOMAIN" \
    --server    "${ACME_SERVER:-letsencrypt}" \
    --home      /root/.acme.sh \
    --log       "$LOG" \
    --log-level 2 \
    2>&1 | tee -a "$LOG" || RENEW_EXIT=$?

case $RENEW_EXIT in
    0)
        log "Certificate renewed successfully."
        status_write "OK" "RENEW" "Certificate renewed – running install and upload"
        /opt/cppm/install_cert.sh
        ;;
    2)
        log "Certificate not due for renewal – no action needed."
        status_write "INFO" "RENEW" "Not due for renewal – ${DAYS_LEFT} days remaining (next check in 12h)"
        ;;
    *)
        err "acme.sh --renew exited with code $RENEW_EXIT – check ${LOG}"
        status_write "FAILED" "RENEW" "acme.sh --renew failed with exit code ${RENEW_EXIT} – check renewal.log"
        exit $RENEW_EXIT
        ;;
esac

log "=== Renewal Check Complete ==="
