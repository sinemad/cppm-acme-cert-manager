#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy_hook.sh – Called after successful issuance/renewal
#                  Uploads ECC cert → HTTPS(ECC) and RSA cert → RADIUS
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/upload.log"
DOMAIN="${DOMAIN:-cppm.sinemalab.com}"
CPPM_HOST="${CPPM_HOST:-cppm.sinemalab.com}"

mkdir -p "$LOG_DIR"
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [HOOK]  $*" | tee -a "$LOG"; }
err() { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }

source /opt/cppm/status.sh

log "=== Deploy Hook ==="

# ECC cert paths (→ HTTPS(ECC) slot)
HTTPS_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer"
HTTPS_KEY="${CERT_DIR}/${DOMAIN}.ecc.key"
HTTPS_FULLCHAIN="${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer"
HTTPS_CA="${CERT_DIR}/${DOMAIN}.ecc.ca.cer"

# RSA cert paths (→ RADIUS slot)
RADIUS_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"
RADIUS_KEY="${CERT_DIR}/${DOMAIN}.rsa.key"
RADIUS_FULLCHAIN="${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer"
RADIUS_CA="${CERT_DIR}/${DOMAIN}.rsa.ca.cer"

for f in "$HTTPS_CERT" "$HTTPS_KEY" "$HTTPS_FULLCHAIN" \
          "$RADIUS_CERT" "$RADIUS_KEY" "$RADIUS_FULLCHAIN"; do
    [[ -f "$f" ]] || {
        err "Required file not found: $f"
        status_write "FAILED" "UPLOAD" "Cert file missing – ${f}"
        exit 1
    }
done

if [[ "${SKIP_UPLOAD:-false}" == "true" ]]; then
    log "SKIP_UPLOAD=true – skipping ClearPass upload."
    status_write "INFO" "UPLOAD" "Upload skipped (SKIP_UPLOAD=true)"
    exit 0
fi

log "Invoking ClearPass upload to ${CPPM_HOST}..."
log "  HTTPS (ECC): ${HTTPS_CERT}"
log "  RADIUS (RSA): ${RADIUS_CERT}"

UPLOAD_EXIT=0
python3 /opt/cppm/clearpass_upload.py \
    --https-cert      "$HTTPS_CERT" \
    --https-key       "$HTTPS_KEY" \
    --https-fullchain "$HTTPS_FULLCHAIN" \
    --https-ca        "$HTTPS_CA" \
    --radius-cert     "$RADIUS_CERT" \
    --radius-key      "$RADIUS_KEY" \
    --radius-fullchain "$RADIUS_FULLCHAIN" \
    --radius-ca       "$RADIUS_CA" \
    --domain          "$DOMAIN" \
    2>&1 | tee -a "$LOG" || UPLOAD_EXIT=$?

if [[ $UPLOAD_EXIT -eq 0 ]]; then
    log "Upload succeeded."
    ECC_EXPIRY=$(openssl x509 -enddate -noout -in "$HTTPS_CERT" 2>/dev/null \
                 | cut -d= -f2 || echo "unknown")
    status_write "OK" "UPLOAD" "ECC→HTTPS + RSA→RADIUS uploaded to ${CPPM_HOST} – expires ${ECC_EXPIRY}"
else
    err "Upload failed (exit ${UPLOAD_EXIT}) – check ${LOG}"
    status_write "FAILED" "UPLOAD" "ClearPass upload failed (exit ${UPLOAD_EXIT}) – check upload.log"
fi

log "=== Deploy Hook Complete ==="
