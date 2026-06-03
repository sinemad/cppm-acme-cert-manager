#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy_hook.sh – Called after successful issuance/renewal
#                  Uploads ECC cert → HTTPS(ECC) and RSA cert → RADIUS
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="/data/certs"
CERT_DIR="${SERVER_CERT_DIR:-$CERT_DIR}"
LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
LOG="${LOG_DIR}/upload.log"
DOMAIN="${DOMAIN:-}"
CPPM_HOST="${CPPM_HOST:-}"

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { local m="[$(ts)] [HOOK]  $*"; echo "$m";    echo "$m" >> "$LOG" 2>/dev/null; }
err() { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

source /opt/cppm/status.sh

ISSUE_ECC="${ISSUE_ECC:-true}"
ISSUE_RSA="${ISSUE_RSA:-true}"

log "=== Deploy Hook ==="

# ── Build cert path args and validate files ───────────────────────────────
UPLOAD_ARGS=()
PRIMARY_CERT=""

if [[ "$ISSUE_ECC" == "true" ]]; then
    HTTPS_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer"
    HTTPS_KEY="${CERT_DIR}/${DOMAIN}.ecc.key"
    HTTPS_FULLCHAIN="${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer"
    HTTPS_CA="${CERT_DIR}/${DOMAIN}.ecc.ca.cer"
    for f in "$HTTPS_CERT" "$HTTPS_KEY" "$HTTPS_FULLCHAIN"; do
        [[ -f "$f" ]] || { err "Required file not found: $f"; status_write "FAILED" "UPLOAD" "Cert file missing – ${f}"; exit 1; }
    done
    UPLOAD_ARGS+=(--https-cert "$HTTPS_CERT" --https-key "$HTTPS_KEY" \
                  --https-fullchain "$HTTPS_FULLCHAIN" --https-ca "$HTTPS_CA")
    PRIMARY_CERT="$HTTPS_CERT"
    log "  HTTPS (ECC): ${HTTPS_CERT}"
else
    UPLOAD_ARGS+=(--skip-https)
fi

if [[ "$ISSUE_RSA" == "true" ]]; then
    RADIUS_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"
    RADIUS_KEY="${CERT_DIR}/${DOMAIN}.rsa.key"
    RADIUS_FULLCHAIN="${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer"
    RADIUS_CA="${CERT_DIR}/${DOMAIN}.rsa.ca.cer"
    for f in "$RADIUS_CERT" "$RADIUS_KEY" "$RADIUS_FULLCHAIN"; do
        [[ -f "$f" ]] || { err "Required file not found: $f"; status_write "FAILED" "UPLOAD" "Cert file missing – ${f}"; exit 1; }
    done
    UPLOAD_ARGS+=(--radius-cert "$RADIUS_CERT" --radius-key "$RADIUS_KEY" \
                  --radius-fullchain "$RADIUS_FULLCHAIN" --radius-ca "$RADIUS_CA")
    [[ -z "$PRIMARY_CERT" ]] && PRIMARY_CERT="$RADIUS_CERT"
    log "  RADIUS (RSA): ${RADIUS_CERT}"
else
    UPLOAD_ARGS+=(--skip-radius)
fi

if [[ "${SKIP_UPLOAD:-false}" == "true" ]]; then
    log "SKIP_UPLOAD=true – skipping ClearPass upload."
    status_write "INFO" "UPLOAD" "Upload skipped (SKIP_UPLOAD=true)"
    exit 0
fi

log "Invoking ClearPass upload to ${CPPM_HOST}..."

UPLOAD_EXIT=0
python3 /opt/cppm/clearpass_upload.py \
    "${UPLOAD_ARGS[@]}" \
    --domain "$DOMAIN" \
    2>&1 | tee -a "$LOG" 2>/dev/null || UPLOAD_EXIT=$?

if [[ $UPLOAD_EXIT -eq 0 ]]; then
    log "Upload succeeded."
    EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_CERT" 2>/dev/null \
             | cut -d= -f2 || echo "unknown")
    UPLOAD_LABEL="$( [[ "$ISSUE_ECC" == "true" && "$ISSUE_RSA" == "true" ]] && echo "ECC→HTTPS + RSA→RADIUS" || \
                     [[ "$ISSUE_ECC" == "true" ]] && echo "ECC→HTTPS" || echo "RSA→RADIUS" )"
    status_write "OK" "UPLOAD" "${UPLOAD_LABEL} uploaded to ${CPPM_HOST} – expires ${EXPIRY}"
else
    err "Upload failed (exit ${UPLOAD_EXIT}) – check ${LOG}"
    status_write "FAILED" "UPLOAD" "ClearPass upload failed (exit ${UPLOAD_EXIT}) – check upload.log"
fi

log "=== Deploy Hook Complete ==="
