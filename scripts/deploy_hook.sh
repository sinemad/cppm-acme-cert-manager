#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy_hook.sh – Called after successful issuance/renewal
#                  Uploads selected ECC/RSA certs to ClearPass service slots
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="/data/certs"
CERT_DIR="${SERVER_CERT_DIR:-$CERT_DIR}"
LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/logs}"
LOG="${LOG_DIR}/cppm_upload.log"
DOMAIN="${DOMAIN:-}"
CPPM_HOST="${CPPM_HOST:-}"
CPPM_CALLBACK_HOST="${CPPM_CALLBACK_HOST:-}"
CPPM_CALLBACK_PORT="${CPPM_CALLBACK_PORT:-8765}"
DNS_PROVIDER="${DNS_PROVIDER:-unknown}"
ACME_SERVER="${ACME_SERVER:-letsencrypt}"

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { local m="[$(ts)] [HOOK]  $*"; echo "$m";    echo "$m" >> "$LOG" 2>/dev/null; }
err() { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

source /opt/cppm/status.sh

# Serialize all upload invocations — the callback HTTP server binds a fixed
# port, so two concurrent deploy_hook.sh runs (e.g. cert pipeline + manual
# upload trigger) would both fail with "Address in use".
UPLOAD_LOCK="/tmp/cppm_upload_${CPPM_CALLBACK_PORT:-8765}.lock"
exec 9>"$UPLOAD_LOCK"
if ! flock -n 9; then
    log "Another upload is already in progress – skipping this run."
    status_write "WARN" "UPLOAD" "Upload skipped – another upload was already in progress. Try again shortly."
    exit 0
fi

ISSUE_ECC="${ISSUE_ECC:-true}"
ISSUE_RSA="${ISSUE_RSA:-true}"
UPLOAD_HTTPS_ECC="${UPLOAD_HTTPS_ECC:-$ISSUE_ECC}"
UPLOAD_HTTPS_RSA="${UPLOAD_HTTPS_RSA:-false}"
UPLOAD_RADIUS="${UPLOAD_RADIUS:-$ISSUE_RSA}"
UPLOAD_RADSEC="${UPLOAD_RADSEC:-$ISSUE_RSA}"

ACME_CA_LABEL="${ACME_SERVER:-letsencrypt}"
case "$ACME_CA_LABEL" in
    letsencrypt)      ACME_CA_LABEL="Let's Encrypt" ;;
    letsencrypt_test) ACME_CA_LABEL="Let's Encrypt (Staging)" ;;
    zerossl)          ACME_CA_LABEL="ZeroSSL" ;;
    buypass)          ACME_CA_LABEL="Buypass" ;;
    buypass_test)     ACME_CA_LABEL="Buypass (Staging)" ;;
    http*)            ACME_CA_LABEL="Custom CA (${ACME_CA_LABEL})" ;;
esac

log "=== Deploy Hook ==="
log "  ClearPass: ${CPPM_HOST}"
log "  Domain   : ${DOMAIN}"
log "  Callback : http://${CPPM_CALLBACK_HOST}:${CPPM_CALLBACK_PORT}/"
log "  DNS      : ${DNS_PROVIDER}"
log "  ACME CA  : ${ACME_CA_LABEL}"

# ── Build cert path args and validate files ───────────────────────────────
UPLOAD_ARGS=()
PRIMARY_CERT=""

if [[ "$UPLOAD_HTTPS_ECC" == "true" ]]; then
    HTTPS_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer"
    HTTPS_KEY="${CERT_DIR}/${DOMAIN}.ecc.key"
    HTTPS_FULLCHAIN="${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer"
    HTTPS_CA="${CERT_DIR}/${DOMAIN}.ecc.ca.cer"
    for f in "$HTTPS_CERT" "$HTTPS_KEY" "$HTTPS_FULLCHAIN"; do
        [[ -f "$f" ]] || { err "Required file not found: $f"; status_write "FAILED" "UPLOAD" "Cert file missing – ${f}"; exit 1; }
    done
    UPLOAD_ARGS+=(--https-ecc-cert "$HTTPS_CERT" --https-ecc-key "$HTTPS_KEY" \
                  --https-fullchain "$HTTPS_FULLCHAIN" --https-ca "$HTTPS_CA")
    PRIMARY_CERT="$HTTPS_CERT"
    log "  HTTPS (ECC): ${HTTPS_CERT}"
else
    UPLOAD_ARGS+=(--skip-https-ecc)
fi

if [[ "$UPLOAD_HTTPS_RSA" == "true" || "$UPLOAD_RADIUS" == "true" || "$UPLOAD_RADSEC" == "true" ]]; then
    RADIUS_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"
    RADIUS_KEY="${CERT_DIR}/${DOMAIN}.rsa.key"
    RADIUS_FULLCHAIN="${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer"
    RADIUS_CA="${CERT_DIR}/${DOMAIN}.rsa.ca.cer"
    for f in "$RADIUS_CERT" "$RADIUS_KEY" "$RADIUS_FULLCHAIN"; do
        [[ -f "$f" ]] || { err "Required file not found: $f"; status_write "FAILED" "UPLOAD" "Cert file missing – ${f}"; exit 1; }
    done
    if [[ "$UPLOAD_HTTPS_RSA" == "true" ]]; then
        UPLOAD_ARGS+=(--https-rsa-cert "$RADIUS_CERT" --https-rsa-key "$RADIUS_KEY" \
                      --https-rsa-fullchain "$RADIUS_FULLCHAIN" --https-rsa-ca "$RADIUS_CA")
    else
        UPLOAD_ARGS+=(--skip-https-rsa)
    fi
    if [[ "$UPLOAD_RADIUS" == "true" ]]; then
        UPLOAD_ARGS+=(--radius-cert "$RADIUS_CERT" --radius-key "$RADIUS_KEY" \
                      --radius-fullchain "$RADIUS_FULLCHAIN" --radius-ca "$RADIUS_CA")
    else
        UPLOAD_ARGS+=(--skip-radius)
    fi
    if [[ "$UPLOAD_RADSEC" == "true" ]]; then
        UPLOAD_ARGS+=(--radsec-cert "$RADIUS_CERT" --radsec-key "$RADIUS_KEY" \
                      --radsec-fullchain "$RADIUS_FULLCHAIN" --radsec-ca "$RADIUS_CA")
    else
        UPLOAD_ARGS+=(--skip-radsec)
    fi
    [[ -z "$PRIMARY_CERT" ]] && PRIMARY_CERT="$RADIUS_CERT"
    log "  RADIUS (RSA): ${RADIUS_CERT}"
else
    UPLOAD_ARGS+=(--skip-https-rsa --skip-radius --skip-radsec)
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
    UPLOAD_LABEL="selected certificate targets"
    status_write "OK" "UPLOAD" "${UPLOAD_LABEL} uploaded to ${CPPM_HOST} via ${ACME_CA_LABEL} – expires ${EXPIRY}"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_success \
        --message "${UPLOAD_LABEL} uploaded to ${CPPM_HOST} via ${ACME_CA_LABEL} – expires ${EXPIRY}" \
        2>/dev/null || true
else
    err "Upload failed (exit ${UPLOAD_EXIT}) – check ${LOG}"
    status_write "FAILED" "UPLOAD" "ClearPass upload failed (exit ${UPLOAD_EXIT}) – check cppm_upload.log"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_failed \
        --message "ClearPass upload failed (exit ${UPLOAD_EXIT}) for ${CPPM_HOST} – check cppm_upload.log" \
        2>/dev/null || true
fi

log "=== Deploy Hook Complete ==="
