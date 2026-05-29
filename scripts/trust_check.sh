#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# trust_check.sh – Periodic Let's Encrypt trust list verification
#
# Called by supercronic on a weekly schedule (Sunday 03:00 container-local time).
# Independently verifies that all required Let's Encrypt CA and intermediate CA
# certificates are present in the ClearPass trust list with EAP + Others enabled,
# and uploads any that are missing — without issuing or renewing certificates.
#
# To run manually:
#   docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
DOMAIN="${DOMAIN:-cppm.sinemalab.com}"
LOG="${LOG_DIR}/upload.log"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

mkdir -p "$LOG_DIR"

# Source status library (writes to /data/certs/status.log)
# shellcheck source=status.sh
source /opt/cppm/status.sh

log()  { echo "[$(ts)] [INFO ] $*" | tee -a "$LOG"; }
warn() { echo "[$(ts)] [WARN ] $*" | tee -a "$LOG"; }
err()  { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }

log "=== Trust List Verification (weekly) ==="

# ── Guard: certificates must exist before we can check trust ──────────────────
ECC_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer"
RSA_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"

if [[ ! -f "$ECC_CERT" || ! -f "$RSA_CERT" ]]; then
    warn "Certificates not yet issued – skipping trust check."
    warn "  Missing: $( [[ ! -f "$ECC_CERT" ]] && echo "$ECC_CERT" ) $( [[ ! -f "$RSA_CERT" ]] && echo "$RSA_CERT" )"
    status_write "INFO" "TRUST" "Trust check skipped – certificates not yet issued"
    exit 0
fi

log "Domain  : ${DOMAIN}"
log "CPPM    : ${CPPM_HOST:-NOT SET}"

# ── Run trust-only check via clearpass_upload.py ──────────────────────────────
# --only-trust-check skips Steps 1–3 (cert upload) and runs only Step 0
# (trust list pre-flight). Both ECC and RSA CA chain paths are passed so
# intermediates unique to either chain (e.g. R13 in the RSA chain) are found.
unset DEBUG

python3 /opt/cppm/clearpass_upload.py \
    --only-trust-check \
    --https-cert      "${CERT_DIR}/${DOMAIN}.ecc.cer" \
    --https-key       "${CERT_DIR}/${DOMAIN}.ecc.key" \
    --https-fullchain "${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer" \
    --https-ca        "${CERT_DIR}/${DOMAIN}.ecc.ca.cer" \
    --radius-cert      "${CERT_DIR}/${DOMAIN}.rsa.cer" \
    --radius-key       "${CERT_DIR}/${DOMAIN}.rsa.key" \
    --radius-fullchain "${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer" \
    --radius-ca        "${CERT_DIR}/${DOMAIN}.rsa.ca.cer" \
    2>&1 | tee -a "$LOG"

EXIT_CODE="${PIPESTATUS[0]}"

if [[ "$EXIT_CODE" -eq 0 ]]; then
    log "Trust check completed successfully."
else
    err "Trust check failed (exit ${EXIT_CODE}) – see ${LOG} for details."
fi

exit "$EXIT_CODE"
