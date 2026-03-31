#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install_cert.sh – Install BOTH ECC and RSA certs from acme.sh state
#                   to flat paths, then trigger ClearPass upload.
#
# Flat file layout:
#   ECC: /data/certs/<domain>.ecc.cer  / .ecc.key / .ecc.fullchain.cer / .ecc.ca.cer
#   RSA: /data/certs/<domain>.rsa.cer  / .rsa.key / .rsa.fullchain.cer / .rsa.ca.cer
#
# acme.sh state directories:
#   ECC: /data/certs/<domain>_ecc/<domain>.cer   (--ecc flag required)
#   RSA: /data/certs/<domain>/<domain>.cer
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/renewal.log"
DOMAIN="${DOMAIN:-cppm.sinemalab.com}"

mkdir -p "$LOG_DIR" "$CERT_DIR"
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [INSTALL] $*" | tee -a "$LOG"; }
err() { echo "[$(ts)] [ERROR  ] $*" | tee -a "$LOG" >&2; }

source /opt/cppm/status.sh
unset DEBUG

die() { err "$*"; status_write "FAILED" "CERT" "$*"; exit 1; }

log "=== Install Cert Files (ECC + RSA) ==="
log "Domain: $DOMAIN"

# ── Install ECC cert ───────────────────────────────────────────────────────
ECC_ACME_CERT="${CERT_DIR}/${DOMAIN}_ecc/${DOMAIN}.cer"
if [[ -f "$ECC_ACME_CERT" ]]; then
    log "--- Installing ECC certificate ---"
    "$ACME_BIN" --install-cert \
        --domain         "$DOMAIN" \
        --ecc \
        --home           /root/.acme.sh \
        --cert-home      "$CERT_DIR" \
        --cert-file      "${CERT_DIR}/${DOMAIN}.ecc.cer" \
        --key-file       "${CERT_DIR}/${DOMAIN}.ecc.key" \
        --fullchain-file "${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer" \
        --ca-file        "${CERT_DIR}/${DOMAIN}.ecc.ca.cer" \
        2>&1 | tee -a "$LOG"
    chmod 600 "${CERT_DIR}/${DOMAIN}.ecc.key"
    log "  ECC cert installed."
else
    err "ECC acme.sh state not found at ${ECC_ACME_CERT} – run issue_cert.sh first"
fi

# ── Install RSA cert ───────────────────────────────────────────────────────
RSA_ACME_CERT="${CERT_DIR}/${DOMAIN}/${DOMAIN}.cer"
if [[ -f "$RSA_ACME_CERT" ]]; then
    log "--- Installing RSA certificate ---"
    "$ACME_BIN" --install-cert \
        --domain         "$DOMAIN" \
        --home           /root/.acme.sh \
        --cert-home      "$CERT_DIR" \
        --cert-file      "${CERT_DIR}/${DOMAIN}.rsa.cer" \
        --key-file       "${CERT_DIR}/${DOMAIN}.rsa.key" \
        --fullchain-file "${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer" \
        --ca-file        "${CERT_DIR}/${DOMAIN}.rsa.ca.cer" \
        2>&1 | tee -a "$LOG"
    chmod 600 "${CERT_DIR}/${DOMAIN}.rsa.key"
    log "  RSA cert installed."
else
    err "RSA acme.sh state not found at ${RSA_ACME_CERT} – run issue_cert.sh first"
fi

# ── Verify all expected flat files exist ──────────────────────────────────
MISSING=0
for f in \
    "${CERT_DIR}/${DOMAIN}.ecc.cer"          "${CERT_DIR}/${DOMAIN}.ecc.key" \
    "${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer" "${CERT_DIR}/${DOMAIN}.ecc.ca.cer" \
    "${CERT_DIR}/${DOMAIN}.rsa.cer"          "${CERT_DIR}/${DOMAIN}.rsa.key" \
    "${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer" "${CERT_DIR}/${DOMAIN}.rsa.ca.cer"; do
    if [[ -f "$f" ]]; then
        log "  OK: $(basename "$f")"
    else
        err "Missing: $f"
        MISSING=$((MISSING + 1))
    fi
done
[[ $MISSING -gt 0 ]] && die "$MISSING expected file(s) missing after --install-cert"

# Log ECC expiry as the primary indicator
EXPIRY=$(openssl x509 -enddate -noout -in "${CERT_DIR}/${DOMAIN}.ecc.cer" 2>/dev/null \
         | cut -d= -f2 || echo "unknown")
DAYS_LEFT="unknown"
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
if [[ "$EXPIRY_EPOCH" -gt 0 ]]; then
    DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
fi

log "ECC certificate expires ${EXPIRY} (${DAYS_LEFT} days)"
RSA_EXPIRY=$(openssl x509 -enddate -noout -in "${CERT_DIR}/${DOMAIN}.rsa.cer" 2>/dev/null \
             | cut -d= -f2 || echo "unknown")
log "RSA certificate expires ${RSA_EXPIRY}"
status_write "OK" "CERT" "ECC+RSA certs installed – expires ${EXPIRY} (${DAYS_LEFT} days remaining)"

log "Triggering ClearPass upload..."
/opt/cppm/deploy_hook.sh

log "=== Install complete ==="
