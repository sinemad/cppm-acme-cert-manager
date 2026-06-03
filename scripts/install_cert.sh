#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install_cert.sh – Install ECC and/or RSA certs from acme.sh state
#                   to flat paths, then trigger ClearPass upload.
#
# Flat file layout (per-server directory, e.g. /data/certs/cppm.example.com/):
#   ECC: <SERVER_CERT_DIR>/<domain>.ecc.cer  / .ecc.key / .ecc.fullchain.cer / .ecc.ca.cer
#   RSA: <SERVER_CERT_DIR>/<domain>.rsa.cer  / .rsa.key / .rsa.fullchain.cer / .rsa.ca.cer
#
# acme.sh state directories (also inside SERVER_CERT_DIR):
#   ECC: <SERVER_CERT_DIR>/<domain>_ecc/<domain>.cer   (--ecc flag required)
#   RSA: <SERVER_CERT_DIR>/<domain>/<domain>.cer
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
CERT_DIR="/data/certs"
CERT_DIR="${SERVER_CERT_DIR:-$CERT_DIR}"
LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
LOG="${LOG_DIR}/acme_renewal.log"
DOMAIN="${DOMAIN:-}"

mkdir -p "$LOG_DIR" "$CERT_DIR"
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [INSTALL] $*" | tee -a "$LOG"; }
err() { echo "[$(ts)] [ERROR  ] $*" | tee -a "$LOG" >&2; }

source /opt/cppm/status.sh
unset DEBUG

die() { err "$*"; status_write "FAILED" "CERT" "$*"; exit 1; }

ISSUE_ECC="${ISSUE_ECC:-true}"
ISSUE_RSA="${ISSUE_RSA:-true}"
CERT_LABEL="$( [[ "$ISSUE_ECC" == "true" && "$ISSUE_RSA" == "true" ]] && echo "ECC + RSA" || \
               [[ "$ISSUE_ECC" == "true" ]] && echo "ECC" || echo "RSA" )"

log "=== Install Cert Files (${CERT_LABEL}) ==="
log "  Domain : $DOMAIN"
log "  CPPM   : ${CPPM_HOST:-NOT SET}"
log "  Types  : ${CERT_LABEL}"

# ── Install ECC cert ───────────────────────────────────────────────────────
if [[ "$ISSUE_ECC" == "true" ]]; then
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
else
    log "--- Skipping ECC install (ISSUE_ECC=false) ---"
fi

# ── Install RSA cert ───────────────────────────────────────────────────────
if [[ "$ISSUE_RSA" == "true" ]]; then
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
else
    log "--- Skipping RSA install (ISSUE_RSA=false) ---"
fi

# ── Verify expected flat files exist ──────────────────────────────────────
MISSING=0
if [[ "$ISSUE_ECC" == "true" ]]; then
    for f in "${CERT_DIR}/${DOMAIN}.ecc.cer" "${CERT_DIR}/${DOMAIN}.ecc.key" \
              "${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer" "${CERT_DIR}/${DOMAIN}.ecc.ca.cer"; do
        [[ -f "$f" ]] && log "  OK: $(basename "$f")" || { err "Missing: $f"; MISSING=$((MISSING+1)); }
    done
fi
if [[ "$ISSUE_RSA" == "true" ]]; then
    for f in "${CERT_DIR}/${DOMAIN}.rsa.cer" "${CERT_DIR}/${DOMAIN}.rsa.key" \
              "${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer" "${CERT_DIR}/${DOMAIN}.rsa.ca.cer"; do
        [[ -f "$f" ]] && log "  OK: $(basename "$f")" || { err "Missing: $f"; MISSING=$((MISSING+1)); }
    done
fi
[[ $MISSING -gt 0 ]] && die "$MISSING expected file(s) missing after --install-cert"

# ── Log expiry ────────────────────────────────────────────────────────────
PRIMARY_CERT=""
[[ "$ISSUE_ECC" == "true" ]] && PRIMARY_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer" \
                              || PRIMARY_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"
EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_CERT" 2>/dev/null \
         | cut -d= -f2 || echo "unknown")
DAYS_LEFT="unknown"
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
if [[ "$EXPIRY_EPOCH" -gt 0 ]]; then
    DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
fi
log "Certificate expires ${EXPIRY} (${DAYS_LEFT} days)"
if [[ "$ISSUE_ECC" == "true" && "$ISSUE_RSA" == "true" ]]; then
    RSA_EXPIRY=$(openssl x509 -enddate -noout -in "${CERT_DIR}/${DOMAIN}.rsa.cer" 2>/dev/null \
                 | cut -d= -f2 || echo "unknown")
    log "RSA certificate expires ${RSA_EXPIRY}"
fi
status_write "OK" "CERT" "${CERT_LABEL} cert(s) installed – expires ${EXPIRY} (${DAYS_LEFT} days remaining)"

log "Triggering ClearPass upload..."
/opt/cppm/deploy_hook.sh

log "=== Install complete ==="
