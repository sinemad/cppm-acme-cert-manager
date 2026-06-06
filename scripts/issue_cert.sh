#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# issue_cert.sh – Issue ECC and/or RSA certificates via DNS-01 challenge.
# Delegates to acme_cli.py which drives the Lego ACME client.
#
# Certificate types are controlled by ISSUE_ECC and ISSUE_RSA (default: both).
#   ECC (ec-256)  → CPPM HTTPS(ECC) service slot
#   RSA (2048)    → CPPM RADIUS service slot
#
# DNS provider is selected via DNS_PROVIDER in servers.json. Supported values:
#   cloudflare (cf)  porkbun  route53 (aws, r53)  digitalocean (do)  godaddy (gd)
#   Any Lego DNS provider name can be used directly.
#
# Lego stores cert state in per-key-type subdirectories:
#   ECC: $SERVER_CERT_DIR/lego-ecc/certificates/<domain>.crt
#   RSA: $SERVER_CERT_DIR/lego-rsa/certificates/<domain>.crt
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="${SERVER_CERT_DIR:-/data/certs}"
LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
LOG="${LOG_DIR}/acme_renewal.log"

mkdir -p "$LOG_DIR" "$CERT_DIR"
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [ISSUE] $*" | tee -a "$LOG"; }
err() { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }

source /opt/cppm/status.sh
unset DEBUG

die() { err "$*"; status_write "FAILED" "CERT" "$*"; exit 1; }

ISSUE_ECC="${ISSUE_ECC:-true}"
ISSUE_RSA="${ISSUE_RSA:-true}"
CERT_LABEL="$( [[ "$ISSUE_ECC" == "true" && "$ISSUE_RSA" == "true" ]] && echo "ECC + RSA" || \
               [[ "$ISSUE_ECC" == "true" ]] && echo "ECC" || echo "RSA" )"

log "=== Certificate Issuance (${CERT_LABEL}) ==="
log "  Domain   : ${DOMAIN:-NOT SET}"
log "  CPPM     : ${CPPM_HOST:-NOT SET}"
log "  DNS      : ${DNS_PROVIDER:-NOT SET}"
log "  ACME CA  : ${ACME_SERVER:-letsencrypt}"
log "  Types    : ${CERT_LABEL}"
log "  Callback : http://${CPPM_CALLBACK_HOST:-not set}:${CPPM_CALLBACK_PORT:-8765}/"
status_write "INFO" "CERT" "Starting issuance (${CERT_LABEL}) – domain=${DOMAIN:-?} provider=${DNS_PROVIDER:-?} server=${ACME_SERVER:-letsencrypt}"

FORCE_FLAG=""
[[ "${FORCE_RENEW:-false}" == "true" ]] && FORCE_FLAG="--force"

ISSUE_EXIT=0
# shellcheck disable=SC2086
python3 /opt/cppm/acme_cli.py issue $FORCE_FLAG 2>&1 | tee -a "$LOG" || ISSUE_EXIT=$?

[[ $ISSUE_EXIT -ne 0 ]] && die "Certificate issuance failed (exit ${ISSUE_EXIT}) – check ${LOG}"

status_write "OK" "CERT" "New ${CERT_LABEL} certificate(s) issued via ${DNS_PROVIDER:-?} DNS-01"

/opt/cppm/install_cert.sh
