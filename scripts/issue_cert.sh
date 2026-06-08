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
#   infoblox         rfc2136 (nsupdate / Active Directory DNS)
#   Any Lego DNS provider name can be used directly.
#
# ACME CA is selected via ACME_SERVER in servers.json. Supported values:
#   letsencrypt  letsencrypt_test  zerossl  buypass  buypass_test
#   Any ACME directory URL for a custom/private CA (e.g. Step-CA, EJBCA, Vault PKI)
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
if [[ "$ISSUE_ECC" == "true" && "$ISSUE_RSA" == "true" ]]; then
    CERT_LABEL="ECC + RSA"
elif [[ "$ISSUE_ECC" == "true" ]]; then
    CERT_LABEL="ECC"
else
    CERT_LABEL="RSA"
fi

# Build a human-readable CA label for log/status messages.
ACME_CA_LABEL="${ACME_SERVER:-letsencrypt}"
case "$ACME_CA_LABEL" in
    letsencrypt)      ACME_CA_LABEL="Let's Encrypt" ;;
    letsencrypt_test) ACME_CA_LABEL="Let's Encrypt (Staging)" ;;
    zerossl)          ACME_CA_LABEL="ZeroSSL" ;;
    buypass)          ACME_CA_LABEL="Buypass" ;;
    buypass_test)     ACME_CA_LABEL="Buypass (Staging)" ;;
    http*)            ACME_CA_LABEL="Custom CA (${ACME_CA_LABEL})" ;;
esac

log "=== Certificate Issuance (${CERT_LABEL}) ==="
log "  Domain   : ${DOMAIN:-NOT SET}"
log "  CPPM     : ${CPPM_HOST:-NOT SET}"
log "  DNS      : ${DNS_PROVIDER:-NOT SET}"
log "  ACME CA  : ${ACME_CA_LABEL}"
log "  Types    : ${CERT_LABEL}"
log "  Callback : http://${CPPM_CALLBACK_HOST:-not set}:${CPPM_CALLBACK_PORT:-8765}/"
status_write "INFO" "CERT" "Starting issuance (${CERT_LABEL}) – domain=${DOMAIN:-?} dns=${DNS_PROVIDER:-?} ca=${ACME_CA_LABEL}"

FORCE_FLAG=""
[[ "${FORCE_RENEW:-false}" == "true" ]] && FORCE_FLAG="--force"

ISSUE_EXIT=0
# shellcheck disable=SC2086
python3 /opt/cppm/acme_cli.py issue $FORCE_FLAG 2>&1 | tee -a "$LOG" || ISSUE_EXIT=$?

[[ $ISSUE_EXIT -ne 0 ]] && die "Certificate issuance failed (exit ${ISSUE_EXIT}) – check ${LOG}"

status_write "OK" "CERT" "New ${CERT_LABEL} certificate(s) issued – dns=${DNS_PROVIDER:-?} ca=${ACME_CA_LABEL}"

/opt/cppm/install_cert.sh
