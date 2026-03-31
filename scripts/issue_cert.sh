#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# issue_cert.sh – Issue BOTH an ECC and an RSA certificate via Cloudflare DNS-01
#
# ECC (ec-256) → CPPM HTTPS(ECC) service slot
# RSA (2048)   → CPPM RADIUS service slot
#
# acme.sh stores ECC certs in:  $CERT_DIR/<domain>_ecc/
# acme.sh stores RSA certs in:  $CERT_DIR/<domain>/
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/renewal.log"
DOMAIN="${DOMAIN:-cppm.sinemalab.com}"

mkdir -p "$LOG_DIR" "$CERT_DIR"
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [ISSUE] $*" | tee -a "$LOG"; }
err() { echo "[$(ts)] [ERROR] $*" | tee -a "$LOG" >&2; }

source /opt/cppm/status.sh
unset DEBUG

die() { err "$*"; status_write "FAILED" "CERT" "$*"; exit 1; }

log "=== Certificate Issuance (ECC + RSA) ==="
log "Domain: $DOMAIN | Server: ${ACME_SERVER:-letsencrypt}"
status_write "INFO" "CERT" "Starting dual issuance – domain=${DOMAIN} server=${ACME_SERVER:-letsencrypt}"

[[ -z "${CF_Token:-}" ]] && die "CF_Token is not set"

COMMON_ARGS=(
    --issue
    --dns dns_cf
    --domain    "$DOMAIN"
    --server    "${ACME_SERVER:-letsencrypt}"
    --cert-home "$CERT_DIR"
    --home      /root/.acme.sh
    --log       "$LOG"
    --log-level 2
)
[[ "${FORCE_RENEW:-false}" == "true" ]] && COMMON_ARGS+=(--force)

# ── Issue ECC cert ─────────────────────────────────────────────────────────
log "--- Issuing ECC (ec-256) certificate ---"
ECC_EXIT=0
"$ACME_BIN" "${COMMON_ARGS[@]}" --keylength ec-256 || ECC_EXIT=$?

case $ECC_EXIT in
    0) log "ECC certificate issued successfully." ;;
    2) log "ECC cert exists in acme.sh state – not due for renewal." ;;
    *) die "acme.sh --issue (ECC) failed with exit code $ECC_EXIT – check ${LOG}" ;;
esac

# ── Issue RSA cert ─────────────────────────────────────────────────────────
log "--- Issuing RSA (2048) certificate ---"
RSA_EXIT=0
"$ACME_BIN" "${COMMON_ARGS[@]}" --keylength 2048 || RSA_EXIT=$?

case $RSA_EXIT in
    0) log "RSA certificate issued successfully." ;;
    2) log "RSA cert exists in acme.sh state – not due for renewal." ;;
    *) die "acme.sh --issue (RSA) failed with exit code $RSA_EXIT – check ${LOG}" ;;
esac

if [[ $ECC_EXIT -eq 0 || $RSA_EXIT -eq 0 ]]; then
    status_write "OK" "CERT" "New certificates issued (ECC + RSA) via Cloudflare DNS-01"
else
    status_write "INFO" "CERT" "Both certs exist in acme.sh state – running install only"
fi

/opt/cppm/install_cert.sh
