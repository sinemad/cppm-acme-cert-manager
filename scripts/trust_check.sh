#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# trust_check.sh – Periodic Let's Encrypt trust list verification
#
# Called by supercronic on a weekly schedule (Sunday 03:00 container-local time).
# Independently verifies that all required Let's Encrypt CA and intermediate CA
# certificates are present in the ClearPass trust list with EAP + Others enabled,
# and uploads any that are missing — without issuing or renewing certificates.
#
# Iterates over all servers configured in servers.json.
#
# To run manually:
#   docker exec -it cppm-acme-cert-manager /opt/cppm/trust_check.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/upload.log"   # startup log until per-server dir is known

ts() { date '+%Y-%m-%d %H:%M:%S'; }

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true

# shellcheck source=status.sh
source /opt/cppm/status.sh

log()  { local m="[$(ts)] [INFO ] $*"; echo "$m";    echo "$m" >> "$LOG" 2>/dev/null; }
warn() { local m="[$(ts)] [WARN ] $*"; echo "$m";    echo "$m" >> "$LOG" 2>/dev/null; }
err()  { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

log "=== Trust List Verification (weekly) ==="

SERVER_IDS=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import load_servers
for s in load_servers():
    sid = s.get('id', '')
    if sid:
        print(sid)
" 2>/dev/null || echo "")

if [[ -z "$SERVER_IDS" ]]; then
    log "No servers configured – skipping trust check."
    status_write "INFO" "TRUST" "Trust check skipped – no servers configured"
    exit 0
fi

OVERALL_EXIT=0

for SERVER_ID in $SERVER_IDS; do
    log "--- Server: ${SERVER_ID} ---"

    SERVER_ENV=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import get_server_shell_env
output = get_server_shell_env('${SERVER_ID}')
if output:
    print(output)
" 2>/dev/null) || true

    if [[ -z "$SERVER_ENV" ]]; then
        err "Failed to load configuration for server ${SERVER_ID} – skipping"
        continue
    fi
    eval "$SERVER_ENV"

    # Switch to per-server cert and log directories
    CERT_DIR="${SERVER_CERT_DIR:-/data/certs}"
    LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
    LOG="${LOG_DIR}/upload.log"
    mkdir -p "$LOG_DIR"
    status_server_init

    if [[ -z "${DOMAIN:-}" ]]; then
        err "Server ${SERVER_ID}: DOMAIN is empty – skipping"
        continue
    fi

    ECC_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer"
    RSA_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"

    # Skip if any enabled cert type has not yet been issued
    CERTS_READY=true
    [[ "${ISSUE_ECC:-true}" == "true" && ! -f "$ECC_CERT" ]] && CERTS_READY=false
    [[ "${ISSUE_RSA:-true}" == "true" && ! -f "$RSA_CERT" ]] && CERTS_READY=false
    if [[ "$CERTS_READY" != "true" ]]; then
        warn "Certificates not yet issued for ${DOMAIN} – skipping trust check."
        status_write "INFO" "TRUST" "Trust check skipped for ${DOMAIN} – certificates not yet issued"
        continue
    fi

    log "Domain : ${DOMAIN}"
    log "CPPM   : ${CPPM_HOST:-NOT SET}"

    unset DEBUG
    TRUST_EXIT=0
    # Build args based on which cert types are enabled for this server
    TRUST_ARGS=(--only-trust-check)
    [[ "${ISSUE_ECC:-true}" == "true" ]] && TRUST_ARGS+=(
        --https-cert      "${CERT_DIR}/${DOMAIN}.ecc.cer"
        --https-key       "${CERT_DIR}/${DOMAIN}.ecc.key"
        --https-fullchain "${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer"
        --https-ca        "${CERT_DIR}/${DOMAIN}.ecc.ca.cer"
    )
    [[ "${ISSUE_RSA:-true}" == "true" ]] && TRUST_ARGS+=(
        --radius-cert      "${CERT_DIR}/${DOMAIN}.rsa.cer"
        --radius-key       "${CERT_DIR}/${DOMAIN}.rsa.key"
        --radius-fullchain "${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer"
        --radius-ca        "${CERT_DIR}/${DOMAIN}.rsa.ca.cer"
    )
    python3 /opt/cppm/clearpass_upload.py "${TRUST_ARGS[@]}" \
        2>&1 | tee -a "$LOG" 2>/dev/null || TRUST_EXIT=$?

    if [[ "$TRUST_EXIT" -eq 0 ]]; then
        log "Trust check completed for ${DOMAIN}."
    else
        err "Trust check failed for ${DOMAIN} (exit ${TRUST_EXIT}) – check ${LOG}"
        OVERALL_EXIT=$TRUST_EXIT
    fi
done

log "=== Trust List Verification Complete ==="
exit "$OVERALL_EXIT"
