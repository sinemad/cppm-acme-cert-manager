#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# trust_check.sh – Periodic ACME CA trust list verification
#
# Called by supercronic on a weekly schedule (Sunday 03:00 container-local time).
# Independently verifies that all required ACME CA and intermediate CA
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
LOG_DIR="/data/certs/logs"
LOG="${LOG_DIR}/cppm_upload.log"   # startup log until per-server dir is known

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
    LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/logs}"
    LOG="${LOG_DIR}/cppm_upload.log"
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

    ACME_CA_LABEL="${ACME_SERVER:-letsencrypt}"
    case "$ACME_CA_LABEL" in
        letsencrypt)      ACME_CA_LABEL="Let's Encrypt" ;;
        letsencrypt_test) ACME_CA_LABEL="Let's Encrypt (Staging)" ;;
        zerossl)          ACME_CA_LABEL="ZeroSSL" ;;
        buypass)          ACME_CA_LABEL="Buypass" ;;
        buypass_test)     ACME_CA_LABEL="Buypass (Staging)" ;;
        http*)            ACME_CA_LABEL="Custom CA (${ACME_CA_LABEL})" ;;
    esac

    log "=== Trust List Verification ==="
    log "  Domain   : ${DOMAIN}"
    log "  ClearPass: ${CPPM_HOST:-NOT SET}"
    log "  DNS      : ${DNS_PROVIDER:-NOT SET}"
    log "  ACME CA  : ${ACME_CA_LABEL}"
    log "  Callback : http://${CPPM_CALLBACK_HOST:-not set}:${CPPM_CALLBACK_PORT:-8765}/"

    unset DEBUG
    TRUST_EXIT=0
    # Build args based on which cert types are enabled for this server
    TRUST_ARGS=(--only-trust-check)
    [[ "${ISSUE_ECC:-true}" == "true" ]] && TRUST_ARGS+=(
        --https-ecc-cert  "${CERT_DIR}/${DOMAIN}.ecc.cer"
        --https-ecc-key   "${CERT_DIR}/${DOMAIN}.ecc.key"
        --https-fullchain "${CERT_DIR}/${DOMAIN}.ecc.fullchain.cer"
        --https-ca        "${CERT_DIR}/${DOMAIN}.ecc.ca.cer"
    )
    [[ "${ISSUE_RSA:-true}" == "true" ]] && TRUST_ARGS+=(
        --radius-cert      "${CERT_DIR}/${DOMAIN}.rsa.cer"
        --radius-key       "${CERT_DIR}/${DOMAIN}.rsa.key"
        --radius-fullchain "${CERT_DIR}/${DOMAIN}.rsa.fullchain.cer"
        --radius-ca        "${CERT_DIR}/${DOMAIN}.rsa.ca.cer"
    )

    # Serialize against deploy_hook.sh (and any other trust_check run) so this
    # never authenticates against the same ClearPass client_id while a real
    # upload is in flight — a concurrent OAuth token mint for the same
    # client_id can invalidate the token the in-flight upload is using,
    # producing spurious 403s partway through its run.
    UPLOAD_LOCK="/tmp/cppm_upload_${CPPM_CALLBACK_PORT:-8765}.lock"
    exec 9>"$UPLOAD_LOCK"
    if ! flock -n 9; then
        warn "Trust check for ${DOMAIN} skipped – an upload is already in progress. It will run again next week."
        status_write "WARN" "TRUST" "Trust check skipped for ${DOMAIN} – another upload was already in progress."
        exec 9>&-
        continue
    fi

    python3 /opt/cppm/clearpass_upload.py "${TRUST_ARGS[@]}" \
        2>&1 | tee -a "$LOG" 2>/dev/null || TRUST_EXIT=$?

    exec 9>&-

    if [[ "$TRUST_EXIT" -eq 0 ]]; then
        log "Trust check completed for ${DOMAIN}."
    else
        err "Trust check failed for ${DOMAIN} (exit ${TRUST_EXIT}) – check ${LOG}"
        OVERALL_EXIT=$TRUST_EXIT
    fi
done

log "=== Trust List Verification Complete ==="
exit "$OVERALL_EXIT"
