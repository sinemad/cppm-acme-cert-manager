#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# linux_ssh_deploy_hook.sh – Called after successful issuance/renewal
#                  Pushes the fullchain/key (ECC by default, RSA, or both
#                  per the target's SSH_KEY_TYPE) to a Linux SSH target and
#                  runs its configured reload command.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="/data/certs"
CERT_DIR="${SERVER_CERT_DIR:-$CERT_DIR}"
LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/logs}"
LOG="${LOG_DIR}/ssh_deploy.log"
DOMAIN="${DOMAIN:-}"
SSH_HOST="${SSH_HOST:-}"

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { local m="[$(ts)] [HOOK]  $*"; echo "$m";    echo "$m" >> "$LOG" 2>/dev/null; }
err() { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

source /opt/cppm/status.sh
DOMAIN_FILE="$(cert_file_stem "$DOMAIN")"

log "=== Deploy Hook (Linux SSH) ==="
log "  Target : ${SSH_HOST}"
log "  Domain : ${DOMAIN}"

KEY_TYPE="${SSH_KEY_TYPE:-ecc}"
[[ "$KEY_TYPE" == "rsa" || "$KEY_TYPE" == "both" ]] || KEY_TYPE="ecc"
log "  Key    : ${KEY_TYPE^^}"
# "both" deploys the ECC pair (LOCAL_*) and the RSA pair (LOCAL_*_RSA); ssh_upload.py
# gives them .ecc/.rsa-suffixed remote names. Single types keep fullchain.pem/privkey.pem.
PRIMARY="$KEY_TYPE"; [[ "$KEY_TYPE" == "both" ]] && PRIMARY="ecc"
LOCAL_FULLCHAIN="${CERT_DIR}/${DOMAIN_FILE}.${PRIMARY}.fullchain.cer"
LOCAL_PRIVKEY="${CERT_DIR}/${DOMAIN_FILE}.${PRIMARY}.key"
REQUIRED_FILES=("$LOCAL_FULLCHAIN" "$LOCAL_PRIVKEY")
if [[ "$KEY_TYPE" == "both" ]]; then
    LOCAL_FULLCHAIN_RSA="${CERT_DIR}/${DOMAIN_FILE}.rsa.fullchain.cer"
    LOCAL_PRIVKEY_RSA="${CERT_DIR}/${DOMAIN_FILE}.rsa.key"
    REQUIRED_FILES+=("$LOCAL_FULLCHAIN_RSA" "$LOCAL_PRIVKEY_RSA")
    export LOCAL_FULLCHAIN_RSA LOCAL_PRIVKEY_RSA
fi
export SSH_KEY_TYPE="$KEY_TYPE"
for f in "${REQUIRED_FILES[@]}"; do
    [[ -f "$f" ]] || { err "Required file not found: $f"; status_write "FAILED" "UPLOAD" "Cert file missing – ${f}"; exit 1; }
done

if [[ "${SKIP_UPLOAD:-false}" == "true" ]]; then
    log "SKIP_UPLOAD=true – skipping SSH deploy."
    status_write "INFO" "UPLOAD" "Upload skipped (SKIP_UPLOAD=true)"
    exit 0
fi

export LOCAL_FULLCHAIN LOCAL_PRIVKEY

DEPLOY_EXIT=0
python3 /opt/cppm/ssh_upload.py deploy 2>&1 | tee -a "$LOG" 2>/dev/null || DEPLOY_EXIT=$?

if [[ $DEPLOY_EXIT -eq 0 ]]; then
    EXPIRY=$(openssl x509 -enddate -noout -in "$LOCAL_FULLCHAIN" 2>/dev/null | cut -d= -f2 || echo "unknown")
    MSG="Certificate deployed to ${SSH_HOST} via SSH – expires ${EXPIRY}"
    log "Deploy succeeded."
    status_write "OK" "UPLOAD" "$MSG"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_success \
        --message "$MSG" \
        2>&1 | tee -a "$LOG" >/dev/null \
        || err "Notification (upload_success) failed – see errors above in ${LOG}"
else
    err "Deploy failed (exit ${DEPLOY_EXIT}) – check ${LOG}"
    MSG="SSH deploy failed (exit ${DEPLOY_EXIT}) for ${SSH_HOST}"
    status_write "FAILED" "UPLOAD" "${MSG} – check ssh_deploy.log"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_failed \
        --message "${MSG} – check ssh_deploy.log" \
        2>&1 | tee -a "$LOG" >/dev/null \
        || err "Notification (upload_failed) failed – see errors above in ${LOG}"
fi

log "=== Deploy Hook Complete ==="
