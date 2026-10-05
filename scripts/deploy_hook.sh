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
NODE_RESULTS="${LOG_DIR}/cppm_node_results.json"
rm -f "$NODE_RESULTS" 2>/dev/null || true
CPPM_NODE_RESULTS_FILE="$NODE_RESULTS" python3 /opt/cppm/clearpass_upload.py \
    "${UPLOAD_ARGS[@]}" \
    --domain "$DOMAIN" \
    2>&1 | tee -a "$LOG" 2>/dev/null || UPLOAD_EXIT=$?

# Cluster mode writes per-node results. Build one line listing every node,
# e.g. "received: 10.0.0.11 (a.example.com) | NOT updated: 10.0.0.12 (b.example.com) (exit 1)"
NODE_SUMMARY=""
NODE_FAILED=""
if [[ -s "$NODE_RESULTS" ]]; then
    NODE_SUMMARY=$(python3 - "$NODE_RESULTS" 2>/dev/null <<'PY' || true
import json, sys
results = json.load(open(sys.argv[1]))
def label(r):
    return "{} ({})".format(r["ip"], r["fqdn"] or "no FQDN")
ok  = [label(r) for r in results if r["ok"]]
bad = [label(r) + " " + r["reason"] for r in results if not r["ok"]]
parts = []
if ok:
    parts.append("received: " + ", ".join(ok))
if bad:
    parts.append("NOT updated: " + ", ".join(bad))
print(" | ".join(parts))
PY
    )
    NODE_FAILED=$(python3 - "$NODE_RESULTS" 2>/dev/null <<'PY' || true
import json, sys
print(sum(1 for r in json.load(open(sys.argv[1])) if not r["ok"]))
PY
    )
fi

if [[ $UPLOAD_EXIT -eq 0 || $UPLOAD_EXIT -eq 2 ]]; then
    EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_CERT" 2>/dev/null \
             | cut -d= -f2 || echo "unknown")
    UPLOAD_LABEL="selected certificate targets"
fi

if [[ $UPLOAD_EXIT -eq 0 ]]; then
    log "Upload succeeded."
    if [[ -n "$NODE_SUMMARY" ]]; then
        MSG="${UPLOAD_LABEL} uploaded to all cluster nodes via ${ACME_CA_LABEL} – expires ${EXPIRY}. ${NODE_SUMMARY}"
    else
        MSG="${UPLOAD_LABEL} uploaded to ${CPPM_HOST} via ${ACME_CA_LABEL} – expires ${EXPIRY}"
    fi
    status_write "OK" "UPLOAD" "$MSG"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_success \
        --message "$MSG" \
        2>&1 | tee -a "$LOG" >/dev/null \
        || err "Notification (upload_success) failed – see errors above in ${LOG}"
elif [[ $UPLOAD_EXIT -eq 2 ]]; then
    MSG="PARTIAL: ${UPLOAD_LABEL} NOT uploaded to ${NODE_FAILED} cluster node(s) via ${ACME_CA_LABEL} – expires ${EXPIRY}. ${NODE_SUMMARY}. Likely cause: cluster config sync from the publisher is lagging or failing for the nodes not updated."
    log "Upload partially succeeded (${NODE_FAILED} node(s) not updated)."
    status_write "WARN" "UPLOAD" "$MSG"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_partial \
        --message "$MSG" \
        2>&1 | tee -a "$LOG" >/dev/null \
        || err "Notification (upload_partial) failed – see errors above in ${LOG}"
else
    err "Upload failed (exit ${UPLOAD_EXIT}) – check ${LOG}"
    MSG="ClearPass upload failed (exit ${UPLOAD_EXIT}) for ${CPPM_HOST}"
    [[ -n "$NODE_SUMMARY" ]] && MSG="${MSG}. ${NODE_SUMMARY}"
    status_write "FAILED" "UPLOAD" "${MSG} – check cppm_upload.log"
    python3 /opt/cppm/notify.py \
        --server-id "${SERVER_ID:-}" \
        --event upload_failed \
        --message "${MSG} – check cppm_upload.log" \
        2>&1 | tee -a "$LOG" >/dev/null \
        || err "Notification (upload_failed) failed – see errors above in ${LOG}"
fi

log "=== Deploy Hook Complete ==="
