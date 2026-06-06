#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install_cert.sh – Copy Lego cert state to flat file paths, then upload.
#
# Flat file layout (per-server directory):
#   ECC: <SERVER_CERT_DIR>/<domain>.ecc.cer  / .ecc.key / .ecc.fullchain.cer / .ecc.ca.cer
#   RSA: <SERVER_CERT_DIR>/<domain>.rsa.cer  / .rsa.key / .rsa.fullchain.cer / .rsa.ca.cer
#
# Lego cert state (inside SERVER_CERT_DIR):
#   ECC: lego-ecc/certificates/<domain>.crt / .key / .issuer.crt
#   RSA: lego-rsa/certificates/<domain>.crt / .key / .issuer.crt
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="${SERVER_CERT_DIR:-/data/certs}"
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

INSTALL_EXIT=0
python3 /opt/cppm/acme_cli.py install 2>&1 | tee -a "$LOG" || INSTALL_EXIT=$?

[[ $INSTALL_EXIT -ne 0 ]] && die "Certificate install failed (exit ${INSTALL_EXIT}) – check ${LOG}"

# Log expiry from the installed flat files
PRIMARY_CERT="${CERT_DIR}/${DOMAIN}.ecc.cer"
[[ "$ISSUE_ECC" != "true" ]] && PRIMARY_CERT="${CERT_DIR}/${DOMAIN}.rsa.cer"
EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_CERT" 2>/dev/null \
         | cut -d= -f2 || echo "unknown")
DAYS_LEFT=$(python3 -c "
import sys, datetime, re
s = re.sub(r'\s+', ' ', sys.argv[1].strip())
try:
    d = datetime.datetime.strptime(s, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
    print((d - datetime.datetime.now(datetime.timezone.utc)).days)
except Exception:
    print('unknown')
" "$EXPIRY" 2>/dev/null || echo "unknown")
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
