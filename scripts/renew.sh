#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# renew.sh – Called by supercronic twice daily to check and renew certificates.
#            Iterates over all servers configured in servers.json.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="/data/certs"
LOG_DIR="/data/certs/.logs"
LOG="${LOG_DIR}/acme_renewal.log"

mkdir -p "$LOG_DIR" "$CERT_DIR" 2>/dev/null || true
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { local m="[$(ts)] [RENEW] $*"; echo "$m";     echo "$m" >> "$LOG" 2>/dev/null; }
err() { local m="[$(ts)] [ERROR] $*"; echo "$m" >&2; echo "$m" >> "$LOG" 2>/dev/null; }

source /opt/cppm/status.sh
unset DEBUG

log "=== Renewal Check ==="

SERVER_IDS=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import certificate_owner_ids
for sid in certificate_owner_ids():
    print(sid)
" 2>/dev/null || echo "")

if [[ -z "$SERVER_IDS" ]]; then
    log "No servers configured – nothing to renew."
    log "=== Renewal Check Complete ==="
    exit 0
fi

upload_profile_targets() {
    local profile_id="$1"
    local member_ids
    member_ids=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import certificate_members
for s in certificate_members('${profile_id}'):
    if s.get('id'):
        print(s['id'])
" 2>/dev/null || true)
    for member_id in $member_ids; do
        local member_env
        member_env=$(python3 -c "
import sys
sys.path.insert(0, '/opt/cppm')
from config_utils import get_server_shell_env
output = get_server_shell_env('${member_id}')
if output:
    print(output)
" 2>/dev/null) || true
        [[ -z "$member_env" ]] && continue
        ( eval "$member_env"; /opt/cppm/deploy_hook.sh ) 2>&1 | tee -a "$LOG" || \
            err "Upload failed for target ${member_id} – check target upload log"
    done
}

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

    CERT_DIR="${SERVER_CERT_DIR:-/data/certs}"
    LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
    LOG="${LOG_DIR}/acme_renewal.log"
    mkdir -p "$LOG_DIR"
    status_server_init

    ACME_CA_LABEL="${ACME_SERVER:-letsencrypt}"
    case "$ACME_CA_LABEL" in
        letsencrypt)      ACME_CA_LABEL="Let's Encrypt" ;;
        letsencrypt_test) ACME_CA_LABEL="Let's Encrypt (Staging)" ;;
        zerossl)          ACME_CA_LABEL="ZeroSSL" ;;
        buypass)          ACME_CA_LABEL="Buypass" ;;
        buypass_test)     ACME_CA_LABEL="Buypass (Staging)" ;;
        http*)            ACME_CA_LABEL="Custom CA (${ACME_CA_LABEL})" ;;
    esac

    log "=== Renewal Check ==="
    log "  Domain   : ${DOMAIN:-NOT SET}"
    log "  CPPM     : ${CPPM_HOST:-NOT SET}"
    log "  DNS      : ${DNS_PROVIDER:-NOT SET}"
    log "  ACME CA  : ${ACME_CA_LABEL}"
    log "  Callback : http://${CPPM_CALLBACK_HOST:-not set}:${CPPM_CALLBACK_PORT:-8765}/"

    if [[ -z "${DOMAIN:-}" ]]; then
        err "Server ${SERVER_ID}: DOMAIN is empty – skipping"
        continue
    fi

    # ── ClearPass reachability probe ────────────────────────────────────────
    # Runs on every renewal check so CPPM outages are detected independently
    # of whether a cert is due for renewal.
    CPPM_UNREACHABLE_FLAG="/tmp/cppm_unreachable_${SERVER_ID}"
    if [[ -n "${CPPM_HOST:-}" ]]; then
        CPPM_PROBE=$(python3 -c "
import socket, sys
_DNS_HINTS = ('[Errno -2]', '[Errno -3]', '[Errno 11001]',
              'Name or service not known', 'nodename nor servname',
              'getaddrinfo failed', 'Try again',
              'Temporary failure in name resolution')
try:
    s = socket.create_connection(('${CPPM_HOST}', 443), timeout=10)
    s.close()
    sys.stdout.write('ok\n')
except socket.gaierror as e:
    sys.stdout.write('dns_error: ' + str(e) + '\n')
except Exception as e:
    msg = str(e)
    if any(h in msg for h in _DNS_HINTS):
        sys.stdout.write('dns_error: ' + msg + '\n')
    else:
        sys.stdout.write('error: ' + msg + '\n')
" 2>/dev/null || echo "error: probe failed")

        if [[ "$CPPM_PROBE" == "ok" ]]; then
            if [[ -f "$CPPM_UNREACHABLE_FLAG" ]]; then
                log "  ClearPass ${CPPM_HOST} is reachable again."
                status_write "OK" "CPPM" "ClearPass ${CPPM_HOST} is reachable again"
                python3 /opt/cppm/notify.py \
                    --server-id "${SERVER_ID}" \
                    --event upload_success \
                    --message "ClearPass ${CPPM_HOST} is reachable again after being offline." \
                    2>/dev/null || true
                rm -f "$CPPM_UNREACHABLE_FLAG"
            fi
        elif [[ "$CPPM_PROBE" == dns_error:* ]]; then
            DNS_ERR="${CPPM_PROBE#dns_error: }"
            log "  WARNING: Cannot resolve ClearPass hostname '${CPPM_HOST}' (${DNS_ERR})"
            status_write "WARN" "CPPM" "DNS resolution failed for '${CPPM_HOST}': ${DNS_ERR}"
            SHOULD_NOTIFY=true
            if [[ -f "$CPPM_UNREACHABLE_FLAG" ]]; then
                LAST_NOTIFIED=$(cat "$CPPM_UNREACHABLE_FLAG" 2>/dev/null || echo 0)
                NOW=$(date +%s)
                if [[ $(( NOW - LAST_NOTIFIED )) -lt 86400 ]]; then
                    SHOULD_NOTIFY=false
                fi
            fi
            if [[ "$SHOULD_NOTIFY" == "true" ]]; then
                python3 /opt/cppm/notify.py \
                    --server-id "${SERVER_ID}" \
                    --event upload_failed \
                    --message "Cannot resolve ClearPass hostname '${CPPM_HOST}' from inside the container (${DNS_ERR}). Certificate uploads will fail until this is resolved. Fix options: (1) Use the server IP address instead of the hostname in settings, (2) Add '--dns <your-dns-server>' to your docker run command, (3) Add 'dns:' under the service in docker-compose.yml." \
                    2>/dev/null || true
                date +%s > "$CPPM_UNREACHABLE_FLAG"
            fi
        else
            log "  WARNING: ClearPass ${CPPM_HOST} is unreachable: ${CPPM_PROBE}"
            status_write "WARN" "CPPM" "ClearPass ${CPPM_HOST} unreachable: ${CPPM_PROBE}"
            # Throttle to once per 24 hours so the twice-daily cron doesn't spam
            SHOULD_NOTIFY=true
            if [[ -f "$CPPM_UNREACHABLE_FLAG" ]]; then
                LAST_NOTIFIED=$(cat "$CPPM_UNREACHABLE_FLAG" 2>/dev/null || echo 0)
                NOW=$(date +%s)
                if [[ $(( NOW - LAST_NOTIFIED )) -lt 86400 ]]; then
                    SHOULD_NOTIFY=false
                fi
            fi
            if [[ "$SHOULD_NOTIFY" == "true" ]]; then
                python3 /opt/cppm/notify.py \
                    --server-id "${SERVER_ID}" \
                    --event upload_failed \
                    --message "ClearPass ${CPPM_HOST} is unreachable on port 443. Certificate upload will fail when renewal is due. Error: ${CPPM_PROBE}" \
                    2>/dev/null || true
                date +%s > "$CPPM_UNREACHABLE_FLAG"
            fi
        fi
    fi

    ISSUE_ECC="${ISSUE_ECC:-true}"
    ISSUE_RSA="${ISSUE_RSA:-true}"

    # If flat cert files are missing, try install-only first (Lego state may already
    # exist from a previous run that crashed before install), then fall back to full
    # re-issue if install fails (no Lego state at all).
    NEEDS_ISSUE=false
    [[ "$ISSUE_ECC" == "true" && ! -f "${CERT_DIR}/${DOMAIN}.ecc.cer" ]] && NEEDS_ISSUE=true
    [[ "$ISSUE_RSA" == "true" && ! -f "${CERT_DIR}/${DOMAIN}.rsa.cer" ]] && NEEDS_ISSUE=true
    if [[ "$NEEDS_ISSUE" == "true" ]]; then
        log "Flat cert(s) missing for ${DOMAIN} – attempting install from Lego state first..."
        status_write "WARN" "RENEW" "Flat cert(s) missing for ${DOMAIN} at renewal check – attempting install"
        INSTALL_ONLY_EXIT=0
        python3 /opt/cppm/acme_cli.py install 2>&1 | tee -a "$LOG" 2>/dev/null || INSTALL_ONLY_EXIT=$?
        if [[ $INSTALL_ONLY_EXIT -eq 0 ]]; then
            log "Install-only succeeded for ${DOMAIN} – triggering upload..."
            upload_profile_targets "${CERTIFICATE_ID}"
        else
            log "Install-only failed for ${DOMAIN} – falling back to full issuance..."
            status_write "WARN" "RENEW" "Lego state missing for ${DOMAIN} – re-running full issuance"
            SKIP_UPLOAD=true /opt/cppm/issue_cert.sh 2>&1 | tee -a "$LOG" 2>/dev/null || \
                err "issue_cert.sh failed for ${DOMAIN} – check acme_renewal.log"
            upload_profile_targets "${CERTIFICATE_ID}"
        fi
        continue
    fi

    # Log current expiry
    PRIMARY_FLAT="${CERT_DIR}/${DOMAIN}.ecc.cer"
    [[ "$ISSUE_ECC" != "true" ]] && PRIMARY_FLAT="${CERT_DIR}/${DOMAIN}.rsa.cer"
    EXPIRY=$(openssl x509 -enddate -noout -in "$PRIMARY_FLAT" 2>/dev/null \
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
    log "Current cert for ${DOMAIN} expires: $EXPIRY ($DAYS_LEFT days remaining)"

    RENEW_EXIT=0
    python3 /opt/cppm/acme_cli.py renew 2>&1 | tee -a "$LOG" 2>/dev/null || RENEW_EXIT=$?

    case $RENEW_EXIT in
        0)
            log "Certificate(s) renewed for ${DOMAIN}."
            status_write "OK" "RENEW" "Certificate renewed for ${DOMAIN} – running install and upload"
            SKIP_UPLOAD=true /opt/cppm/install_cert.sh 2>&1 | tee -a "$LOG" 2>/dev/null || \
                err "install_cert.sh failed for ${DOMAIN}"
            upload_profile_targets "${CERTIFICATE_ID}"
            ;;
        2)
            log "Certificate for ${DOMAIN} not due for renewal."
            status_write "INFO" "RENEW" "Not due for renewal – ${DOMAIN} has ${DAYS_LEFT} days remaining (next check in 12h)"
            ;;
        *)
            err "lego renew exited ${RENEW_EXIT} for ${DOMAIN} – check acme_renewal.log"
            status_write "FAILED" "RENEW" "lego renew failed for ${DOMAIN} – check acme_renewal.log"
            ;;
    esac
done

log "=== Renewal Check Complete ==="
