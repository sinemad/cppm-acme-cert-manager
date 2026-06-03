#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# issue_cert.sh – Issue ECC and/or RSA certificates via DNS-01 challenge
#
# Certificate types are controlled by ISSUE_ECC and ISSUE_RSA (default: both).
# ECC (ec-256) → CPPM HTTPS(ECC) service slot
# RSA (2048)   → CPPM RADIUS service slot
#
# DNS provider is selected via DNS_PROVIDER in .env. Supported providers:
#
#   cloudflare   (default) – dns_cf
#     CF_Token + CF_Account_ID + CF_Zone_ID   (scoped API token – preferred)
#     CF_Key + CF_Email                        (global API key – fallback)
#
#   porkbun – dns_porkbun
#     PORKBUN_API_KEY + PORKBUN_SECRET_API_KEY
#
#   route53 – dns_aws
#     AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
#     AWS_DEFAULT_REGION  (optional, defaults to us-east-1)
#
#   digitalocean – dns_dgon
#     DO_API_KEY
#
#   godaddy – dns_gd
#     GD_Key + GD_Secret
#
# Any other acme.sh dnsapi plugin can be used by setting:
#   DNS_PROVIDER=<plugin_name>   (without the dns_ prefix)
# and ensuring the required credential variables are present in .env.
#
# acme.sh stores ECC certs in:  $CERT_DIR/<domain>_ecc/
# acme.sh stores RSA certs in:  $CERT_DIR/<domain>/
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACME_BIN="/usr/local/bin/acme.sh"
CERT_DIR="/data/certs"
# Use per-server directory when available (set by get_server_shell_env)
CERT_DIR="${SERVER_CERT_DIR:-$CERT_DIR}"
LOG_DIR="${SERVER_LOG_DIR:-${CERT_DIR}/.logs}"
LOG="${LOG_DIR}/renewal.log"
DOMAIN="${DOMAIN:-}"
DNS_PROVIDER="${DNS_PROVIDER:-cloudflare}"

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
log "Domain:   $DOMAIN"
log "Provider: $DNS_PROVIDER"
log "Server:   ${ACME_SERVER:-letsencrypt}"
log "Types:    ${CERT_LABEL}"
status_write "INFO" "CERT" "Starting issuance (${CERT_LABEL}) – domain=${DOMAIN} provider=${DNS_PROVIDER} server=${ACME_SERVER:-letsencrypt}"

# ── Resolve acme.sh DNS plugin and validate required credentials ───────────
case "${DNS_PROVIDER,,}" in
    cloudflare|cf)
        DNS_PLUGIN="dns_cf"
        if [[ -n "${CF_Token:-}" ]]; then
            log "Cloudflare: using scoped API token (CF_Token)"
        elif [[ -n "${CF_Key:-}" && -n "${CF_Email:-}" ]]; then
            log "Cloudflare: using global API key (CF_Key + CF_Email)"
        else
            die "Cloudflare credentials missing. Set CF_Token (preferred) or CF_Key + CF_Email."
        fi
        ;;

    porkbun)
        DNS_PLUGIN="dns_porkbun"
        [[ -z "${PORKBUN_API_KEY:-}" ]]        && die "PORKBUN_API_KEY is not set."
        [[ -z "${PORKBUN_SECRET_API_KEY:-}" ]] && die "PORKBUN_SECRET_API_KEY is not set."
        log "Porkbun: using API key"
        ;;

    route53|aws|r53)
        DNS_PLUGIN="dns_aws"
        [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]     && die "AWS_ACCESS_KEY_ID is not set."
        [[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]] && die "AWS_SECRET_ACCESS_KEY is not set."
        log "Route53: using IAM key ${AWS_ACCESS_KEY_ID:0:8}..."
        ;;

    digitalocean|do)
        DNS_PLUGIN="dns_dgon"
        [[ -z "${DO_API_KEY:-}" ]] && die "DO_API_KEY is not set."
        log "DigitalOcean: using API key"
        ;;

    godaddy|gd)
        DNS_PLUGIN="dns_gd"
        [[ -z "${GD_Key:-}" ]]    && die "GD_Key is not set."
        [[ -z "${GD_Secret:-}" ]] && die "GD_Secret is not set."
        log "GoDaddy: using API key"
        ;;

    *)
        # Passthrough: treat DNS_PROVIDER as the bare plugin name (without dns_ prefix)
        DNS_PLUGIN="dns_${DNS_PROVIDER,,}"
        log "Custom provider: using plugin '${DNS_PLUGIN}' – ensure credentials are set."
        ;;
esac

COMMON_ARGS=(
    --issue
    --dns "$DNS_PLUGIN"
    --domain    "$DOMAIN"
    --server    "${ACME_SERVER:-letsencrypt}"
    --cert-home "$CERT_DIR"
    --home      /root/.acme.sh
    --log       "$LOG"
    --log-level 2
)
[[ "${FORCE_RENEW:-false}" == "true" ]] && COMMON_ARGS+=(--force)

# ── Issue ECC cert ─────────────────────────────────────────────────────────
NEWLY_ISSUED=false

if [[ "$ISSUE_ECC" == "true" ]]; then
    log "--- Issuing ECC (ec-256) certificate ---"
    ECC_EXIT=0
    "$ACME_BIN" "${COMMON_ARGS[@]}" --keylength ec-256 || ECC_EXIT=$?
    case $ECC_EXIT in
        0) log "ECC certificate issued successfully."; NEWLY_ISSUED=true ;;
        2) log "ECC cert exists in acme.sh state – not due for renewal." ;;
        *) die "acme.sh --issue (ECC) failed with exit code $ECC_EXIT – check ${LOG}" ;;
    esac
else
    log "--- Skipping ECC (ISSUE_ECC=false) ---"
fi

# ── Issue RSA cert ─────────────────────────────────────────────────────────
if [[ "$ISSUE_RSA" == "true" ]]; then
    log "--- Issuing RSA (2048) certificate ---"
    RSA_EXIT=0
    "$ACME_BIN" "${COMMON_ARGS[@]}" --keylength 2048 || RSA_EXIT=$?
    case $RSA_EXIT in
        0) log "RSA certificate issued successfully."; NEWLY_ISSUED=true ;;
        2) log "RSA cert exists in acme.sh state – not due for renewal." ;;
        *) die "acme.sh --issue (RSA) failed with exit code $RSA_EXIT – check ${LOG}" ;;
    esac
else
    log "--- Skipping RSA (ISSUE_RSA=false) ---"
fi

if [[ "$NEWLY_ISSUED" == "true" ]]; then
    status_write "OK" "CERT" "New ${CERT_LABEL} certificate(s) issued via ${DNS_PROVIDER} DNS-01"
else
    status_write "INFO" "CERT" "${CERT_LABEL} cert(s) exist in acme.sh state – running install only"
fi

/opt/cppm/install_cert.sh
