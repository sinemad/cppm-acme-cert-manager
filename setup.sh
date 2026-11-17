#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh – One-time host preparation before docker compose build
#
#   1. Verifies Docker and docker compose are available
#   2. Creates the host directory for persistent storage
#   3. Copies docker-compose.override.yml.example → docker-compose.override.yml
#      if an override file does not already exist
#   4. Optionally sets the container timezone and prints next steps for the
#      deployment targets you plan to use (ClearPass, Linux SSH, or both)
#
# Usage:  ./setup.sh [--targets clearpass|linux_ssh|both] [--tz Area/City]
#   Without flags the script asks (when run in a terminal). Without a terminal
#   it never prompts: defaults are targets=both and the template's timezone.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[--]${NC}  $*"; }
fail() { echo -e "${RED}[!!]${NC}  $*" >&2; exit 1; }

TARGETS=""; TZ_CHOICE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets) [[ $# -ge 2 ]] || fail "--targets needs a value"; TARGETS="$2"; shift 2 ;;
        --tz)      [[ $# -ge 2 ]] || fail "--tz needs a value";      TZ_CHOICE="$2"; shift 2 ;;
        -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) fail "Unknown option: $1 (try --help)" ;;
    esac
done
case "$TARGETS" in ""|clearpass|linux_ssh|both) ;; *) fail "--targets must be clearpass, linux_ssh or both" ;; esac

echo "=============================================="
echo " ACME Certificate Manager – Host Setup"
echo "=============================================="
echo ""

# ── Check Docker ──────────────────────────────────────────────────────────────
command -v docker &>/dev/null \
    && ok "Docker found: $(docker --version)" \
    || fail "Docker not found. Install Docker Engine first."

docker compose version &>/dev/null \
    && ok "Compose found: $(docker compose version)" \
    || fail "docker compose plugin not found. Install the Compose v2 plugin."

# ── Create persistent cert directory ─────────────────────────────────────────
CERT_DIR="/opt/cppm-certs"
if [[ -d "$CERT_DIR" ]]; then
    ok "Cert directory already exists: $CERT_DIR"
else
    info "Creating persistent cert directory: $CERT_DIR"
    sudo mkdir -p "$CERT_DIR"
    sudo chmod 750 "$CERT_DIR"
    ok "Created $CERT_DIR"
fi

# ── Create override file from template if needed ──────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERRIDE="${SCRIPT_DIR}/docker-compose.override.yml"
TEMPLATE="${SCRIPT_DIR}/docker-compose.override.yml.example"

if [[ ! -f "$OVERRIDE" ]]; then
    if [[ -f "$TEMPLATE" ]]; then
        cp "$TEMPLATE" "$OVERRIDE"
        ok "docker-compose.override.yml created from template"
    else
        fail "docker-compose.override.yml.example not found in ${SCRIPT_DIR} – re-clone the repository."
    fi
else
    ok "docker-compose.override.yml already exists."
fi

# ── Choose deployment targets / timezone ──────────────────────────────────────
if [[ -t 0 ]]; then
    if [[ -z "$TARGETS" ]]; then
        echo ""
        echo "What will you deploy certificates to?"
        echo "  1) ClearPass Policy Manager"
        echo "  2) Linux servers over SSH (e.g. Frigate)"
        echo "  3) Both"
        read -r -p "Choice [3]: " _choice
        case "${_choice:-3}" in 1) TARGETS=clearpass ;; 2) TARGETS=linux_ssh ;; *) TARGETS=both ;; esac
    fi
    if [[ -z "$TZ_CHOICE" ]]; then
        read -r -p "Container timezone (e.g. America/Chicago, blank keeps the template value): " TZ_CHOICE
    fi
fi
TARGETS="${TARGETS:-both}"

if [[ -n "$TZ_CHOICE" ]]; then
    [[ "$TZ_CHOICE" =~ ^[A-Za-z0-9_+/-]+$ ]] || fail "Invalid timezone: $TZ_CHOICE"
    if grep -qE '^      TZ: ' "$OVERRIDE"; then
        sed -i.bak -E "s#^      TZ: .*#      TZ: ${TZ_CHOICE}#" "$OVERRIDE" && rm -f "${OVERRIDE}.bak"
        ok "Timezone set to ${TZ_CHOICE} in docker-compose.override.yml"
    else
        info "No active TZ line in docker-compose.override.yml – set it manually."
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
ok "Host setup complete."
echo ""
echo "  Optional: edit docker-compose.override.yml to customise your deployment."
echo "  The defaults in docker-compose.yml work for most installations as-is."
echo ""
echo "  Common overrides (all optional):"
echo "    TZ                   – container timezone (default: UTC)"
echo "    STATUS_PORT          – web UI port (default: 8080)"
echo "    CPPM_CALLBACK_PORT   – PKCS12 callback port (default: 8765; ClearPass only)"
echo "    REQUIRE_AUTH_FOR_STATUS – require login for dashboard (default: false)"
echo ""
echo "  !! Changing ports requires editing TWO sections in the override file:"
echo "     the environment section AND the ports section."
echo "     See the comments inside docker-compose.override.yml for details."
echo ""
echo "  Servers, DNS provider credentials, domain and ACME settings are configured"
echo "  through the web UI after the container starts — no file editing needed."
echo ""
echo "  Next steps:"
echo "    1. (Optional) nano ${SCRIPT_DIR}/docker-compose.override.yml"
echo "    2. docker compose build --no-cache"
echo "    3. docker compose up -d"
echo "    4. docker compose logs -f"
echo "    5. Open http://<docker-host>:8080/ in a browser"
echo "       – follow the Setup link to create the admin account"
echo "       – pick your deployment target on the dashboard to add your first server"
if [[ "$TARGETS" == "clearpass" || "$TARGETS" == "both" ]]; then
echo ""
echo "  For ClearPass (docs/01-initial-setup.md, 'Deploying to ClearPass'):"
echo "    – create an API client in CPPM (Administration → API Services → API Clients,"
echo "      grant type client_credentials) before adding the server"
echo "    – the PKCS12 callback port (default 8765) must be reachable from ClearPass"
fi
if [[ "$TARGETS" == "linux_ssh" || "$TARGETS" == "both" ]]; then
echo ""
echo "  For Linux servers (docs/10-linux-ssh-target.md):"
echo "    – create a dedicated SSH user and key for this tool on each target"
echo "    – make sure that user can write the certificate directory and run your reload command"
fi
echo "=============================================="
