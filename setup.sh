#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh – One-time host preparation before docker compose build
#
#   1. Verifies Docker and docker compose are available
#   2. Creates the host directory for persistent storage
#   3. Copies docker-compose.override.yml.example → docker-compose.override.yml
#      if an override file does not already exist
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[--]${NC}  $*"; }
fail() { echo -e "${RED}[!!]${NC}  $*" >&2; exit 1; }

echo "=============================================="
echo " ClearPass ACME Certificate Manager – Host Setup"
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
echo "    CPPM_CALLBACK_PORT   – PKCS12 callback port (default: 8765)"
echo "    REQUIRE_AUTH_FOR_STATUS – require login for dashboard (default: false)"
echo ""
echo "  !! Changing ports requires editing TWO sections in the override file:"
echo "     the environment section AND the ports section."
echo "     See the comments inside docker-compose.override.yml for details."
echo ""
echo "  ClearPass server credentials, domain, and DNS provider are configured"
echo "  through the web UI after the container starts — no file editing needed."
echo ""
echo "  Next steps:"
echo "    1. (Optional) nano ${SCRIPT_DIR}/docker-compose.override.yml"
echo "    2. docker compose build --no-cache"
echo "    3. docker compose up -d"
echo "    4. docker compose logs -f"
echo "    5. Open http://<docker-host>:8080/ in a browser"
echo "       – follow the Setup link to create the admin account"
echo "       – go to Servers → Add Server to register your ClearPass server"
echo "=============================================="
