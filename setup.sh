#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh – One-time host preparation before docker compose build
#
#   1. Verifies Docker and docker compose are available
#   2. Creates the host directory for persistent storage
#   3. Copies env-example → .env if .env does not already exist
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

# ── Create .env from env-example if needed ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
    if [[ -f "${SCRIPT_DIR}/env-example" ]]; then
        cp "${SCRIPT_DIR}/env-example" "${SCRIPT_DIR}/.env"
        chmod 600 "${SCRIPT_DIR}/.env"
        ok ".env created from env-example"
    else
        fail "env-example not found in ${SCRIPT_DIR} – re-clone the repository."
    fi
else
    ok ".env already exists."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
ok "Host setup complete."
echo ""
echo "  Minimum required before building:"
echo "    Review ${SCRIPT_DIR}/.env and set:"
echo "      TZ                  – container timezone (default: UTC)"
echo "      CPPM_CALLBACK_HOST  – Docker host LAN IP that ClearPass can reach"
echo "      CPPM_CALLBACK_PORT  – callback port (default: 8765)"
echo "      STATUS_PORT         – web UI port (default: 8080)"
echo ""
echo "  ClearPass server credentials and DNS provider configuration"
echo "  are set up through the web UI after the container starts."
echo ""
echo "  Next steps:"
echo "    1. nano ${SCRIPT_DIR}/.env"
echo "    2. docker compose build --no-cache"
echo "    3. docker compose up -d"
echo "    4. docker compose logs -f"
echo "    5. Open http://<docker-host>:\${STATUS_PORT:-8080}/ in a browser"
echo "       – follow the Setup link to create the admin account"
echo "       – go to Servers → Add Server to register your ClearPass server"
echo "=============================================="
