#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh – One-time host preparation before docker compose build
#
# All acme.sh and Let's Encrypt CA downloads now happen inside the Docker
# build itself, so this script only needs to:
#   1. Create the host directory for persistent cert storage
#   2. Confirm Docker and docker compose are available
#   3. Remind you to fill in .env
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[--]${NC}  $*"; }
fail() { echo -e "${RED}[!!]${NC}  $*" >&2; exit 1; }

echo "=============================================="
echo " ClearPass Cert Manager – Host Setup"
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

# ── Check .env ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
    info "Copying .env.example -> .env"
    cp "${SCRIPT_DIR}/.env.example" "${SCRIPT_DIR}/.env"
    echo ""
    echo -e "${YELLOW}  ACTION REQUIRED: fill in your credentials in .env before building:${NC}"
    echo "    nano ${SCRIPT_DIR}/.env"
else
    ok ".env already exists."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
ok "Host setup complete."
echo ""
echo "  Next steps:"
echo "    1. Fill in ${SCRIPT_DIR}/.env  (if not already done)"
echo "    2. docker compose build --no-cache"
echo "    3. docker compose up -d"
echo "    4. docker compose logs -f"
echo "=============================================="
