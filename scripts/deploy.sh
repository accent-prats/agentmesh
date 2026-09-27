#!/usr/bin/env bash
# deploy.sh — first-time and incremental deployment for the AgentMesh platform.
#
# Usage:
#   ./scripts/deploy.sh          # Full build + deploy (first-time or update)
#   ./scripts/deploy.sh --update # Re-deploy without rebuilding unchanged images

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[deploy]${NC} $*"; }
error() { echo -e "${RED}[deploy]${NC} $*" >&2; exit 1; }

UPDATE_ONLY="${1:-}"

# ── 1. Pre-flight checks ──────────────────────────────────────────────────────
info "Checking prerequisites..."
command -v docker      >/dev/null 2>&1 || error "docker not found"
command -v docker-compose >/dev/null 2>&1 || COMPOSE_CMD="docker compose" || true
COMPOSE_CMD="${COMPOSE_CMD:-docker-compose}"

# ── 2. Environment file ───────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    warn ".env not found — copying from .env.example. Edit it before production use."
    cp .env.example .env
  else
    error ".env not found and no .env.example to copy from. Create .env first."
  fi
fi

# Warn if secrets still have placeholder values
if grep -q "change-me-in-production" .env; then
  warn "SECRET_KEY in .env is still the placeholder value — change it before production!"
fi
if grep -q "your_anthropic_key" .env 2>/dev/null || ! grep -q "ANTHROPIC_API_KEY=sk-" .env 2>/dev/null; then
  warn "ANTHROPIC_API_KEY may not be set — AI generation will fail without it."
fi

# ── 3. TLS certificates ───────────────────────────────────────────────────────
CERTS_DIR="infrastructure/nginx/certs"
if [[ ! -f "${CERTS_DIR}/portal.local.crt" ]]; then
  info "Generating self-signed TLS certificates..."
  if [[ -f "infrastructure/nginx/generate-certs.sh" ]]; then
    bash infrastructure/nginx/generate-certs.sh
  else
    warn "generate-certs.sh not found — skipping cert generation. HTTPS will not work."
  fi
else
  info "TLS certificates already present — skipping generation."
fi

# ── 4. Build images ───────────────────────────────────────────────────────────
if [[ "${UPDATE_ONLY}" != "--update" ]]; then
  info "Building Docker images (this may take a few minutes on first run)..."
  ${COMPOSE_CMD} build --parallel
else
  info "--update flag set, skipping full rebuild."
fi

# ── 5. Start infrastructure services first ───────────────────────────────────
info "Starting infrastructure services (postgres, mongo, growthbook)..."
${COMPOSE_CMD} up -d postgres mongo growthbook

info "Waiting for postgres to be healthy..."
for i in $(seq 1 30); do
  if ${COMPOSE_CMD} exec -T postgres pg_isready -U "${DB_USER:-portal}" >/dev/null 2>&1; then
    info "Postgres is ready."
    break
  fi
  if [[ $i -eq 30 ]]; then
    error "Postgres did not become healthy in time."
  fi
  sleep 2
done

# ── 6. Start Portal (creates its own schema + seeds the first admin) ────────
info "Starting portal-api (runs Portal's DB bootstrap)..."
${COMPOSE_CMD} up -d portal-api

# ── 7. Bring up the rest ──────────────────────────────────────────────────────
info "Starting all remaining services..."
${COMPOSE_CMD} up -d

# ── 8. Health summary ─────────────────────────────────────────────────────────
info "Waiting 20s for all services to settle..."
sleep 20

info "Service status:"
${COMPOSE_CMD} ps

echo ""
info "Deployment complete. Access the platform at:"
echo "  Portal: https://portal.local  (or http://portal.local)"
echo ""
warn "Add this entry to /etc/hosts (or C:\\Windows\\System32\\drivers\\etc\\hosts) if not already present:"
echo "  127.0.0.1  portal.local"
echo ""
info "To stream all logs: ${COMPOSE_CMD} logs -f"
info "To stop:            ${COMPOSE_CMD} down"
info "To stop + wipe DB:  ${COMPOSE_CMD} down -v  (WARNING: destroys all data)"
