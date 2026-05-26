#!/usr/bin/env bash
# =============================================================================
#  ATTT — One-command startup script
#  Usage:
#    ./start.sh            → full stack (build + pull models + start)
#    ./start.sh --no-build → skip docker build (dùng image có sẵn)
#    ./start.sh --down     → dừng và xoá toàn bộ containers
#    ./start.sh --reset    → down + xoá volumes + start lại sạch
#    ./start.sh --logs     → xem logs real-time sau khi start
# =============================================================================

set -euo pipefail

# ── Bật BuildKit — cache pip/apt giữa các lần build ──────────────────────────
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
header()  { echo -e "\n${BOLD}${BLUE}══ $* ══${NC}"; }

# ── Parse flags ──────────────────────────────────────────────────────────────
BUILD=true
SHOW_LOGS=false
DO_DOWN=false
DO_RESET=false

for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=false ;;
    --logs)     SHOW_LOGS=true ;;
    --down)     DO_DOWN=true ;;
    --reset)    DO_RESET=true ;;
    --help|-h)
      echo "Usage: $0 [--no-build] [--logs] [--down] [--reset]"
      exit 0 ;;
    *) error "Unknown flag: $arg"; exit 1 ;;
  esac
done

# ── Go to project root ────────────────────────────────────────────────────────
cd "$(dirname "$0")"

# ── Preflight checks ─────────────────────────────────────────────────────────
header "Preflight"

if ! command -v docker &>/dev/null; then
  error "Docker not found. Install Docker Desktop: https://docs.docker.com/get-docker/"
  exit 1
fi
success "Docker found: $(docker --version | cut -d' ' -f3 | tr -d ',')"

# ── Wait for Docker daemon (auto-start Docker Desktop on macOS) ───────────────
_docker_daemon_ready() {
  # Dùng --format để buộc connect tới server thực sự (không chỉ client info)
  docker info --format '{{.ServerVersion}}' &>/dev/null 2>&1
}

if ! _docker_daemon_ready; then
  warn "Docker daemon chưa sẵn sàng. Đang thử khởi động..."

  OS="$(uname)"

  if [[ "$OS" == "Darwin" ]]; then
    # Tìm Docker.app ở cả /Applications lẫn ~/Applications
    DOCKER_APP=""
    for p in "/Applications/Docker.app" "$HOME/Applications/Docker.app"; do
      if [ -d "$p" ]; then DOCKER_APP="$p"; break; fi
    done

    if [ -n "$DOCKER_APP" ]; then
      info "Đang mở Docker Desktop từ $DOCKER_APP ..."
      open -a "$DOCKER_APP"
      info "Chờ Docker daemon khởi động (tối đa 90s)..."
    else
      echo ""
      error "Không tìm thấy Docker Desktop tại /Applications hoặc ~/Applications."
      error "Tải tại: https://docs.docker.com/desktop/install/mac-install/"
      exit 1
    fi

  elif [[ "$OS" == "Linux" ]]; then
    warn "Trên Linux: thử khởi động Docker service..."
    if command -v systemctl &>/dev/null; then
      sudo systemctl start docker 2>/dev/null || true
    fi
  fi

  # Poll tối đa 90 giây
  MAX_WAIT=90
  WAITED=0
  until _docker_daemon_ready; do
    if [ $WAITED -ge $MAX_WAIT ]; then
      echo ""
      error "Docker daemon không sẵn sàng sau ${MAX_WAIT}s."
      echo ""
      echo -e "  ${YELLOW}Hướng dẫn sửa:${NC}"
      echo -e "  1. Mở Docker Desktop từ Launchpad / Applications"
      echo -e "  2. Chờ icon whale 🐳 trên menu bar ổn định (không còn loading)"
      echo -e "  3. Chạy lại: ${BOLD}./start.sh${NC}"
      echo ""
      echo -e "  ${YELLOW}Chi tiết lỗi Docker:${NC}"
      docker info 2>&1 | grep -E "Cannot|Error|error" | head -3 || true
      exit 1
    fi
    echo -n "."
    sleep 2
    WAITED=$((WAITED + 2))
  done
  echo ""
  success "Docker daemon sẵn sàng (${WAITED}s)"
else
  success "Docker daemon running"
fi

if ! docker compose version &>/dev/null; then
  error "docker compose plugin not found. Update Docker Desktop."
  exit 1
fi
success "Docker Compose found: $(docker compose version --short)"

# ── --down ────────────────────────────────────────────────────────────────────
if $DO_DOWN; then
  header "Stopping all services"
  docker compose down --remove-orphans
  success "All services stopped"
  exit 0
fi

# ── --reset ───────────────────────────────────────────────────────────────────
if $DO_RESET; then
  header "Resetting everything (containers + volumes)"
  warn "This will DELETE all database data and model cache!"
  read -rp "  Are you sure? (yes/N): " confirm
  if [[ "$confirm" != "yes" ]]; then
    info "Reset cancelled."
    exit 0
  fi
  docker compose down --volumes --remove-orphans
  success "Volumes removed"
  BUILD=true
fi

# ── Check ports ───────────────────────────────────────────────────────────────
header "Port availability"

check_port() {
  local port=$1 name=$2
  if lsof -i ":$port" -sTCP:LISTEN -t &>/dev/null 2>&1; then
    warn "Port $port ($name) is already in use — service may conflict"
  else
    success "Port $port ($name) is free"
  fi
}

check_port 3000  "Next.js UI"
check_port 8000  "FastAPI"
check_port 8080  "ZAP"
check_port 11434 "Ollama"
check_port 6379  "Redis"
check_port 5432  "PostgreSQL"
check_port 9090  "Prometheus"

# ── Build ─────────────────────────────────────────────────────────────────────
if $BUILD; then
  header "Building Docker images"
  info "Lần đầu build: ~3-5 phút (apt + pip + Nikto clone)"
  info "Lần sau (có cache): ~10-30 giây"
  info ""
  # --progress=plain hiện từng bước rõ ràng thay vì spinner câm lặng
  docker compose build --parallel --progress=plain 2>&1 \
    | grep -E "^(#[0-9]|CACHED|=>| => |Step|Successfully)" \
    | sed 's/^#[0-9]* //' \
    || docker compose build --parallel   # fallback nếu grep làm exit sớm
  success "Images built"
else
  info "Skipping build (--no-build)"
fi

# ── Start infrastructure services first ──────────────────────────────────────
header "Starting infrastructure"
info "Starting db, redis, ollama, zap..."
docker compose up -d db redis ollama zap

# ── Wait for DB ───────────────────────────────────────────────────────────────
header "Waiting for PostgreSQL"
MAX_WAIT=60
WAITED=0
until docker compose exec -T db pg_isready -U user -d secdb &>/dev/null 2>&1; do
  if [ $WAITED -ge $MAX_WAIT ]; then
    error "PostgreSQL did not become ready after ${MAX_WAIT}s"
    docker compose logs db | tail -20
    exit 1
  fi
  echo -n "."
  sleep 2
  WAITED=$((WAITED + 2))
done
echo ""
success "PostgreSQL ready (${WAITED}s)"

# ── Wait for Redis ────────────────────────────────────────────────────────────
header "Waiting for Redis"
MAX_WAIT=30
WAITED=0
until docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
  if [ $WAITED -ge $MAX_WAIT ]; then
    error "Redis did not become ready after ${MAX_WAIT}s"
    exit 1
  fi
  echo -n "."
  sleep 1
  WAITED=$((WAITED + 1))
done
echo ""
success "Redis ready (${WAITED}s)"

# ── Pull Ollama models (only if not already present) ─────────────────────────
header "Ollama models"

pull_model_if_missing() {
  local model=$1
  info "Checking model: $model"
  if docker compose exec -T ollama ollama list 2>/dev/null | grep -q "^${model}"; then
    success "  $model already present"
  else
    info "  Pulling $model (this may take a few minutes on first run)..."
    docker compose exec -T ollama ollama pull "$model"
    success "  $model pulled"
  fi
}

# Wait for Ollama API to be ready
MAX_WAIT=30
WAITED=0
until docker compose exec -T ollama ollama list &>/dev/null 2>&1; do
  if [ $WAITED -ge $MAX_WAIT ]; then
    warn "Ollama not ready after ${MAX_WAIT}s — skipping model pull, will retry on demand"
    break
  fi
  echo -n "."
  sleep 2
  WAITED=$((WAITED + 2))
done
echo ""

if docker compose exec -T ollama ollama list &>/dev/null 2>&1; then
  pull_model_if_missing "llama3"
  pull_model_if_missing "nomic-embed-text"
else
  warn "Ollama not available yet. Pull models manually after startup:"
  warn "  docker compose exec ollama ollama pull llama3"
  warn "  docker compose exec ollama ollama pull nomic-embed-text"
fi

# ── Start application services ────────────────────────────────────────────────
header "Starting application services"
info "Starting api, worker, web, prometheus..."
docker compose up -d api worker web prometheus

# ── Wait for API ──────────────────────────────────────────────────────────────
header "Waiting for API"
MAX_WAIT=90
WAITED=0
until curl -sf http://localhost:8000/api/v1/health &>/dev/null; do
  if [ $WAITED -ge $MAX_WAIT ]; then
    error "API did not become healthy after ${MAX_WAIT}s"
    echo ""
    error "API logs:"
    docker compose logs --tail=30 api
    exit 1
  fi
  echo -n "."
  sleep 3
  WAITED=$((WAITED + 3))
done
echo ""
success "API healthy (${WAITED}s)"

# ── Wait for Web ──────────────────────────────────────────────────────────────
header "Waiting for Next.js"
MAX_WAIT=60
WAITED=0
until curl -sf http://localhost:3000 &>/dev/null; do
  if [ $WAITED -ge $MAX_WAIT ]; then
    warn "Next.js not ready after ${MAX_WAIT}s — may still be compiling"
    break
  fi
  echo -n "."
  sleep 3
  WAITED=$((WAITED + 3))
done
echo ""
if curl -sf http://localhost:3000 &>/dev/null; then
  success "Next.js ready (${WAITED}s)"
fi

# ── Status summary ────────────────────────────────────────────────────────────
header "Service Status"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ── Access URLs ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ATTT is running!${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}UI Dashboard${NC}        →  http://localhost:3000"
echo -e "  ${BOLD}API (FastAPI)${NC}       →  http://localhost:8000"
echo -e "  ${BOLD}API Docs (Swagger)${NC}  →  http://localhost:8000/api/v1/docs"
echo -e "  ${BOLD}ZAP Scanner${NC}         →  http://localhost:8080"
echo -e "  ${BOLD}Ollama LLM${NC}          →  http://localhost:11434"
echo -e "  ${BOLD}Prometheus${NC}          →  http://localhost:9090"
echo ""
echo -e "  ${BOLD}Default credentials:${NC}"
echo -e "    admin   / admin123"
echo -e "    analyst / analyst123"
echo -e "    viewer  / viewer123"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "    ./start.sh --logs     → tail logs từ tất cả services"
echo -e "    ./start.sh --down     → dừng tất cả services"
echo -e "    ./start.sh --reset    → reset hoàn toàn (xoá DB + models)"
echo -e "    docker compose logs -f api worker  → xem logs API + worker"
echo ""

# ── Tail logs if requested ────────────────────────────────────────────────────
if $SHOW_LOGS; then
  header "Live logs (Ctrl+C to stop)"
  docker compose logs -f api worker
fi
