# AI-Augmented Web Vulnerability Assessment Platform

---

## Khởi động nhanh — 1 lệnh duy nhất

```bash
./start.sh
```

Script tự động làm toàn bộ:
1. Kiểm tra Docker đang chạy
2. Kiểm tra các port cần thiết
3. Build Docker images (backend + frontend)
4. Start infrastructure (PostgreSQL, Redis, Ollama, ZAP)
5. Chạy Alembic migrations tự động
6. Pull Ollama models nếu chưa có (`llama3`, `nomic-embed-text`)
7. Start API, Celery worker, Next.js, Prometheus
8. Chờ tất cả healthy rồi in URL

---

## Options

| Lệnh | Mô tả |
|------|-------|
| `./start.sh` | Full start (build + pull models + run) |
| `./start.sh --no-build` | Start không build lại image |
| `./start.sh --logs` | Start rồi tail logs real-time |
| `./start.sh --down` | Dừng tất cả services |
| `./start.sh --reset` | Dừng + xoá toàn bộ data + start lại sạch |

---

## URLs sau khi khởi động

| Service | URL |
|---------|-----|
| UI Dashboard | http://localhost:3000 |
| API (FastAPI) | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/api/v1/docs |
| ZAP Scanner | http://localhost:8080 |
| Ollama LLM | http://localhost:11434 |
| Prometheus | http://localhost:9090 |

---

## Default credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | admin |
| analyst | analyst123 | analyst |
| viewer | viewer123 | viewer |

---

## Các lệnh hữu ích

```bash
# Xem logs của API và worker
docker compose logs -f api worker

# Xem logs của 1 service cụ thể
docker compose logs -f api

# Restart 1 service không ảnh hưởng service khác
docker compose restart api

# Chạy migration thủ công
docker compose exec api alembic upgrade head

# Pull model Ollama thêm
docker compose exec ollama ollama pull llama3:70b

# Seed demo data
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin&password=admin123" | jq -r .access_token)
curl -s -X POST http://localhost:8000/api/v1/demo/seed \
  -H "Authorization: Bearer $TOKEN"

# Dừng tất cả
./start.sh --down

# Reset hoàn toàn (xoá DB + model cache)
./start.sh --reset
```

---

## Yêu cầu hệ thống

- Docker Desktop >= 4.x
- RAM >= 8GB (Ollama cần ít nhất 4GB cho llama3)
- Disk >= 10GB (models + images)
- macOS / Linux / Windows (WSL2)

---

## Production stack

```bash
docker compose -f docker-compose.prod.yml up --build
```
