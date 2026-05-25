# AI-Augmented Web Vulnerability Assessment Platform

Local dev quickstart:

Docker dev (full stack):

1) Build and run
   - docker compose up --build

2) (Optional) Pull a local model
   - docker compose exec ollama ollama pull llama3
   - docker compose exec ollama ollama pull nomic-embed-text

Production-like stack:

1) Build and run
   - docker compose -f docker-compose.prod.yml up --build

1) Start dependencies
   - docker compose up -d db redis ollama

2) Backend
   - cd be
   - python -m venv .venv
   - source .venv/bin/activate
   - pip install -r requirements.txt
   - cp .env.example .env
   - uvicorn app.main:app --reload --port 8000

2b) Worker
   - cd be
   - source .venv/bin/activate
   - celery -A app.core.celery_app worker --loglevel=info

3) Frontend
   - cd web
   - npm install
   - cp .env.local.example .env.local
   - npm run dev

API health check: http://localhost:8000/api/v1/health
Web app: http://localhost:3000
API docs: http://localhost:8000/api/v1/docs
Metrics: http://localhost:8000/metrics (Prometheus on http://localhost:9090)

Default users:
- admin / admin123 (admin)
- analyst / analyst123 (analyst)
- viewer / viewer123 (viewer)

Seed demo data:
- curl -X POST http://localhost:8000/api/v1/demo/seed \
   -H "Authorization: Bearer <TOKEN>"
