# ATTT — Production Roadmap & System Status

> Last updated: 2026-05-27

---

## Hệ thống đã làm được gì (What's Already Done)

### Phase 1 — Core Infrastructure ✅

| Component | File(s) | Trạng thái |
|-----------|---------|------------|
| FastAPI backend với OpenAPI docs | `be/app/main.py` | ✅ Done |
| JWT authentication + RBAC (3 roles) | `be/app/core/security.py` | ✅ Done |
| PostgreSQL + pgvector schema | `be/app/db/models/` | ✅ Done |
| Celery + Redis task queue (5 queues) | `be/app/core/celery_app.py` | ✅ Done |
| OWASP ZAP integration (spider + active scan + auth) | `be/app/services/scanners/zap.py` | ✅ Done |
| Nikto integration | `be/app/services/scanners/nikto.py` | ✅ Done |
| Scan lifecycle (queue → run → cancel → complete) | `be/app/tasks/scan_tasks.py` | ✅ Done |
| WebSocket real-time scan status | `be/app/api/v1/routers/scans.py` | ✅ Done (Redis Pub/Sub) |
| Prometheus metrics endpoint | `be/app/main.py` | ✅ Done |
| Structured Docker Compose (dev + prod) | `docker-compose.yml` | ✅ Done |
| Ollama LLM integration | `be/app/services/ai/ollama_client.py` | ✅ Done |
| Next.js frontend dashboard | `web/app/` | ✅ Done |

---

### Phase 2 — AI Enrichment Pipeline ✅

| Component | File(s) | Trạng thái |
|-----------|---------|------------|
| CWE mapping (static lookup + LLM batch) | `be/app/services/ai/cwe_mapper.py` | ✅ Done |
| CVSS v3.1 scoring (severity defaults + LLM) | `be/app/services/ai/cvss_scorer.py` | ✅ Done |
| Risk prioritization (0.0–1.0 score) | `be/app/services/ai/risk_prioritizer.py` | ✅ Done |
| False positive scoring | `be/app/services/ai/false_positive.py` | ✅ Done |
| Duplicate / root-cause grouping | `be/app/services/ai/duplicate_detector.py` | ✅ Done |
| LLM-based remediation guidance | `be/app/services/ai/remediation.py` | ✅ Done |
| Executive summary generation | `be/app/services/ai/executive_summary.py` | ✅ Done |
| AI pipeline as Celery chain | `be/app/tasks/ai_tasks.py` | ✅ Done |
| Report generation | `be/app/services/reporting/generator.py` | ✅ Done |

---

### Phase 3 — RAG & Knowledge Base ✅

| Component | File(s) | Trạng thái |
|-----------|---------|------------|
| Knowledge doc ingestion | `be/app/services/rag/` | ✅ Done |
| Hybrid BM25 + vector retrieval (RRF fusion) | `be/app/services/rag/retriever.py` | ✅ Done |
| Semantic chunker (sentence-boundary aware) | `be/app/services/rag/chunker.py` | ✅ Done |
| Ollama embeddings (nomic-embed-text) | `be/app/services/rag/embedder.py` | ✅ Done |
| Cross-encoder reranker | `be/app/services/rag/reranker.py` | ✅ Done |
| Embedding lifecycle manager | `be/app/services/rag/lifecycle.py` | ✅ Done |
| Scanner output normalization | `be/app/services/normalization/` | ✅ Done |
| Exploit verification engine (sandbox + policy) | `be/app/services/sandbox/` | ✅ Done |
| Patch generation (framework-aware) | `be/app/services/ai/patch_generator.py` | ✅ Done |
| Patch validator (bandit + pattern gate) | `be/app/services/ai/patch_validator.py` | ✅ Done |
| Secure code rewrite engine | `be/app/services/ai/secure_rewriter.py` | ✅ Done |
| LangGraph multi-agent state machine | `be/app/services/agents/graph.py` | ✅ Done |
| Agent memory store (Redis, TTL 30d) | `be/app/services/agents/memory.py` | ✅ Done |
| Scanner plugin registry | `be/app/services/scanners/registry.py` | ✅ Done |

---

## Những điểm yếu cần sửa ngay (Critical Gaps)

| # | Vấn đề | Mức độ | Trạng thái |
|---|--------|--------|------------|
| 1 | Users lưu trong in-memory dict — mất khi restart | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 2 | Không có Alembic — migration thủ công bằng ALTER TABLE | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 3 | LLM calls đồng bộ (blocking), không có retry/cache | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 4 | `json.loads()` trực tiếp từ LLM output — hallucination ghi vào DB | 🟠 High | ✅ **ĐÃ SỬA** |
| 5 | CORS `allow_origins=["*"]` — wildcard trong production | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 6 | Không có audit log — zero forensic trail | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 7 | Không có rate limiting — scan/LLM endpoint có thể bị DoS | 🟠 High | ✅ **ĐÃ SỬA** |
| 8 | pgvector không có HNSW index — O(n) scan trên vector search | 🟠 High | ✅ **ĐÃ SỬA** |
| 9 | Redis result backend không có TTL — OOM theo thời gian | 🟠 High | ✅ **ĐÃ SỬA** |
| 10 | Không có prompt injection protection | 🟠 High | ✅ **ĐÃ SỬA** |

---

## Final Production Roadmap

### Sprint 1 — Bảo mật & Toàn vẹn dữ liệu (Tuần 1–2) ✅ COMPLETE

```
Deliverables:
├── 1.1  Thay users_db (dict) → bảng users trong PostgreSQL       ✅ DONE
├── 1.2  Token refresh + Redis blocklist (logout / revocation)    ✅ DONE
├── 1.3  CORS lockdown → env-variable CORS_ORIGINS                ✅ DONE
├── 1.4  Rate limiting middleware (slowapi)                        ✅ DONE
├── 1.5  Bảng audit_logs + middleware ghi mọi action              ✅ DONE
└── 1.6  Alembic thay thế manual ALTER TABLE                       ✅ DONE
```

**Sprint 1 progress: 6/6 done ✅ COMPLETE**

---

### Sprint 2 — AI Reliability (Tuần 3–4) ✅ COMPLETE

```
Deliverables:
├── 2.1  LLM Gateway (model abstraction + cache + retry)           ✅ DONE
├── 2.2  Pydantic schemas cho mọi LLM output                       ✅ DONE
├── 2.3  Prompt injection guard                                    ✅ DONE
├── 2.4  Hallucination detection + confidence scoring             ✅ DONE
├── 2.5  Checkpointed AI pipeline (idempotent per step)           ✅ DONE
└── 2.6  Dead-letter queue + result_expires cho Celery            ✅ DONE
```

**Sprint 2 progress: 6/6 done ✅ COMPLETE**

---

### Sprint 3 — RAG & Vector Search (Tuần 5–6) ✅ COMPLETE

```
Deliverables:
├── 3.1  HNSW index trên bảng embeddings                          ✅ DONE
├── 3.2  Hybrid retriever: BM25 (tsvector) + cosine + RRF fusion  ✅ DONE
├── 3.3  Cross-encoder reranker                                    ✅ DONE
├── 3.4  Semantic chunker (sentence-boundary aware)               ✅ DONE
├── 3.5  Embedding lifecycle manager                              ✅ DONE
└── 3.6  Contextual chunk enrichment                             ✅ DONE
```

**Sprint 3 progress: 6/6 done ✅ COMPLETE**

---

### Sprint 4 — Phase 3: Exploit + Patch + Rewrite (Tuần 7–9) ✅ COMPLETE

```
Deliverables:
├── 4.1  Sandbox policy engine                                    ✅ DONE
│        be/app/services/sandbox/policy.py
├── 4.2  Async exploit executor                                   ✅ DONE
│        be/app/services/sandbox/executor.py
├── 4.3  Bảng exploit_results + Celery task                       ✅ DONE
│        be/app/db/models/exploit_result.py
│        be/app/tasks/exploit_tasks.py
│        be/alembic/versions/005_add_exploit_results.py
├── 4.4  Patch generator (framework-aware, AST-grounded)          ✅ DONE
│        be/app/services/ai/patch_generator.py
├── 4.5  Patch validator (bandit + pattern gate)                  ✅ DONE
│        be/app/services/ai/patch_validator.py
└── 4.6  Secure rewriter + AST equivalence check                 ✅ DONE
         be/app/services/ai/secure_rewriter.py
```

**Sprint 4 progress: 6/6 done ✅ COMPLETE**

---

### Sprint 5 — Multi-Agent Orchestration (Tuần 10–12) ✅ COMPLETE

```
Deliverables:
├── 5.1  LangGraph state machine                                  ✅ DONE
│        be/app/services/agents/state.py (PipelineState)
│        be/app/services/agents/graph.py (StateGraph)
│        - 6 nodes: scan→normalize→ai_enrich→exploit→patch→report
│        - Conditional edge: skip exploit nếu không có High/Critical
│
├── 5.2  Agent memory store (Redis, TTL 30 ngày)                 ✅ DONE
│        be/app/services/agents/memory.py
│        - Namespaced per agent_id, JSON serialization, 30d TTL
│
├── 5.3  Scanner abstraction layer + plugin registry              ✅ DONE
│        be/app/services/scanners/base.py (ScannerBase ABC)
│        be/app/services/scanners/registry.py
│
├── 5.4  Prompt version registry                                  ✅ DONE
│        be/app/services/ai/prompt_registry.py
│        - 9 built-in versioned prompt templates                 ✅
│        - Semver + "active" tag routing                         ✅
│        - Prometheus usage counter per prompt+version           ✅
│        - render() với safe str.format_map substitution         ✅
│
└── 5.5  Agent evaluator + eval test suite                        ✅ DONE
         be/app/services/agents/evaluator.py
         - 6 evaluation dimensions (0.0–1.0 each)               ✅
         - Weighted aggregate score + A/B/C/D/F grade            ✅
         - run_eval_suite() — offline tests không cần DB         ✅
```

**Sprint 5 progress: 5/5 done ✅ COMPLETE**

---

### Sprint 6 — Observability & Production Hardening (Tuần 13–14) ✅ COMPLETE

```
Deliverables:
├── 6.1  structlog JSON logging + trace ID injection              ✅ DONE
│        be/app/core/logging.py  (rewrite)
│        - structlog JSON renderer (fallback to stdlib JSON)     ✅
│        - ContextVar trace_id per request                       ✅
│        - TraceIDMiddleware → X-Trace-ID header                 ✅
│        - Wired into main.py                                    ✅
│        - requirements.txt: structlog==24.1.0                   ✅
│
├── 6.2  OpenTelemetry tracing                                    ✅ DONE
│        be/app/core/tracing.py
│        - FastAPI + SQLAlchemy + Redis auto-instrumentation     ✅
│        - OTLP/HTTP exporter (Jaeger/Tempo compatible)          ✅
│        - get_tracer() helper + no-op fallback                  ✅
│        - setup_tracing() called on startup                     ✅
│        - requirements.txt: opentelemetry-* packages            ✅
│
├── 6.3  Prometheus metrics registry                              ✅ DONE
│        be/app/core/metrics.py
│        - 15 domain metrics (scan, AI, RAG, exploit, patch,     ✅
│          auth, rate-limit, prompt injection)
│        - No-op stub khi prometheus_client không install        ✅
│        - PROMPT_USAGE counter dùng bởi prompt_registry        ✅
│
├── 6.4  Grafana dashboards (4 dashboards)                        ✅ DONE
│        infra/grafana/dashboards/01_overview.json               ✅
│        infra/grafana/dashboards/02_ai_pipeline.json            ✅
│        infra/grafana/dashboards/03_rag.json                    ✅
│        infra/grafana/dashboards/04_security.json               ✅
│        infra/grafana/provisioning/ (datasources + dashboards)  ✅
│
├── 6.5  Redis Pub/Sub WebSocket (thay thế DB polling)            ✅ DONE
│        be/app/api/v1/routers/scans.py  (rewrite)
│        - subscribe channel scan:events:{scan_id}               ✅
│        - publish_scan_event() helper cho Celery tasks          ✅
│        - Fallback về 3-second DB poll nếu Pub/Sub fail         ✅
│        - Initial state từ DB ngay khi connect                  ✅
│
└── 6.6  Kubernetes manifests + HPA                              ✅ DONE
         infra/k8s/namespace.yaml                                ✅
         infra/k8s/configmap.yaml                                ✅
         infra/k8s/secret.yaml                                   ✅
         infra/k8s/api-deployment.yaml + Service                 ✅
         infra/k8s/api-hpa.yaml (2–10 pods, CPU 60% / Mem 75%)  ✅
         infra/k8s/worker-deployment.yaml + HPA (2–8 pods)       ✅
         infra/k8s/beat-deployment.yaml (1 replica)              ✅
         infra/k8s/ingress.yaml (WebSocket headers)              ✅
         infra/k8s/kustomization.yaml                            ✅
```

**Sprint 6 progress: 6/6 done ✅ COMPLETE**

---

## Tổng tiến độ

```
Sprint 1  [██████████]  6/6  100%   ✅ COMPLETE
Sprint 2  [██████████]  6/6  100%   ✅ COMPLETE
Sprint 3  [██████████]  6/6  100%   ✅ COMPLETE
Sprint 4  [██████████]  6/6  100%   ✅ COMPLETE
Sprint 5  [██████████]  5/5  100%   ✅ COMPLETE
Sprint 6  [██████████]  6/6  100%   ✅ COMPLETE

TỔNG      [██████████] 35/35  100%  🎉 ENTERPRISE-GRADE COMPLETE
```

---

## Việc đã làm trong session cuối (2026-05-27)

| Task | Files tạo/sửa | Kết quả |
|------|--------------|---------|
| Prompt version registry | `services/ai/prompt_registry.py` | 9 built-in versioned templates, semver routing, Prometheus counter |
| Agent evaluator | `services/agents/evaluator.py` | 6 dimensions, A–F grading, offline eval suite (5 test cases) |
| structlog JSON logging | `core/logging.py` (rewrite), `main.py` | JSON logs với trace_id, X-Trace-ID header, structlog fallback |
| OpenTelemetry tracing | `core/tracing.py`, `main.py` | FastAPI + SQLAlchemy + Redis auto-instrumented, OTLP/HTTP export |
| Prometheus metrics registry | `core/metrics.py` | 15 domain counters/histograms/gauges, no-op stubs |
| requirements.txt | `requirements.txt` | structlog, opentelemetry-*, prometheus-client thêm vào |
| Grafana dashboards | `infra/grafana/dashboards/` × 4 | Overview, AI Pipeline, RAG, Security Operations |
| Redis Pub/Sub WebSocket | `api/v1/routers/scans.py` (rewrite) | Pub/Sub real-time, publish_scan_event() helper, DB poll fallback |
| Kubernetes manifests | `infra/k8s/` × 9 files | API HPA (2–10), Worker HPA (2–8), Beat, Ingress, kustomization |

---

## Architecture Summary (Final)

```
┌─────────────────────────────────────────────────────┐
│                   ATTT Backend                       │
│                                                     │
│  FastAPI API ──→ Celery Workers ──→ Celery Beat     │
│      │               │                              │
│      │         [5 queues: scans, ai,                │
│      │          rag, exploit, default]               │
│      │                                              │
│  ┌───▼────┐   ┌──────▼──────┐   ┌────────────┐    │
│  │ Auth   │   │ AI Pipeline │   │ RAG Engine │    │
│  │ RBAC   │   │ LLM Gateway │   │ Hybrid BM25│    │
│  │ Audit  │   │ Confidence  │   │ + Vector   │    │
│  │ Logs   │   │ Scoring     │   │ Reranker   │    │
│  └───┬────┘   └──────┬──────┘   └────────────┘    │
│      │               │                              │
│  ┌───▼───────────────▼──────────────────────────┐  │
│  │          LangGraph State Machine              │  │
│  │  scan → normalize → enrich → exploit →        │  │
│  │  patch → report                               │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  Observability Stack:                               │
│  structlog JSON → OpenTelemetry → Prometheus        │
│  → Grafana (4 dashboards)                           │
│                                                     │
│  Kubernetes: API HPA (2–10) + Worker HPA (2–8)     │
└─────────────────────────────────────────────────────┘
```

---

## Critical Path (Hoàn thành)

```
[Sprint 1 ✅] → [Sprint 2 ✅] → [Sprint 3 ✅]
                                       │
                              [Sprint 4 ✅] (Exploit + Patch)
                                       │
                              [Sprint 5 ✅] (Multi-Agent)
                                       │
                              [Sprint 6 ✅] (Observability + K8s)
                                       │
                              🎉 PRODUCTION READY
```
