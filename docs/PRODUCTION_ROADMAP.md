# ATTT — Production Roadmap & System Status

> Last updated: 2026-05-26

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
| WebSocket real-time scan status | `be/app/api/v1/routers/scans.py` | ✅ Done (polling-based) |
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

### Phase 3 — RAG & Knowledge Base ✅ (partial)

| Component | File(s) | Trạng thái |
|-----------|---------|------------|
| Knowledge doc ingestion | `be/app/services/rag/` | ✅ Done |
| Cosine similarity vector search | `be/app/services/rag/retriever.py` | ✅ Done (basic) |
| Character-based chunking | `be/app/services/rag/chunker.py` | ✅ Done (basic) |
| Ollama embeddings (nomic-embed-text) | `be/app/services/rag/embedder.py` | ✅ Done |
| Prompt-based exploit hints | `be/app/services/ai/remediation.py` | ✅ Done |
| Scanner output normalization | `be/app/services/normalization/` | ✅ Done |

---

### Phase 3 — Missing / Incomplete ❌

| Component | Trạng thái |
|-----------|------------|
| Exploit verification engine (sandbox, payload, diff) | ❌ Not implemented |
| Patch generation (AST-aware) | ❌ Not implemented |
| Secure code rewrite engine | ❌ Not implemented |
| LangGraph multi-agent state machine | ❌ Not implemented |
| Agent memory store | ❌ Not implemented |
| Hybrid BM25 + vector retrieval | ❌ Not implemented |
| Cross-encoder reranker | ❌ Not implemented |

---

## Những điểm yếu cần sửa ngay (Critical Gaps)

| # | Vấn đề | Mức độ | Trạng thái |
|---|--------|--------|------------|
| 1 | Users lưu trong in-memory dict — mất khi restart | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 2 | Không có Alembic — migration thủ công bằng ALTER TABLE | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 3 | LLM calls đồng bộ (blocking), không có retry/cache | 🔴 Critical | ✅ **ĐÃ SỬA** |
| 4 | `json.loads()` trực tiếp từ LLM output — hallucination ghi vào DB | 🟠 High | ✅ **ĐÃ SỬA** |
| 5 | CORS `allow_origins=["*"]` — wildcard trong production | 🔴 Critical | ⏳ Chưa làm |
| 6 | Không có audit log — zero forensic trail | 🔴 Critical | ⏳ Chưa làm |
| 7 | Không có rate limiting — scan/LLM endpoint có thể bị DoS | 🟠 High | ⏳ Chưa làm |
| 8 | pgvector không có HNSW index — O(n) scan trên vector search | 🟠 High | ⏳ Chưa làm |
| 9 | Redis result backend không có TTL — OOM theo thời gian | 🟠 High | ⏳ Chưa làm |
| 10 | Không có prompt injection protection | 🟠 High | ⏳ Chưa làm |

---

## Final Production Roadmap

### Sprint 1 — Bảo mật & Toàn vẹn dữ liệu (Tuần 1–2)

**Mục tiêu:** Vá các lỗ hổng nghiêm trọng nhất trước khi làm bất cứ thứ gì khác.

```
Deliverables:
├── 1.1  Thay users_db (dict) → bảng users trong PostgreSQL       ✅ DONE
│        File: be/app/db/models/user.py                           ✅
│        File: be/alembic/versions/001_add_users_table.py         ✅
│        File: be/app/core/security.py  (rewrite, DB-backed)      ✅
│        File: be/app/api/v1/routers/auth.py  (pass db session)   ✅
│        File: be/entrypoint.sh  (alembic upgrade head on start)  ✅
│
├── 1.2  Token refresh + Redis blocklist (logout / revocation)    ⏳ TODO
│        Endpoint: POST /api/v1/auth/refresh
│        Endpoint: POST /api/v1/auth/logout
│
├── 1.3  CORS lockdown → env-variable CORS_ORIGINS                ⏳ TODO
│        Không còn allow_origins=["*"]
│
├── 1.4  Rate limiting middleware (slowapi)                        ⏳ TODO
│        Giới hạn: 10 req/min cho /auth, 5 scan/min per user
│
├── 1.5  Bảng audit_logs + middleware ghi mọi action              ⏳ TODO
│        File: be/app/db/models/audit_log.py
│        File: be/alembic/versions/004_add_audit_logs.py
│        File: be/app/api/v1/middleware/audit_log.py
│
└── 1.6  Alembic thay thế manual ALTER TABLE                       ✅ DONE
         File: be/alembic/env.py                                  ✅
         File: be/alembic.ini                                     ✅
         File: be/alembic/script.py.mako                          ✅
         Xoá _MIGRATIONS list trong session.py                    ✅
         docker-compose: db healthcheck + entrypoint              ✅
```

**Sprint 1 progress: 2/6 done (1.1 ✅, 1.6 ✅)**

---

### Sprint 2 — AI Reliability (Tuần 3–4)

**Mục tiêu:** Mọi LLM call đều có cache, retry, validation, và không block worker.

```
Deliverables:
├── 2.1  LLM Gateway (model abstraction + cache + retry)           ✅ DONE
│        File: be/app/services/ai/gateway.py                      ✅
│        File: be/app/services/ai/ollama_client.py  (shim)        ✅
│        File: be/app/core/config.py  (llm_timeout, cache_ttl…)   ✅
│        - Redis cache TTL 1h cho identical prompts               ✅
│        - Retry 3 lần với exponential backoff (1s/2s/4s)         ✅
│        - Provider interface sẵn sàng (Ollama, OpenAI, Anthropic) ✅
│
├── 2.2  Pydantic schemas cho mọi LLM output                       ✅ DONE
│        File: be/app/schemas/ai_output.py                        ✅
│        - CWEItem: reject format sai (không phải CWE-NNN)        ✅
│        - CVSSItem: validate vector string đúng chuẩn CVSS:3.1   ✅
│        - RiskItem, FalsePositiveItem: clamp 0.0–1.0             ✅
│        - RemediationItem: min_length, steps list validation      ✅
│        - PatchOutput: confidence clamp                          ✅
│        - parse_llm_json_list: strip markdown fences tự động     ✅
│        Cập nhật: cwe_mapper, cvss_scorer, risk_prioritizer,     ✅
│                  false_positive, remediation dùng schemas        ✅
│
├── 2.3  Prompt injection guard                                    ⏳ TODO
│        File: be/app/services/ai/prompt_guard.py
│        - 8 injection pattern detectors
│        - Hardened delimiter wrapping cho user data
│
├── 2.4  Hallucination detection + confidence scoring             ⏳ TODO
│        File: be/app/services/ai/hallucination.py
│        File: be/app/services/ai/confidence.py
│        - Ghi ai_confidence (0.0–1.0) vào bảng findings
│        - Tier: HIGH / MEDIUM / LOW confidence
│
├── 2.5  Checkpointed AI pipeline (idempotent per step)           ⏳ TODO
│        File: be/app/tasks/ai_tasks.py  (rewrite)
│        - Mỗi bước là 1 Celery task riêng
│        - Retry chỉ re-run bước bị fail, không re-run toàn bộ
│
└── 2.6  Dead-letter queue + result_expires cho Celery            ⏳ TODO
         File: be/app/core/celery_app.py
         - result_expires = 86400 (24h)
         - DLQ cho mọi queue quan trọng
```

**Sprint 2 progress: 2/6 done (2.1 ✅, 2.2 ✅)**

---

### Sprint 3 — RAG & Vector Search (Tuần 5–6)

**Mục tiêu:** RAG đủ chính xác để grounding LLM output và giảm hallucination.

```
Deliverables:
├── 3.1  HNSW index trên bảng embeddings                          ⏳ TODO
│        File: be/alembic/versions/003_add_hnsw_index.py
│        SQL: CREATE INDEX CONCURRENTLY ... USING hnsw
│        SQL: CREATE INDEX ... USING gin(to_tsvector...)
│
├── 3.2  Hybrid retriever: BM25 (tsvector) + cosine + RRF fusion  ⏳ TODO
│        File: be/app/services/rag/retriever.py  (rewrite)
│        - alpha=0.7 (vector) + 0.3 (BM25)
│        - Reciprocal Rank Fusion (K=60)
│
├── 3.3  Cross-encoder reranker                                    ⏳ TODO
│        File: be/app/services/rag/reranker.py
│        Model: cross-encoder/ms-marco-MiniLM-L-6-v2
│        (sentence-transformers đã thêm vào requirements.txt)     ✅
│
├── 3.4  Semantic chunker (sentence-boundary aware)               ⏳ TODO
│        File: be/app/services/rag/chunker.py  (rewrite)
│        - Bảo toàn code blocks, CVE references
│        - Overlap theo số câu thay vì số ký tự
│
├── 3.5  Embedding lifecycle manager                              ⏳ TODO
│        File: be/app/services/rag/lifecycle.py
│        - Detect chunks cần reindex khi đổi model
│        - Celery beat task: rag.reindex_stale (mỗi 1 giờ)
│
└── 3.6  Contextual chunk enrichment                             ⏳ TODO
         File: be/app/tasks/rag_tasks.py  (addition)
         - LLM nhỏ thêm 1-2 câu context vào mỗi chunk trước index
```

**Sprint 3 progress: 0/6 done** *(sentence-transformers dep đã thêm)*

---

### Sprint 4 — Phase 3: Exploit + Patch + Rewrite (Tuần 7–9)

**Mục tiêu:** Hoàn thiện 3 tính năng Phase 3 còn thiếu với safety boundaries.

```
Deliverables:
├── 4.1  Sandbox policy engine                                    ⏳ TODO
│        File: be/app/services/sandbox/policy.py
│
├── 4.2  Async exploit executor                                   ⏳ TODO
│        File: be/app/services/sandbox/executor.py
│
├── 4.3  Bảng exploit_results + Celery task                       ⏳ TODO
│        File: be/app/db/models/exploit_result.py
│        File: be/app/tasks/exploit_tasks.py
│        File: be/alembic/versions/005_add_exploit_results.py
│
├── 4.4  Patch generator (framework-aware, AST-grounded)          ⏳ TODO
│        File: be/app/services/ai/patch_generator.py
│        Note: PatchOutput schema đã sẵn sàng trong ai_output.py ✅
│
├── 4.5  Patch validator (bandit + semgrep gate)                  ⏳ TODO
│        File: be/app/services/ai/patch_validator.py
│
└── 4.6  Secure rewriter + AST equivalence check                 ⏳ TODO
         File: be/app/services/ai/secure_rewriter.py
```

**Sprint 4 progress: 0/6 done** *(PatchOutput schema đã có sẵn)*

---

### Sprint 5 — Multi-Agent Orchestration (Tuần 10–12)

**Mục tiêu:** Toàn bộ pipeline chạy như một state machine có thể resume, retry, và evaluate.

```
Deliverables:
├── 5.1  LangGraph state machine                                  ⏳ TODO
│        File: be/app/services/agents/state.py
│        File: be/app/services/agents/graph.py
│
├── 5.2  Agent memory store (Redis, TTL 30 ngày)                 ⏳ TODO
│        File: be/app/services/agents/memory.py
│
├── 5.3  Scanner abstraction layer + plugin registry              ⏳ TODO
│        File: be/app/services/scanners/base.py
│        File: be/app/services/scanners/registry.py
│
├── 5.4  Prompt version registry                                  ⏳ TODO
│        File: be/app/services/ai/prompt_registry.py
│
└── 5.5  Agent evaluator + eval test suite                        ⏳ TODO
         File: be/app/services/agents/evaluator.py
```

**Sprint 5 progress: 0/5 done**

---

### Sprint 6 — Observability & Production Hardening (Tuần 13–14)

**Mục tiêu:** Hệ thống observable, traceable, và sẵn sàng cho Kubernetes.

```
Deliverables:
├── 6.1  structlog JSON logging + trace ID injection              ⏳ TODO
│        File: be/app/core/logging.py  (rewrite)
│
├── 6.2  OpenTelemetry tracing                                    ⏳ TODO
│        File: be/app/core/tracing.py
│
├── 6.3  Prometheus metrics registry                              ⏳ TODO
│        File: be/app/core/metrics.py
│
├── 6.4  Grafana dashboards (4 dashboards)                        ⏳ TODO
│        File: infra/grafana/dashboards/
│
├── 6.5  Redis Pub/Sub WebSocket (thay thế DB polling)            ⏳ TODO
│        File: be/app/api/v1/routers/scans.py  (rewrite WS)
│
└── 6.6  Kubernetes manifests + HPA                              ⏳ TODO
         File: infra/k8s/
```

**Sprint 6 progress: 0/6 done**

---

## Tổng tiến độ

```
Sprint 1  [██░░░░░░░░]  2/6   33%   ← Đang làm
Sprint 2  [██░░░░░░░░]  2/6   33%   ← Đang làm
Sprint 3  [░░░░░░░░░░]  0/6    0%
Sprint 4  [░░░░░░░░░░]  0/6    0%
Sprint 5  [░░░░░░░░░░]  0/5    0%
Sprint 6  [░░░░░░░░░░]  0/6    0%

TỔNG      [█░░░░░░░░░]  4/35  11%
```

### Việc đã làm trong session này ✅

| Task | Files tạo/sửa | Kết quả |
|------|--------------|---------|
| User model + Alembic | `db/models/user.py`, `alembic/`, `entrypoint.sh` | Users persistent trong DB, migration tự chạy khi start |
| security.py rewrite | `core/security.py`, `routers/auth.py` | `authenticate_user` + `get_current_user` query DB thay dict |
| LLM Gateway | `services/ai/gateway.py`, `ollama_client.py` (shim) | Redis cache 1h + retry 3x + provider abstraction |
| Config update | `core/config.py` | `llm_timeout`, `llm_max_retries`, `llm_cache_ttl` |
| AI output schemas | `schemas/ai_output.py` | 6 schema với strict validators, `parse_llm_json_list` |
| AI services update | `cwe_mapper`, `cvss_scorer`, `risk_prioritizer`, `false_positive`, `remediation` | Hallucinated JSON bị reject trước khi vào DB |
| requirements update | `requirements.txt` | `alembic==1.13.1`, `sentence-transformers==3.0.1` |
| docker-compose | `docker-compose.yml` | DB healthcheck, api dùng entrypoint.sh |

---

## Việc tiếp theo nên làm (Next Up)

```
Ưu tiên 1 (Sprint 1 — còn lại):
├── 1.2  Token refresh + logout endpoint
├── 1.3  CORS lockdown (CORS_ORIGINS env var)
├── 1.4  Rate limiting (slowapi)
└── 1.5  Audit log table + middleware

Ưu tiên 2 (Sprint 2 — còn lại):
├── 2.3  Prompt injection guard
├── 2.4  Hallucination detection + confidence scoring
├── 2.5  Checkpointed AI pipeline (idempotent per step)
└── 2.6  Dead-letter queue + result_expires

Ưu tiên 3 (Sprint 3):
├── 3.1  HNSW index migration
└── 3.2  Hybrid BM25 + vector retriever
```

---

## Critical Path (Thứ tự phụ thuộc)

```
[1.1 Users DB ✅] ─────────────────────────────────────────────────┐
      │                                                             │
      ▼                                                             ▼
[1.6 Alembic ✅] → [3.1 HNSW Index] → [3.2 Hybrid RAG] → [3.3 Reranker]
      │
      ▼
[2.1 LLM Gateway ✅] → [2.2 Output Schemas ✅] → [2.3 Prompt Guard]
                                │
                                ▼
                    [2.4 Confidence Scoring] → [2.5 Checkpointed Pipeline]
                                                       │
                              ┌────────────────────────┤
                              ▼                        ▼
                    [4.1 Sandbox Policy]      [4.4 Patch Generator]
                    [4.2 Exploit Executor]    [4.5 Patch Validator]
                    [4.3 Exploit Results]     [4.6 Secure Rewriter]
                              │                        │
                              └───────────┬────────────┘
                                          ▼
                                   [5.1 LangGraph]
                                   [5.2 Agent Memory]
                                   [5.3 Scanner Plugin]
                                          │
                                          ▼
                                   [6.x Observability]
```

---

## Ước tính thời gian hoàn thành

| Sprint | Tuần | Effort | Done | Còn lại | Kết quả chính |
|--------|------|--------|------|---------|---------------|
| Sprint 1 | 1–2 | 10 ngày | 2 | 4 items | Hệ thống an toàn để deploy production |
| Sprint 2 | 3–4 | 10 ngày | 2 | 4 items | AI pipeline đáng tin cậy |
| Sprint 3 | 5–6 | 8 ngày | 0 | 6 items | RAG chính xác + grounding LLM |
| Sprint 4 | 7–9 | 15 ngày | 0 | 6 items | Phase 3 hoàn chỉnh |
| Sprint 5 | 10–12 | 12 ngày | 0 | 5 items | Multi-agent production-grade |
| Sprint 6 | 13–14 | 8 ngày | 0 | 6 items | Full observability + K8s |
| **Total** | **14 tuần** | **~63 ngày** | **4** | **31 items** | **Enterprise-grade** |
