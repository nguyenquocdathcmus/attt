# ATTT — Optimization Roadmap

> Tài liệu này mô tả các điểm **chưa đúng / chưa đủ** so với yêu cầu trong `system-flow.md`,
> và kế hoạch cụ thể để sửa từng điểm.
>
> Last updated: 2026-05-27 | Trạng thái ban đầu: 7 gaps cần xử lý

---

## Phân tích Gap (So sánh system-flow.md ↔ code thực tế)

### ✅ Những thứ đúng với system-flow

| Yêu cầu trong system-flow | Trạng thái |
|---------------------------|------------|
| ZAP + Nikto multi-scanner | ✅ |
| AI pipeline 7 bước có checkpoint | ✅ |
| Exploit verification (9 probe types) | ✅ |
| Patch gen + 4-gate validation | ✅ |
| Secure code rewriter + AST check | ✅ |
| RAG hybrid BM25 + vector + reranker | ✅ |
| LangGraph state machine (6 nodes) | ✅ |
| JWT + RBAC + jti blocklist | ✅ |
| Audit log middleware | ✅ |
| Rate limiting (slowapi) | ✅ |
| HNSW + GIN index | ✅ |
| Redis LLM cache 1h + retry 3x | ✅ |
| Prompt injection guard | ✅ |
| Pydantic schema gate (chống hallucination) | ✅ |
| WebSocket real-time feed | ✅ (Pub/Sub) |
| Prometheus metrics endpoint `/metrics` | ✅ |
| Kubernetes manifests + HPA | ✅ |

---

### ❌ Gaps cần sửa

| # | Gap | Mức độ | Chi tiết |
|---|-----|--------|----------|
| **G1** | `scan_tasks.py` không publish Pub/Sub events | 🔴 Critical | WebSocket dùng Pub/Sub nhưng task không gọi `publish_scan_event()` khi status thay đổi (running/completed/failed). Client nhận initial state rồi không nhận update nào nữa |
| **G2** | AI services dùng hardcoded prompt strings | 🟠 High | `cwe_mapper.py`, `cvss_scorer.py`, `remediation.py` vẫn dùng f-string thay vì `prompt_registry`. Prompt registry được tạo nhưng không được dùng — không có version tracking, A/B test, audit |
| **G3** | Prometheus metrics không được increment | 🟠 High | `metrics.py` định nghĩa 15 counters/histograms nhưng không có task/service nào gọi chúng. Grafana dashboards sẽ trống rỗng |
| **G4** | Không có API endpoint cho Agent Evaluator | 🟠 High | `evaluator.py` tồn tại nhưng không expose qua REST. Không có cách nào trigger evaluation từ frontend/CI |
| **G5** | Grafana + OTel Collector thiếu trong `docker-compose.yml` | 🟠 High | Dashboards và tracing code đã có nhưng không có Grafana service và OTel Collector trong compose → không thể chạy observability stack |
| **G6** | API inconsistency: `DELETE` vs `POST /cancel` | 🟡 Medium | `system-flow.md` section 9 ghi `DELETE /api/v1/scans/{id}` nhưng code là `POST /{id}/cancel`. Cần thêm `DELETE` alias hoặc update docs |
| **G7** | `system-flow.md` outdated (77% → 100%) | 🟡 Medium | Tiến độ, kiến trúc diagram, và observability section chưa được cập nhật |

---

## Optimization Plan

### OPT-1 — Wire Pub/Sub vào scan_tasks + ai_tasks

**File cần sửa:** `be/app/tasks/scan_tasks.py`, `be/app/tasks/ai_tasks.py`

**Vấn đề:**
- `publish_scan_event()` đã tồn tại trong `routers/scans.py`
- `scan_tasks.py` thay đổi `scan.status` (running → completed/failed) nhưng không notify
- Kết quả: WebSocket client nhận initial state nhưng không bao giờ nhận update thực tế

```
Deliverables:
├── OPT-1.1  scan_tasks.py publish 3 events:                      ⏳ TODO
│             - "running" khi scan bắt đầu
│             - "completed" kèm findings_count khi xong
│             - "failed" kèm error khi crash
│
└── OPT-1.2  ai_tasks.py publish step-level progress events:      ⏳ TODO
              - Mỗi checkpoint (step 1–7) publish {"step": N, "status": "done"}
              - Client có thể hiện progress bar AI pipeline
```

---

### OPT-2 — Migrate AI services sang prompt_registry

**File cần sửa:** `cwe_mapper.py`, `cvss_scorer.py`, `remediation.py`, `risk_prioritizer.py`, `false_positive.py`

**Vấn đề:**
- Prompt strings hardcoded trong mỗi file — không có version tracking, không A/B test được
- `prompt_registry.py` đã có 9 built-in templates nhưng chưa được dùng ở đâu
- Metrics `PROMPT_USAGE` sẽ luôn = 0

```
Deliverables:
├── OPT-2.1  cwe_mapper.py dùng get_prompt("cwe_mapping")         ⏳ TODO
├── OPT-2.2  cvss_scorer.py dùng get_prompt("cvss_scoring")       ⏳ TODO
├── OPT-2.3  remediation.py dùng get_prompt("remediation")        ⏳ TODO
├── OPT-2.4  risk_prioritizer.py dùng get_prompt("risk_prioritization") ⏳ TODO
├── OPT-2.5  false_positive.py dùng get_prompt("false_positive")  ⏳ TODO
└── OPT-2.6  patch_generator.py dùng get_prompt("patch_generation") ⏳ TODO
```

---

### OPT-3 — Wire Prometheus metrics vào tasks và services

**File cần sửa:** `scan_tasks.py`, `ai_tasks.py`, `exploit_tasks.py`, `routers/auth.py`, `gateway.py`

**Vấn đề:**
- 15 metrics định nghĩa trong `metrics.py`, không có gì increment → Grafana dashboards trống
- Cần instrument các điểm chính: scan lifecycle, LLM calls, exploit attempts, auth failures

```
Deliverables:
├── OPT-3.1  scan_tasks.py:                                        ⏳ TODO
│             - SCAN_TOTAL.labels(status=...).inc() tại mỗi transition
│             - SCAN_DURATION_SECONDS.labels(scanner=...).observe()
│             - SCAN_FINDINGS_TOTAL.labels(severity=...).inc()
│             - ACTIVE_SCANS_GAUGE.inc()/dec()
│
├── OPT-3.2  gateway.py (LLM Gateway):                            ⏳ TODO
│             - LLM_REQUESTS_TOTAL.labels(step, outcome).inc()
│             - LLM_LATENCY_SECONDS.labels(model, step).observe()
│
├── OPT-3.3  ai_tasks.py:                                          ⏳ TODO
│             - LLM_CONFIDENCE_HISTOGRAM per finding
│
├── OPT-3.4  exploit_tasks.py:                                     ⏳ TODO
│             - EXPLOIT_ATTEMPTS_TOTAL.labels(type, outcome).inc()
│
├── OPT-3.5  patch_generator.py + patch_validator.py:             ⏳ TODO
│             - PATCH_GENERATION_TOTAL.labels(outcome).inc()
│
└── OPT-3.6  routers/auth.py:                                      ⏳ TODO
              - AUTH_FAILURES_TOTAL.labels(reason).inc()
              - RATE_LIMIT_HITS_TOTAL.labels(endpoint).inc()
```

---

### OPT-4 — Expose Agent Evaluator qua REST API

**File cần tạo:** `be/app/api/v1/routers/evaluations.py`
**File cần sửa:** `be/app/main.py`

**Vấn đề:**
- `evaluator.py` có `PipelineEvaluator` và `run_eval_suite()` nhưng không có endpoint
- Không thể trigger từ frontend hay CI/CD pipeline

```
Deliverables:
├── OPT-4.1  Tạo router evaluations.py:                           ⏳ TODO
│             POST /api/v1/evaluations/{scan_id}
│               → chạy PipelineEvaluator.evaluate()
│               → trả về EvalReport (JSON)
│               → lưu result vào Redis (TTL 24h)
│             GET  /api/v1/evaluations/{scan_id}
│               → lấy cached result
│             POST /api/v1/evaluations/suite
│               → chạy run_eval_suite() (offline, không cần DB)
│               → dùng cho CI/CD health check
│
└── OPT-4.2  Wire vào main.py                                     ⏳ TODO
```

---

### OPT-5 — Thêm Grafana + OTel Collector vào docker-compose.yml

**File cần sửa:** `docker-compose.yml`
**File cần tạo:** `infra/otel-collector/otel-collector.yml`

**Vấn đề:**
- Grafana dashboard JSON đã có trong `infra/grafana/dashboards/`
- `tracing.py` export tới `http://localhost:4318` nhưng không có OTel Collector service
- Không thể chạy observability stack bằng `docker-compose up`

```
Deliverables:
├── OPT-5.1  Thêm Grafana service vào docker-compose:             ⏳ TODO
│             - image: grafana/grafana:10.4.0
│             - Mount provisioning/ và dashboards/
│             - Port 3001 (tránh conflict với Next.js :3000)
│
└── OPT-5.2  Thêm OTel Collector service:                         ⏳ TODO
              - image: otel/opentelemetry-collector-contrib:0.104.0
              - Receive OTLP/gRPC :4317 và HTTP :4318
              - Export traces tới Jaeger (optional) hoặc log
              - infra/otel-collector/otel-collector.yml config file
```

---

### OPT-6 — Fix API inconsistency: Thêm DELETE alias

**File cần sửa:** `be/app/api/v1/routers/scans.py`, `docs/system-flow.md`

**Vấn đề:**
- `system-flow.md` section 9 ghi `DELETE /api/v1/scans/{id}`
- Code thực tế: `POST /api/v1/scans/{id}/cancel`
- CI/CD scripts theo docs sẽ fail

```
Deliverables:
└── OPT-6.1  Thêm @router.delete("/{scan_id}") alias gọi cancel logic   ⏳ TODO
              (giữ nguyên POST cancel để backward compatible)
```

---

### OPT-7 — Cập nhật system-flow.md

**File cần sửa:** `docs/system-flow.md`

```
Deliverables:
└── OPT-7.1  Cập nhật:                                            ⏳ TODO
              - Timestamp: 2026-05-27
              - Tiến độ: 100% (35/35 + 7 optimizations)
              - Thêm Observability section (structlog, OTel, Prometheus, Grafana)
              - Thêm Prompt registry vào section 2.2
              - Thêm Agent evaluator vào section 2.7
              - Cập nhật kiến trúc diagram
              - Fix API reference (DELETE alias)
```

---

## Tổng hợp theo mức độ ưu tiên

```
🔴 Critical (ảnh hưởng chức năng cốt lõi):
├── OPT-1: Pub/Sub không hoạt động → WebSocket client không nhận update
└── (không có gì khác ở mức Critical)

🟠 High (tính năng tồn tại nhưng không hoạt động đúng):
├── OPT-2: Prompt registry được tạo nhưng không dùng
├── OPT-3: Metrics defined nhưng không increment → Grafana trống
├── OPT-4: Evaluator không có API → không trigger được
└── OPT-5: Observability stack không chạy được từ docker-compose

🟡 Medium (inconsistency / docs):
├── OPT-6: API docs vs code không khớp
└── OPT-7: system-flow.md cũ
```

---

## Kế hoạch thực hiện (Thứ tự)

```
Ưu tiên 1 — Fix ngay (blocking features):
├── OPT-1  Wire Pub/Sub events vào scan_tasks + ai_tasks
└── OPT-5  Thêm Grafana + OTel Collector vào docker-compose

Ưu tiên 2 — Wire components vào nhau:
├── OPT-2  AI services dùng prompt_registry
├── OPT-3  Instrument Prometheus metrics
└── OPT-4  Expose evaluator qua REST

Ưu tiên 3 — Cleanup / Docs:
├── OPT-6  Thêm DELETE alias
└── OPT-7  Update system-flow.md
```

---

## Tiến độ

```
OPT-1  Wire Pub/Sub                  [██████████] 100%  ✅ DONE (2026-05-27)
OPT-2  Migrate to prompt_registry    [██████████] 100%  ✅ DONE (2026-05-27)
OPT-3  Wire Prometheus metrics       [██████████] 100%  ✅ DONE (2026-05-27)
OPT-4  Evaluator REST API            [██████████] 100%  ✅ DONE (2026-05-27)
OPT-5  docker-compose observability  [██████████] 100%  ✅ DONE (2026-05-27)
OPT-6  DELETE alias                  [██████████] 100%  ✅ DONE (2026-05-27)
OPT-7  Update system-flow.md         [██████████] 100%  ✅ DONE (2026-05-27)

TỔNG   [██████████]  7/7 done  🎉 ALL GAPS CLOSED
```

---

## Files đã thay đổi

| File | Thay đổi |
|------|---------|
| `be/app/tasks/scan_tasks.py` | Pub/Sub publish (running/completed/failed/cancelled) + Prometheus metrics |
| `be/app/tasks/ai_tasks.py` | Pub/Sub step-level progress + LLM confidence histogram |
| `be/app/tasks/exploit_tasks.py` | EXPLOIT_ATTEMPTS_TOTAL metric |
| `be/app/services/ai/gateway.py` | LLM_REQUESTS_TOTAL + LLM_LATENCY_SECONDS |
| `be/app/services/ai/cwe_mapper.py` | Dùng prompt_registry ("cwe_mapping_batch") |
| `be/app/services/ai/cvss_scorer.py` | Dùng prompt_registry ("cvss_scoring_batch") |
| `be/app/services/ai/risk_prioritizer.py` | Dùng prompt_registry ("risk_prioritization_batch") |
| `be/app/services/ai/false_positive.py` | Dùng prompt_registry ("false_positive_batch") |
| `be/app/services/ai/remediation.py` | Dùng prompt_registry ("remediation_batch") |
| `be/app/services/ai/patch_generator.py` | Dùng prompt_registry ("patch_generation") |
| `be/app/services/ai/patch_validator.py` | PATCH_GENERATION_TOTAL metric |
| `be/app/services/ai/prompt_registry.py` | +5 batch variant templates |
| `be/app/api/v1/routers/auth.py` | AUTH_FAILURES_TOTAL metric |
| `be/app/api/v1/routers/scans.py` | DELETE alias endpoint |
| `be/app/api/v1/routers/evaluations.py` | **Mới** — 3 endpoints (POST/GET/{id}, POST/suite/run) |
| `be/app/main.py` | Wire evaluations router |
| `docker-compose.yml` | +grafana + otel-collector services |
| `infra/otel-collector/otel-collector.yml` | **Mới** — OTel Collector config |
| `docs/system-flow.md` | Cập nhật 100%, observability, new API endpoints |
