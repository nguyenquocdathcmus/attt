"""
Prometheus application metrics registry.

Centralises all Counter / Histogram / Gauge definitions so every module
imports from one place. The existing prometheus-fastapi-instrumentator
already handles HTTP latency/request-count; we extend it with domain metrics.

If prometheus_client is not installed, all metrics are replaced with
no-op stubs so the rest of the codebase imports cleanly.

Usage:
    from app.core.metrics import SCAN_TOTAL, LLM_LATENCY_SECONDS
    SCAN_TOTAL.labels(status="complete").inc()
    with LLM_LATENCY_SECONDS.labels(model="llama3", step="cwe_mapping").time():
        ...
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── Stub classes used when prometheus_client is absent ────────────────────────

class _NoOpLabels:
    def inc(self, amount: float = 1) -> None: ...
    def dec(self, amount: float = 1) -> None: ...
    def set(self, value: float) -> None: ...
    def observe(self, value: float) -> None: ...
    def time(self) -> object:
        from contextlib import contextmanager

        @contextmanager
        def _noop():
            yield

        return _noop()


class _NoOpMetric:
    def labels(self, **kw: object) -> _NoOpLabels:
        return _NoOpLabels()

    def inc(self, amount: float = 1) -> None: ...
    def dec(self, amount: float = 1) -> None: ...
    def set(self, value: float) -> None: ...
    def observe(self, value: float) -> None: ...


# ── Real metrics (only when prometheus_client available) ──────────────────────

try:
    from prometheus_client import Counter, Histogram, Gauge

    # ── Scan metrics ──────────────────────────────────────────────────────────
    SCAN_TOTAL = Counter(
        "attt_scan_total",
        "Total scans by status",
        ["status"],           # queued | running | complete | failed | cancelled
    )

    SCAN_DURATION_SECONDS = Histogram(
        "attt_scan_duration_seconds",
        "Full scan duration from queue to complete",
        ["scanner"],          # zap | nikto | all
        buckets=(30, 60, 120, 300, 600, 1200, 3600),
    )

    SCAN_FINDINGS_TOTAL = Counter(
        "attt_scan_findings_total",
        "Findings discovered per scan",
        ["severity"],         # info | low | medium | high | critical
    )

    # ── AI pipeline metrics ───────────────────────────────────────────────────
    LLM_REQUESTS_TOTAL = Counter(
        "attt_llm_requests_total",
        "LLM calls by step and outcome",
        ["step", "outcome"],  # step=cwe_mapping|… outcome=cache_hit|success|retry|error
    )

    LLM_LATENCY_SECONDS = Histogram(
        "attt_llm_latency_seconds",
        "LLM generation latency",
        ["model", "step"],
        buckets=(0.5, 1, 2, 5, 10, 30, 60, 120),
    )

    LLM_CONFIDENCE_HISTOGRAM = Histogram(
        "attt_llm_confidence",
        "AI confidence scores for findings",
        ["tier"],             # high | medium | low | very_low
        buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
    )

    PROMPT_USAGE = Counter(
        "attt_prompt_usage_total",
        "Prompt template renders by name and version",
        ["prompt", "version"],
    )

    # ── RAG metrics ───────────────────────────────────────────────────────────
    RAG_RETRIEVAL_LATENCY_SECONDS = Histogram(
        "attt_rag_retrieval_latency_seconds",
        "Time to retrieve and rerank RAG chunks",
        buckets=(0.05, 0.1, 0.2, 0.5, 1, 2, 5),
    )

    RAG_CHUNKS_RETURNED = Histogram(
        "attt_rag_chunks_returned",
        "Number of chunks returned per RAG query",
        buckets=(1, 2, 3, 5, 8, 12, 20),
    )

    # ── Exploit metrics ───────────────────────────────────────────────────────
    EXPLOIT_ATTEMPTS_TOTAL = Counter(
        "attt_exploit_attempts_total",
        "Exploit probe attempts by type and outcome",
        ["exploit_type", "outcome"],   # outcome=confirmed|denied|error|policy_blocked
    )

    # ── Patch metrics ─────────────────────────────────────────────────────────
    PATCH_GENERATION_TOTAL = Counter(
        "attt_patch_generation_total",
        "Patch generation outcomes",
        ["outcome"],          # generated | validated | rejected | error
    )

    # ── Auth / security metrics ───────────────────────────────────────────────
    AUTH_FAILURES_TOTAL = Counter(
        "attt_auth_failures_total",
        "Authentication failures by reason",
        ["reason"],           # bad_credentials | token_expired | blocked | rate_limited
    )

    RATE_LIMIT_HITS_TOTAL = Counter(
        "attt_rate_limit_hits_total",
        "Rate limit rejections by endpoint",
        ["endpoint"],
    )

    PROMPT_INJECTION_DETECTIONS_TOTAL = Counter(
        "attt_prompt_injection_detections_total",
        "Prompt injection pattern detections by pattern name",
        ["pattern"],
    )

    # ── System gauges ─────────────────────────────────────────────────────────
    ACTIVE_SCANS_GAUGE = Gauge(
        "attt_active_scans",
        "Number of scans currently in running state",
    )

    logger.info("Prometheus metrics registry initialised")

except ImportError:
    logger.warning("prometheus_client not installed — metrics are no-ops")

    SCAN_TOTAL = _NoOpMetric()                        # type: ignore[assignment]
    SCAN_DURATION_SECONDS = _NoOpMetric()             # type: ignore[assignment]
    SCAN_FINDINGS_TOTAL = _NoOpMetric()               # type: ignore[assignment]
    LLM_REQUESTS_TOTAL = _NoOpMetric()                # type: ignore[assignment]
    LLM_LATENCY_SECONDS = _NoOpMetric()               # type: ignore[assignment]
    LLM_CONFIDENCE_HISTOGRAM = _NoOpMetric()          # type: ignore[assignment]
    PROMPT_USAGE = _NoOpMetric()                      # type: ignore[assignment]
    RAG_RETRIEVAL_LATENCY_SECONDS = _NoOpMetric()     # type: ignore[assignment]
    RAG_CHUNKS_RETURNED = _NoOpMetric()               # type: ignore[assignment]
    EXPLOIT_ATTEMPTS_TOTAL = _NoOpMetric()            # type: ignore[assignment]
    PATCH_GENERATION_TOTAL = _NoOpMetric()            # type: ignore[assignment]
    AUTH_FAILURES_TOTAL = _NoOpMetric()               # type: ignore[assignment]
    RATE_LIMIT_HITS_TOTAL = _NoOpMetric()             # type: ignore[assignment]
    PROMPT_INJECTION_DETECTIONS_TOTAL = _NoOpMetric() # type: ignore[assignment]
    ACTIVE_SCANS_GAUGE = _NoOpMetric()                # type: ignore[assignment]
