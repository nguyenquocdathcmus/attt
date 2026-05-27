"""
Pipeline state schema for the LangGraph security assessment agent.

PipelineState is the single shared state object that flows through
every node in the StateGraph.  Each node reads what it needs and writes
its output fields back — LangGraph merges them via the Annotated reducer.
"""
from __future__ import annotations

from typing import Annotated, TypedDict
import operator


class PipelineState(TypedDict, total=False):
    # ── Input ─────────────────────────────────────────────────────────────
    scan_id: str
    asset_id: str
    target_url: str

    # ── Scan phase ────────────────────────────────────────────────────────
    scan_status: str          # "pending" | "running" | "complete" | "failed"
    raw_findings: list[dict]  # normalized output from ZAP/Nikto

    # ── AI enrichment phase ───────────────────────────────────────────────
    enriched_findings: list[dict]  # after CWE, CVSS, risk, FP, dedup, remediation
    ai_confidence_avg: float

    # ── Exploit verification phase ────────────────────────────────────────
    exploit_results: Annotated[list[dict], operator.add]   # accumulates across nodes
    verified_count: int
    high_confidence_exploits: list[dict]

    # ── Patch generation phase ─────────────────────────────────────────────
    patches: Annotated[list[dict], operator.add]
    patches_accepted: int

    # ── Report phase ──────────────────────────────────────────────────────
    report_id: str | None
    report_path: str | None

    # ── Control flow ─────────────────────────────────────────────────────
    error: str | None
    current_node: str
    messages: Annotated[list[str], operator.add]  # audit trail
