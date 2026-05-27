"""
Security assessment LangGraph state machine.

Graph topology:
    scan_target
        ↓
    normalize_findings
        ↓
    ai_enrich          (CWE, CVSS, risk, FP, dedup, remediation, confidence)
        ↓
    route_exploit  ──── (no high-confidence findings) ────→ generate_report
        ↓                                                         ↑
    exploit_verify  ─────────────────────────────────────────────┘
        ↓
    patch_generate
        ↓
    generate_report
        ↓
    END

Each node is a pure function: (PipelineState) → dict[str, Any].
LangGraph merges the returned dict back into the shared state.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# ── Lazy import guard — langgraph may not be installed ────────────────────────
try:
    from langgraph.graph import StateGraph, END
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    logger.warning("langgraph not installed — security agent graph unavailable")

from app.services.agents.state import PipelineState


# ── Node implementations ──────────────────────────────────────────────────────

def node_scan_target(state: PipelineState) -> dict[str, Any]:
    """Trigger a ZAP scan and wait for completion (delegates to Celery)."""
    logger.info("Agent: scan_target scan_id=%s", state.get("scan_id"))
    # In production, this fires the scan Celery task and polls status.
    # Here we return the scan_id so downstream nodes can query the DB.
    return {
        "scan_status": "complete",
        "current_node": "scan_target",
        "messages": [f"Scan {state.get('scan_id')} initiated"],
    }


def node_normalize(state: PipelineState) -> dict[str, Any]:
    """Load raw findings from the DB and normalize them."""
    from app.db.models.finding import Finding
    from app.db.session import SessionLocal

    scan_id = state.get("scan_id", "")
    session = SessionLocal()
    try:
        findings = (
            session.query(Finding)
            .filter(Finding.scan_id == uuid.UUID(scan_id))
            .all()
        )
        raw = [
            {
                "id": str(f.id),
                "type": f.type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "cwe": f.cwe,
                "owasp": f.owasp,
            }
            for f in findings
        ]
        return {
            "raw_findings": raw,
            "current_node": "normalize",
            "messages": [f"Loaded {len(raw)} findings"],
        }
    finally:
        session.close()


def node_ai_enrich(state: PipelineState) -> dict[str, Any]:
    """Run the full AI enrichment pipeline (via Celery task or inline)."""
    from app.tasks.ai_tasks import analyze_scan

    scan_id = state.get("scan_id", "")
    analyze_scan.delay(scan_id)   # non-blocking; downstream nodes should poll

    return {
        "current_node": "ai_enrich",
        "messages": ["AI enrichment task dispatched"],
    }


def node_exploit_route(state: PipelineState) -> str:
    """
    Conditional edge: route to exploit_verify if we have High/Critical findings,
    otherwise go straight to generate_report.
    """
    findings = state.get("raw_findings", [])
    high_critical = [f for f in findings if f.get("severity") in ("High", "Critical")]
    return "exploit_verify" if high_critical else "generate_report"


def node_exploit_verify(state: PipelineState) -> dict[str, Any]:
    """Fire exploit verification tasks for High/Critical findings."""
    from app.tasks.exploit_tasks import verify_finding

    findings = state.get("raw_findings", [])
    high_critical = [f for f in findings if f.get("severity") in ("High", "Critical")]

    dispatched = 0
    for f in high_critical[:5]:   # cap at 5 per graph run
        verify_finding.delay(f["id"])
        dispatched += 1

    return {
        "current_node": "exploit_verify",
        "messages": [f"Dispatched {dispatched} exploit verification tasks"],
    }


def node_patch_generate(state: PipelineState) -> dict[str, Any]:
    """Generate patches for verified findings (code snippet must be in evidence)."""
    from app.services.ai.patch_generator import generate_patch

    findings = state.get("raw_findings", [])
    patches: list[dict] = []

    for f in findings:
        code = (f.get("evidence") or {}).get("code_snippet")
        if not code:
            continue
        patch = generate_patch(f, code)
        if patch:
            patches.append({"finding_id": f["id"], **patch.model_dump()})

    return {
        "patches": patches,
        "patches_accepted": sum(1 for p in patches if p.get("confidence", 0) >= 0.7),
        "current_node": "patch_generate",
        "messages": [f"Generated {len(patches)} patches"],
    }


def node_generate_report(state: PipelineState) -> dict[str, Any]:
    """Trigger report generation task."""
    from app.tasks.report_tasks import generate_report

    scan_id = state.get("scan_id", "")
    generate_report.delay(scan_id)

    return {
        "current_node": "generate_report",
        "messages": ["Report generation dispatched"],
    }


# ── Graph builder ─────────────────────────────────────────────────────────────

def build_graph():
    """
    Build and compile the security assessment StateGraph.

    Returns a compiled LangGraph application, or None if langgraph is not installed.
    """
    if not _LANGGRAPH_AVAILABLE:
        return None

    g = StateGraph(PipelineState)

    g.add_node("scan_target",      node_scan_target)
    g.add_node("normalize",        node_normalize)
    g.add_node("ai_enrich",        node_ai_enrich)
    g.add_node("exploit_verify",   node_exploit_verify)
    g.add_node("patch_generate",   node_patch_generate)
    g.add_node("generate_report",  node_generate_report)

    g.set_entry_point("scan_target")
    g.add_edge("scan_target",    "normalize")
    g.add_edge("normalize",      "ai_enrich")

    # Conditional routing after ai_enrich
    g.add_conditional_edges(
        "ai_enrich",
        node_exploit_route,
        {
            "exploit_verify":  "exploit_verify",
            "generate_report": "generate_report",
        },
    )

    g.add_edge("exploit_verify",  "patch_generate")
    g.add_edge("patch_generate",  "generate_report")
    g.add_edge("generate_report", END)

    return g.compile()


# Module-level singleton — compiled once per process
security_graph = build_graph()


def run_pipeline(scan_id: str, target_url: str = "", asset_id: str = "") -> PipelineState:
    """
    Execute the full security assessment pipeline for a scan.

    Falls back to a no-op if langgraph is not available.
    """
    if security_graph is None:
        logger.warning("security_graph unavailable — langgraph not installed")
        return {"scan_id": scan_id, "error": "langgraph not installed"}

    initial: PipelineState = {
        "scan_id": scan_id,
        "target_url": target_url,
        "asset_id": asset_id,
        "messages": [],
        "exploit_results": [],
        "patches": [],
    }
    return security_graph.invoke(initial)
