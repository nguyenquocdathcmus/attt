from app.services.ai.executive_summary import generate_summary


def build_report(findings: list[dict], raw_output: dict | None = None) -> dict:
    # risk_score, false_positive_score, and remediation are already computed
    # by ai_tasks.analyze_scan and stored on each finding — no need to re-run LLM here.
    sorted_findings = sorted(
        findings, key=lambda f: f.get("risk_score") or 0, reverse=True
    )

    return {
        "summary": generate_summary(sorted_findings),
        "findings": sorted_findings,
        "raw_output": raw_output or {},
    }
