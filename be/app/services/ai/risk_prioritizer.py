import logging

from app.services.ai.ollama_client import generate

logger = logging.getLogger(__name__)

_SEVERITY_BASE = {
    "Critical": 0.95,
    "High": 0.80,
    "Medium": 0.55,
    "Low": 0.30,
    "Info": 0.10,
}

# Only run LLM on findings that matter; skip pure informational noise
_LLM_SEVERITIES = {"Critical", "High", "Medium"}


def _build_batch_prompt(findings: list[dict]) -> str:
    items = []
    for i, f in enumerate(findings):
        evidence = f.get("evidence") or {}
        items.append(
            f'{i}: title="{f.get("title")}" severity={f.get("severity")} '
            f'cwe={f.get("cwe","N/A")} url={evidence.get("url","N/A")}'
        )
    listing = "\n".join(items)
    return f"""You are a security expert. Score each finding's exploitability risk from 0.0 to 1.0.

Findings:
{listing}

Respond with ONLY a JSON array indexed by finding number, no markdown:
[{{"index": 0, "risk_score": 0.85}}, {{"index": 1, "risk_score": 0.4}}, ...]"""


def prioritize(findings: list[dict]) -> list[dict]:
    # Apply severity-based defaults first
    for f in findings:
        f.setdefault("risk_score", _SEVERITY_BASE.get(f.get("severity", "Info"), 0.3))

    llm_targets = [f for f in findings if f.get("severity") in _LLM_SEVERITIES]
    if not llm_targets:
        return findings

    try:
        from app.schemas.ai_output import RiskItem, parse_llm_json_list

        raw = generate(_build_batch_prompt(llm_targets))
        items = parse_llm_json_list(raw, RiskItem)
        score_map = {item.index: item.risk_score for item in items}
        for i, f in enumerate(llm_targets):
            if i in score_map:
                f["risk_score"] = score_map[i]
    except Exception as exc:
        logger.warning("Batch risk scoring failed: %s", exc)

    return findings
