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
    from app.services.ai.prompt_registry import get_prompt
    items = []
    for i, f in enumerate(findings):
        evidence = f.get("evidence") or {}
        items.append(
            f'{i}: title="{f.get("title")}" severity={f.get("severity")} '
            f'cwe={f.get("cwe","N/A")} url={evidence.get("url","N/A")}'
        )
    return get_prompt("risk_prioritization_batch").render(listing="\n".join(items))


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
