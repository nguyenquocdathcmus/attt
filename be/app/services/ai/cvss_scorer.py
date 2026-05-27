import logging

from app.services.ai.ollama_client import generate

logger = logging.getLogger(__name__)

# CVSS v3.1 base score defaults by severity when LLM is skipped
_SEVERITY_DEFAULTS: dict[str, tuple[float, str]] = {
    "Critical": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "High":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Medium":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Low":      (2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "Info":     (0.0, ""),
}

_LLM_SEVERITIES = {"Critical", "High", "Medium"}


def _build_batch_prompt(findings: list[dict]) -> str:
    from app.services.ai.prompt_registry import get_prompt
    items = []
    for i, f in enumerate(findings):
        ev = f.get("evidence") or {}
        items.append(
            f'{i}: title="{f.get("title")}" severity={f.get("severity")} '
            f'cwe={f.get("cwe", "N/A")} param="{ev.get("param", "N/A")}" '
            f'auth_required={ev.get("auth_required", False)}'
        )
    return get_prompt("cvss_scoring_batch").render(listing="\n".join(items))



def score(findings: list[dict]) -> list[dict]:
    """Assign cvss_score and cvss_vector to each finding."""
    # Apply severity-based defaults first
    for f in findings:
        sev = f.get("severity", "Info")
        default_score, default_vector = _SEVERITY_DEFAULTS.get(sev, (0.0, ""))
        f.setdefault("cvss_score", default_score)
        f.setdefault("cvss_vector", default_vector)

    llm_targets = [
        (i, f) for i, f in enumerate(findings)
        if f.get("severity") in _LLM_SEVERITIES
    ]
    if not llm_targets:
        return findings

    try:
        from app.schemas.ai_output import CVSSItem, parse_llm_json_list

        llm_input = [f for _, f in llm_targets]
        raw = generate(_build_batch_prompt(llm_input))
        items = parse_llm_json_list(raw, CVSSItem)
        result_map = {item.index: item for item in items}

        for llm_idx, (_, f) in enumerate(llm_targets):
            item = result_map.get(llm_idx)
            if item:
                f["cvss_score"] = item.score
                f["cvss_vector"] = item.vector

    except Exception as exc:
        logger.warning("CVSS batch scoring failed: %s", exc)

    return findings
