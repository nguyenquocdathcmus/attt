import logging

from app.services.ai.ollama_client import generate

logger = logging.getLogger(__name__)


def _build_batch_prompt(findings: list[dict]) -> str:
    from app.services.ai.prompt_registry import get_prompt
    items = []
    for i, f in enumerate(findings):
        evidence = f.get("evidence") or {}
        items.append(
            f'{i}: title="{f.get("title")}" confidence={evidence.get("confidence","N/A")} '
            f'evidence="{str(evidence.get("evidence",""))[:80]}"'
        )
    return get_prompt("false_positive_batch").render(listing="\n".join(items))


def analyze(findings: list[dict]) -> list[dict]:
    for f in findings:
        f.setdefault("false_positive_score", 0.1)

    if not findings:
        return findings

    try:
        from app.schemas.ai_output import FalsePositiveItem, parse_llm_json_list

        raw = generate(_build_batch_prompt(findings))
        items = parse_llm_json_list(raw, FalsePositiveItem)
        score_map = {item.index: item.false_positive_score for item in items}
        for i, f in enumerate(findings):
            if i in score_map:
                f["false_positive_score"] = score_map[i]
    except Exception as exc:
        logger.warning("Batch FP analysis failed: %s", exc)

    return findings
