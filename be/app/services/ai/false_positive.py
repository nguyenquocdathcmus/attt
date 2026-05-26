import logging

from app.services.ai.ollama_client import generate

logger = logging.getLogger(__name__)


def _build_batch_prompt(findings: list[dict]) -> str:
    items = []
    for i, f in enumerate(findings):
        evidence = f.get("evidence") or {}
        items.append(
            f'{i}: title="{f.get("title")}" confidence={evidence.get("confidence","N/A")} '
            f'evidence="{str(evidence.get("evidence",""))[:80]}"'
        )
    listing = "\n".join(items)
    return f"""You are a security expert reviewing automated scanner results.
Estimate the false positive probability (0.0=definitely real, 1.0=definitely false positive) for each finding.

Findings:
{listing}

Respond with ONLY a JSON array, no markdown:
[{{"index": 0, "false_positive_score": 0.1}}, {{"index": 1, "false_positive_score": 0.7}}, ...]"""


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
