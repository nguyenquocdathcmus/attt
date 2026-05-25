import json
import logging

from app.services.ai.ollama_client import generate as _llm

logger = logging.getLogger(__name__)

# Only generate full LLM remediation for High/Critical; others get a fast template
_LLM_SEVERITIES = {"Critical", "High"}


def _build_batch_prompt(findings: list[dict]) -> str:
    items = []
    for i, f in enumerate(findings):
        evidence = f.get("evidence") or {}
        items.append(
            f'{i}: title="{f.get("title")}" cwe={f.get("cwe","N/A")} '
            f'owasp={f.get("owasp","N/A")} param="{evidence.get("param","N/A")}" '
            f'solution_hint="{str(evidence.get("solution",""))[:120]}"'
        )
    listing = "\n".join(items)
    return f"""You are a security engineer. Provide remediation for each vulnerability below.

Findings:
{listing}

Respond with ONLY a JSON array, no markdown:
[
  {{
    "index": 0,
    "summary": "<one sentence fix>",
    "steps": ["<step 1>", "<step 2>", "<step 3>"],
    "references": ["<OWASP or CWE link>"]
  }},
  ...
]"""


def _template(finding: dict) -> dict:
    sev = finding.get("severity", "Low")
    title = finding.get("title", "vulnerability")
    return {
        "summary": f"Address {title} by applying the relevant security control.",
        "steps": [
            "Identify all code paths that process the affected input or output.",
            "Apply input validation, output encoding, or the appropriate security header.",
            "Test the fix in a staging environment before deploying.",
        ],
        "references": [f"https://owasp.org/www-project-top-ten/" if sev in ("High", "Critical") else ""],
    }


def _batch_remediate(findings: list[dict]) -> dict[int, dict]:
    """Returns {original_index: remediation_dict}."""
    try:
        raw = _llm(_build_batch_prompt(findings))
        cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        results = json.loads(cleaned)
        return {item["index"]: item for item in results}
    except Exception as exc:
        logger.warning("Batch remediation LLM failed: %s", exc)
        return {}


def generate_for_finding(finding: dict) -> dict:
    """Single-finding path — uses template for non-critical to avoid LLM overhead."""
    if finding.get("severity") not in _LLM_SEVERITIES:
        return _template(finding)
    result = _batch_remediate([finding])
    return result.get(0, _template(finding))


def generate(findings: list[dict]) -> list[dict]:
    """Batch path — one LLM call for all High/Critical, templates for rest."""
    llm_targets = {i: f for i, f in enumerate(findings) if f.get("severity") in _LLM_SEVERITIES}
    llm_input = list(llm_targets.values())

    llm_results: dict[int, dict] = {}
    if llm_input:
        raw_map = _batch_remediate(llm_input)
        # re-map LLM indices back to original indices
        for llm_idx, orig_idx in enumerate(llm_targets.keys()):
            if llm_idx in raw_map:
                llm_results[orig_idx] = raw_map[llm_idx]

    output = []
    for i, f in enumerate(findings):
        rem = llm_results.get(i, _template(f))
        output.append({"finding_id": f.get("id"), **rem})
    return output
