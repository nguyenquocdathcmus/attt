"""
Framework-aware patch generator.

Detects the code language/framework from the finding evidence and generates
a targeted security patch using the LLM.  All output is validated against
the PatchOutput Pydantic schema before being returned.
"""
from __future__ import annotations

import logging
import re

from app.schemas.ai_output import PatchOutput, parse_llm_json
from app.services.ai.ollama_client import generate as _llm

logger = logging.getLogger(__name__)

# ── Framework / language detection ───────────────────────────────────────────

_FRAMEWORK_HINTS = {
    "django":      r"\b(?:django|request\.GET|request\.POST|HttpResponse)\b",
    "flask":       r"\b(?:flask|request\.args|render_template|Blueprint)\b",
    "fastapi":     r"\b(?:fastapi|Depends|APIRouter|HTTPException)\b",
    "express":     r"\b(?:express|req\.query|res\.send|app\.get)\b",
    "spring":      r"\b(?:@Controller|@RequestParam|@GetMapping|@Service)\b",
    "rails":       r"\b(?:params\[|render\s*:json|ActiveRecord)\b",
    "laravel":     r"\b(?:\$request->input|Route::|Eloquent)\b",
    "sqlalchemy":  r"\b(?:session\.query|Column|ForeignKey|relationship)\b",
}

_LANG_HINTS = {
    "python": r"\b(?:def |import |print\(|class |:$)",
    "javascript": r"\b(?:function\s|const\s|let\s|var\s|=>)\b",
    "java": r"\b(?:public\s+class|import\s+java|@Override|System\.out)\b",
    "php": r"<\?php|\$[a-z_]+\s*=",
    "ruby": r"\b(?:def\s|end\b|puts\s|require\s)",
    "go": r"\b(?:func\s|package\s|import\s\(|:=)\b",
    "csharp": r"\b(?:using\s+System|namespace\s|public\s+class|Console\.Write)\b",
}


def _detect_context(code_snippet: str) -> tuple[str, str]:
    """Return (language, framework) best-guess for a code snippet."""
    lang = "unknown"
    framework = "generic"

    for l_name, pattern in _LANG_HINTS.items():
        if re.search(pattern, code_snippet, re.MULTILINE):
            lang = l_name
            break

    for fw_name, pattern in _FRAMEWORK_HINTS.items():
        if re.search(pattern, code_snippet, re.IGNORECASE):
            framework = fw_name
            break

    return lang, framework


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(finding: dict, code_snippet: str, lang: str, framework: str) -> str:
    from app.services.ai.prompt_registry import get_prompt
    finding_text = (
        f'Title: {finding.get("title", "Vulnerability")}\n'
        f'CWE: {finding.get("cwe", "Unknown")}\n'
        f'Severity: {finding.get("severity", "Unknown")}\n'
        f'CVSS: {finding.get("cvss_vector", "N/A")}\n'
        f'Description: {str(finding.get("description", ""))[:400]}'
    )
    return get_prompt("patch_generation").render(
        language=lang,
        framework=framework,
        finding_text=finding_text,
        code_snippet=code_snippet,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_patch(finding: dict, code_snippet: str) -> PatchOutput | None:
    """
    Generate a security patch for *code_snippet* given *finding* context.

    Returns a validated PatchOutput or None if the LLM output is invalid.
    """
    if not code_snippet or not code_snippet.strip():
        logger.warning("patch_generator: empty code snippet for finding %s", finding.get("id"))
        return None

    lang, framework = _detect_context(code_snippet)
    prompt = _build_prompt(finding, code_snippet, lang, framework)

    try:
        raw = _llm(prompt, response_format="json")
        result = parse_llm_json(raw, PatchOutput)
        logger.info(
            "patch_generator: ok finding=%s lang=%s fw=%s confidence=%.2f",
            finding.get("id"), lang, framework, result.confidence,
        )
        return result
    except Exception as exc:
        logger.warning("patch_generator: LLM failed for finding %s: %s", finding.get("id"), exc)
        return None
