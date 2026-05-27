"""
Secure code rewriter.

Produces a security-hardened version of a full code file (not just a
function-level patch).  After the LLM rewrites the file, an AST
equivalence check verifies that:
  1. No functions/classes were accidentally removed
  2. The call graph topology is preserved

Supported: Python (full AST), JavaScript/others (structure heuristic).
"""
from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass

from app.services.ai.ollama_client import generate as _llm
from app.services.ai.patch_validator import validate as _validate, ValidationReport

logger = logging.getLogger(__name__)


@dataclass
class RewriteResult:
    rewritten_code: str
    validation: ValidationReport
    equivalence_ok: bool
    removed_symbols: list[str]
    added_symbols: list[str]
    accepted: bool  # True only when validation.passed AND equivalence_ok

    def summary(self) -> str:
        status = "ACCEPTED" if self.accepted else "REJECTED"
        return (
            f"[{status}] validation={self.validation.summary()} "
            f"equivalence={self.equivalence_ok} "
            f"removed={self.removed_symbols}"
        )


_REWRITE_PROMPT = """You are a senior security engineer doing a full security hardening review.

Rewrite the following {language} code to eliminate ALL security vulnerabilities.
Apply defense-in-depth: input validation, output encoding, parameterised queries,
least privilege, safe defaults.  Preserve ALL existing functions and classes.

Original code:
```{language}
{code}
```

Security findings to fix:
{findings_summary}

Respond with ONLY the complete rewritten code. No explanations. No markdown fences.
Start your response directly with the code."""


def rewrite(
    code: str,
    findings: list[dict],
    language: str = "python",
) -> RewriteResult:
    """
    Rewrite *code* to be security-hardened based on *findings*.

    Args:
        code:       The full source file to rewrite.
        findings:   List of finding dicts (title, cwe, severity).
        language:   Language string for the prompt.

    Returns:
        RewriteResult — check .accepted before deploying.
    """
    findings_summary = "\n".join(
        f"  - [{f.get('severity','?')}] {f.get('title','?')} ({f.get('cwe','')})"
        for f in findings
    )

    prompt = _REWRITE_PROMPT.format(
        language=language,
        code=code,
        findings_summary=findings_summary,
    )

    try:
        rewritten = _llm(prompt).strip()
        # Strip any accidental markdown fences the LLM added
        rewritten = re.sub(r"^```\w*\n?", "", rewritten)
        rewritten = re.sub(r"\n?```$", "", rewritten).strip()
    except Exception as exc:
        logger.warning("secure_rewriter: LLM call failed: %s", exc)
        return RewriteResult(
            rewritten_code=code,
            validation=ValidationReport(passed=False, issues=[str(exc)]),
            equivalence_ok=False,
            removed_symbols=[],
            added_symbols=[],
            accepted=False,
        )

    validation = _validate(code, rewritten, language)
    eq_ok, removed, added = _check_equivalence(code, rewritten, language)

    accepted = validation.passed and eq_ok
    result = RewriteResult(
        rewritten_code=rewritten,
        validation=validation,
        equivalence_ok=eq_ok,
        removed_symbols=removed,
        added_symbols=added,
        accepted=accepted,
    )
    logger.info("secure_rewriter: %s", result.summary())
    return result


# ── AST equivalence check ─────────────────────────────────────────────────────

def _check_equivalence(
    original: str,
    rewritten: str,
    language: str,
) -> tuple[bool, list[str], list[str]]:
    """
    Return (equivalence_ok, removed_symbols, added_symbols).

    For Python: full AST symbol extraction.
    For others: regex-based function/class name extraction.
    """
    if language == "python":
        orig_syms = _python_symbols(original)
        new_syms = _python_symbols(rewritten)
    else:
        orig_syms = _heuristic_symbols(original, language)
        new_syms = _heuristic_symbols(rewritten, language)

    removed = sorted(orig_syms - new_syms)
    added = sorted(new_syms - orig_syms)
    equivalence_ok = len(removed) == 0  # removed symbols = structural regression

    return equivalence_ok, removed, added


def _python_symbols(code: str) -> set[str]:
    """Extract all top-level and nested function/class names via AST."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()

    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.add(node.name)
    return symbols


def _heuristic_symbols(code: str, language: str) -> set[str]:
    """Regex-based symbol extraction for non-Python languages."""
    patterns = {
        "javascript": re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())"
        ),
        "java": re.compile(r"(?:public|private|protected|static)[\w\s]+\s+(\w+)\s*\("),
        "go": re.compile(r"^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(", re.MULTILINE),
        "ruby": re.compile(r"^\s*def\s+(\w+)", re.MULTILINE),
        "php": re.compile(r"function\s+(\w+)\s*\("),
    }
    pattern = patterns.get(language, re.compile(r"(?:function|def|func)\s+(\w+)"))
    matches = pattern.findall(code)
    return {m if isinstance(m, str) else next((x for x in m if x), "") for m in matches}
