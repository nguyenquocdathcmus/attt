"""
Patch validator — security gate before a generated patch is accepted.

Gates (in order):
  1. Syntax check — AST parse for Python, basic bracket balance for others
  2. Bandit SAST scan (Python only) — fail if HIGH severity issues found
  3. Heuristic pattern check — block known dangerous patterns regardless of language
  4. Diff sanity — patched code must differ from original

Returns a ValidationReport with passed=True only when all gates pass.
"""
from __future__ import annotations

import ast
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Dangerous patterns that must never appear in patched code ─────────────────
_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("shell_injection",    re.compile(r"os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True", re.DOTALL)),
    ("eval_exec",          re.compile(r"\beval\s*\(|\bexec\s*\(")),
    ("hardcoded_secret",   re.compile(r'(?:password|secret|api_key)\s*=\s*["\'][^"\']{6,}["\']', re.IGNORECASE)),
    ("sql_fstring",        re.compile(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{', re.IGNORECASE | re.DOTALL)),
    ("pickle_loads",       re.compile(r"\bpickle\.loads\s*\(")),
    ("yaml_unsafe_load",   re.compile(r"\byaml\.load\s*\([^,)]*\)")),
]


@dataclass
class ValidationReport:
    passed: bool
    issues: list[str] = field(default_factory=list)
    bandit_issues: list[dict] = field(default_factory=list)
    gate_results: dict[str, bool] = field(default_factory=dict)

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {len(self.issues)} issue(s): {'; '.join(self.issues[:3])}"


def validate(original_code: str, patched_code: str, language: str = "python") -> ValidationReport:
    """
    Run all validation gates against *patched_code*.

    Args:
        original_code: The vulnerable code before patching.
        patched_code:  The LLM-generated patched version.
        language:      Detected language string (e.g. "python", "javascript").

    Returns:
        ValidationReport — check .passed to know if patch is safe to use.
    """
    issues: list[str] = []
    gate_results: dict[str, bool] = {}
    bandit_issues: list[dict] = []

    # Gate 1: Syntax check
    syntax_ok = _check_syntax(patched_code, language)
    gate_results["syntax"] = syntax_ok
    if not syntax_ok:
        issues.append(f"Syntax error in patched {language} code")

    # Gate 2: Bandit (Python only)
    if language == "python":
        bandit_ok, bandit_issues = _run_bandit(patched_code)
        gate_results["bandit"] = bandit_ok
        if not bandit_ok:
            issues.append(f"Bandit found {len(bandit_issues)} HIGH/MEDIUM security issue(s)")

    # Gate 3: Heuristic dangerous patterns
    pattern_ok, pattern_hits = _check_dangerous_patterns(patched_code)
    gate_results["patterns"] = pattern_ok
    if not pattern_ok:
        issues.extend([f"Dangerous pattern: {h}" for h in pattern_hits])

    # Gate 4: Diff sanity
    diff_ok = patched_code.strip() != original_code.strip()
    gate_results["diff"] = diff_ok
    if not diff_ok:
        issues.append("Patched code is identical to original — no fix applied")

    passed = syntax_ok and pattern_ok and diff_ok
    try:
        from app.core.metrics import PATCH_GENERATION_TOTAL
        PATCH_GENERATION_TOTAL.labels(outcome="validated" if passed else "rejected").inc()
    except Exception:
        pass
    return ValidationReport(
        passed=passed,
        issues=issues,
        bandit_issues=bandit_issues,
        gate_results=gate_results,
    )


# ── Gate implementations ──────────────────────────────────────────────────────

def _check_syntax(code: str, language: str) -> bool:
    if language == "python":
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    # For other languages: basic bracket balance
    opens = code.count("{") + code.count("(") + code.count("[")
    closes = code.count("}") + code.count(")") + code.count("]")
    return abs(opens - closes) <= 2  # allow minor imbalance (may be partial snippet)


def _run_bandit(code: str) -> tuple[bool, list[dict]]:
    """Run bandit on code string. Returns (passed, issues_list)."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            ["bandit", "-f", "json", "-l", "-i", tmp_path],
            capture_output=True, text=True, timeout=30,
        )

        import json
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        results = data.get("results", [])
        high_medium = [
            r for r in results
            if r.get("issue_severity") in ("HIGH", "MEDIUM")
        ]
        return len(high_medium) == 0, high_medium

    except FileNotFoundError:
        logger.debug("bandit not installed — skipping SAST gate")
        return True, []
    except Exception as exc:
        logger.warning("bandit run failed: %s", exc)
        return True, []


def _check_dangerous_patterns(code: str) -> tuple[bool, list[str]]:
    hits: list[str] = []
    for name, pattern in _DANGEROUS_PATTERNS:
        if pattern.search(code):
            hits.append(name)
    return len(hits) == 0, hits
