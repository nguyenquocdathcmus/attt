"""
Agent evaluator — score the quality of a completed pipeline run.

Evaluation dimensions (each 0.0–1.0):
  1. completeness   — fraction of expected output fields present
  2. consistency    — CWE/CVSS/risk cross-check (no contradictions)
  3. confidence     — average ai_confidence_score across findings
  4. exploit_recall — fraction of High/Critical findings that have exploit results
  5. patch_coverage — fraction of exploited findings that have validated patches
  6. fp_calibration — inverse of average fp_score (lower FP = better signal)

Aggregate = weighted average of the six dimensions.

Usage:
    from app.services.agents.evaluator import PipelineEvaluator
    ev = PipelineEvaluator(scan_id=42, db=session)
    report = ev.evaluate()
    print(report.score, report.breakdown)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Weight for each dimension (must sum to 1.0)
_WEIGHTS: dict[str, float] = {
    "completeness": 0.20,
    "consistency": 0.20,
    "confidence": 0.20,
    "exploit_recall": 0.15,
    "patch_coverage": 0.15,
    "fp_calibration": 0.10,
}

assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-6, "Weights must sum to 1.0"


@dataclass
class EvalReport:
    scan_id: int
    score: float                          # weighted aggregate 0.0–1.0
    grade: str                            # A/B/C/D/F
    breakdown: dict[str, float] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "score": round(self.score, 4),
            "grade": self.grade,
            "breakdown": {k: round(v, 4) for k, v in self.breakdown.items()},
            "issues": self.issues,
            "metadata": self.metadata,
        }


def _grade(score: float) -> str:
    if score >= 0.90:
        return "A"
    if score >= 0.75:
        return "B"
    if score >= 0.60:
        return "C"
    if score >= 0.45:
        return "D"
    return "F"


class PipelineEvaluator:
    def __init__(self, scan_id: int, db: Any) -> None:
        self.scan_id = scan_id
        self.db = db

    # ── Public ────────────────────────────────────────────────────────────────

    def evaluate(self) -> EvalReport:
        findings = self._load_findings()
        if not findings:
            return EvalReport(
                scan_id=self.scan_id,
                score=0.0,
                grade="F",
                issues=["No findings found for this scan"],
            )

        exploit_results = self._load_exploit_results()
        breakdown: dict[str, float] = {}
        issues: list[str] = []

        breakdown["completeness"] = self._completeness(findings, issues)
        breakdown["consistency"] = self._consistency(findings, issues)
        breakdown["confidence"] = self._confidence(findings)
        breakdown["exploit_recall"] = self._exploit_recall(findings, exploit_results, issues)
        breakdown["patch_coverage"] = self._patch_coverage(findings, exploit_results, issues)
        breakdown["fp_calibration"] = self._fp_calibration(findings)

        score = sum(_WEIGHTS[k] * v for k, v in breakdown.items())

        return EvalReport(
            scan_id=self.scan_id,
            score=score,
            grade=_grade(score),
            breakdown=breakdown,
            issues=issues,
            metadata={
                "total_findings": len(findings),
                "high_critical": sum(
                    1 for f in findings
                    if (f.get("severity") or "").lower() in ("high", "critical")
                ),
                "exploit_results": len(exploit_results),
            },
        )

    # ── Dimensions ────────────────────────────────────────────────────────────

    _REQUIRED_FIELDS = (
        "title", "severity", "cwe_ids", "cvss_vector", "risk_score",
        "fp_score", "ai_confidence_score", "remediation",
    )

    def _completeness(self, findings: list[dict], issues: list[str]) -> float:
        total = len(findings) * len(self._REQUIRED_FIELDS)
        present = 0
        for f in findings:
            for key in self._REQUIRED_FIELDS:
                val = f.get(key)
                if val is not None and val != "" and val != [] and val != {}:
                    present += 1
        score = present / total if total else 0.0
        if score < 0.8:
            issues.append(
                f"Completeness {score:.0%}: many required AI fields are missing"
            )
        return score

    def _consistency(self, findings: list[dict], issues: list[str]) -> float:
        """Check that severity/CVSS/risk don't contradict each other."""
        ok = 0
        checked = 0
        for f in findings:
            severity = (f.get("severity") or "").lower()
            risk = f.get("risk_score")
            cvss = f.get("cvss_score")
            if risk is None or severity == "":
                continue
            checked += 1
            # High/Critical should have risk ≥ 0.6
            if severity in ("high", "critical") and risk >= 0.5:
                ok += 1
            elif severity in ("low", "info", "informational") and risk <= 0.5:
                ok += 1
            elif severity in ("medium",) and 0.2 <= risk <= 0.85:
                ok += 1
            else:
                issues.append(
                    f"Finding '{f.get('title', f.get('id'))}': "
                    f"severity={severity} conflicts with risk_score={risk:.2f}"
                )
        return ok / checked if checked else 1.0

    def _confidence(self, findings: list[dict]) -> float:
        scores = [
            f["ai_confidence_score"]
            for f in findings
            if f.get("ai_confidence_score") is not None
        ]
        return sum(scores) / len(scores) if scores else 0.0

    def _exploit_recall(
        self,
        findings: list[dict],
        exploit_results: list[dict],
        issues: list[str],
    ) -> float:
        high_crit = [
            f for f in findings
            if (f.get("severity") or "").lower() in ("high", "critical")
        ]
        if not high_crit:
            return 1.0  # nothing to exploit — full marks
        exploited_ids = {r.get("finding_id") for r in exploit_results}
        covered = sum(1 for f in high_crit if f.get("id") in exploited_ids)
        score = covered / len(high_crit)
        if score < 0.5:
            issues.append(
                f"Exploit recall {score:.0%}: only {covered}/{len(high_crit)} "
                "High/Critical findings were attempted"
            )
        return score

    def _patch_coverage(
        self,
        findings: list[dict],
        exploit_results: list[dict],
        issues: list[str],
    ) -> float:
        confirmed = [
            r for r in exploit_results
            if r.get("confirmed") or r.get("success")
        ]
        if not confirmed:
            return 1.0  # no confirmed exploits — nothing to patch
        patched_ids = {
            r.get("finding_id")
            for r in confirmed
            if r.get("patch_validated")
        }
        score = len(patched_ids) / len(confirmed)
        if score < 0.5:
            issues.append(
                f"Patch coverage {score:.0%}: most confirmed exploits lack a validated patch"
            )
        return score

    def _fp_calibration(self, findings: list[dict]) -> float:
        scores = [
            f["fp_score"]
            for f in findings
            if f.get("fp_score") is not None
        ]
        if not scores:
            return 0.5  # neutral when no data
        avg_fp = sum(scores) / len(scores)
        return 1.0 - avg_fp  # lower FP score = better calibration

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _load_findings(self) -> list[dict]:
        try:
            from app.db.models.finding import Finding
            rows = (
                self.db.query(Finding)
                .filter(Finding.scan_id == self.scan_id)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "cwe_ids": r.cwe_ids,
                    "cvss_vector": r.cvss_vector,
                    "cvss_score": r.cvss_score,
                    "risk_score": r.risk_score,
                    "fp_score": r.fp_score,
                    "ai_confidence_score": r.ai_confidence_score,
                    "remediation": r.remediation,
                }
                for r in rows
            ]
        except Exception as exc:
            logger.warning("Could not load findings for scan %d: %s", self.scan_id, exc)
            return []

    def _load_exploit_results(self) -> list[dict]:
        try:
            from app.db.models.exploit_result import ExploitResult
            rows = (
                self.db.query(ExploitResult)
                .filter(ExploitResult.scan_id == self.scan_id)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "finding_id": r.finding_id,
                    "confirmed": r.confirmed,
                    "success": getattr(r, "success", r.confirmed),
                    "patch_validated": getattr(r, "patch_validated", False),
                }
                for r in rows
            ]
        except Exception as exc:
            logger.warning("Could not load exploit results for scan %d: %s", self.scan_id, exc)
            return []


# ── Standalone eval test suite ────────────────────────────────────────────────

def run_eval_suite() -> list[dict[str, Any]]:
    """
    Offline eval suite using synthetic data — no DB required.

    Returns a list of test result dicts, each with:
        name, passed, score, issues
    """
    results: list[dict[str, Any]] = []

    def _run(name: str, findings: list[dict], exploits: list[dict]) -> None:
        class _FakeDB:
            pass

        ev = PipelineEvaluator(scan_id=0, db=_FakeDB())
        ev._load_findings = lambda: findings       # type: ignore[method-assign]
        ev._load_exploit_results = lambda: exploits  # type: ignore[method-assign]
        report = ev.evaluate()
        results.append({
            "name": name,
            "passed": report.score >= 0.60,
            "score": round(report.score, 4),
            "grade": report.grade,
            "issues": report.issues,
        })
        status = "PASS" if report.score >= 0.60 else "FAIL"
        logger.info("eval[%s] %s score=%.3f grade=%s", name, status, report.score, report.grade)

    # Test 1: perfect run
    perfect_finding = {
        "id": 1, "title": "SQL Injection", "severity": "critical",
        "cwe_ids": ["CWE-89"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8, "risk_score": 0.95, "fp_score": 0.05,
        "ai_confidence_score": 0.92, "remediation": "Use parameterized queries.",
    }
    perfect_exploit = {"id": 1, "finding_id": 1, "confirmed": True, "success": True, "patch_validated": True}
    _run("perfect_run", [perfect_finding], [perfect_exploit])

    # Test 2: empty findings → grade F
    _run("empty_findings", [], [])

    # Test 3: missing AI fields (low completeness)
    sparse = {"id": 2, "title": "XSS", "severity": "medium",
               "cwe_ids": None, "cvss_vector": None, "cvss_score": None,
               "risk_score": None, "fp_score": None, "ai_confidence_score": None,
               "remediation": None}
    _run("sparse_fields", [sparse], [])

    # Test 4: severity/risk contradiction
    contradicted = {**perfect_finding, "id": 3, "severity": "critical", "risk_score": 0.1}
    _run("severity_risk_contradiction", [contradicted], [])

    # Test 5: good run but no exploit attempts on High/Critical
    _run("no_exploits_on_high", [perfect_finding], [])

    return results
