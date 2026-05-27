"""
AI output confidence scorer.

Aggregates multiple signals from the AI pipeline to produce a single
ai_confidence score (0.0–1.0) per finding.

Signals (weighted equally):
  - false_positive_score (inverted: low FP = high confidence)
  - risk_score normalization
  - CVSS score presence + reasonableness
  - CWE mapping presence
  - Remediation quality (has steps)

Tiers:
  HIGH   ≥ 0.70
  MEDIUM 0.40–0.69
  LOW    < 0.40
"""
from __future__ import annotations

from typing import Literal

ConfidenceTier = Literal["HIGH", "MEDIUM", "LOW"]


def compute_confidence(finding: dict) -> float:
    """Return a confidence score 0.0–1.0 for a single finding dict."""
    signals: list[float] = []

    # 1. False positive score (inverted)
    fp = finding.get("false_positive_score")
    if fp is not None:
        signals.append(max(0.0, min(1.0, 1.0 - float(fp))))

    # 2. Risk score (already 0–1)
    risk = finding.get("risk_score")
    if risk is not None:
        signals.append(max(0.0, min(1.0, float(risk))))

    # 3. CVSS presence — LLM produced structured output
    cvss = finding.get("cvss_score")
    if cvss is not None:
        # Map CVSS 0–10 → 0.3–1.0 range (presence alone is a positive signal)
        signals.append(0.3 + min(float(cvss) / 10.0 * 0.7, 0.7))
    else:
        signals.append(0.2)

    # 4. CWE mapping
    signals.append(0.85 if finding.get("cwe") else 0.15)

    # 5. Remediation quality
    rem = finding.get("remediation") or {}
    steps = rem.get("steps", [])
    if isinstance(steps, list) and len(steps) >= 2:
        signals.append(0.9)
    elif rem.get("summary"):
        signals.append(0.5)
    else:
        signals.append(0.1)

    score = sum(signals) / len(signals) if signals else 0.5
    return round(max(0.0, min(1.0, score)), 3)


def get_tier(score: float) -> ConfidenceTier:
    if score >= 0.70:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    return "LOW"


def enrich_with_confidence(findings: list[dict]) -> list[dict]:
    """Add ai_confidence and ai_confidence_tier to each finding in-place."""
    for f in findings:
        score = compute_confidence(f)
        f["ai_confidence"] = score
        f["ai_confidence_tier"] = get_tier(score)
    return findings
