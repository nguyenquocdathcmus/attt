from app.services.ai.ollama_client import generate

_MAX_FINDINGS_IN_PROMPT = 20


def generate_summary(findings: list[dict]) -> str:
    if not findings:
        return "No findings to summarize."

    # Sort by risk_score desc so the most critical appear first in prompt
    sorted_f = sorted(findings, key=lambda f: f.get("risk_score") or 0, reverse=True)
    top = sorted_f[:_MAX_FINDINGS_IN_PROMPT]

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    counts_str = ", ".join(f"{v} {k}" for k, v in severity_counts.items())
    lines = [
        f"- [{f.get('severity')}] {f.get('title')} "
        f"(CWE: {f.get('cwe') or 'N/A'}, risk: {f.get('risk_score') or 'N/A'})"
        for f in top
    ]
    findings_str = "\n".join(lines)

    prompt = (
        "You are a security analyst writing for a non-technical executive audience.\n"
        "Write a concise summary (max 6 sentences) covering: overall risk level, "
        "the most critical issues, and the recommended next actions.\n"
        "Do not invent vulnerabilities. Base your answer only on the data below.\n\n"
        f"Total findings: {len(findings)} ({counts_str})\n"
        f"Top findings by risk:\n{findings_str}"
    )

    try:
        summary = generate(prompt)
        return summary or "Executive summary pending AI analysis."
    except Exception:
        return "Executive summary pending AI analysis."
