def build_prompt(task: str, context: list[dict], findings: list[dict]) -> str:
    lines = [f"Task: {task}", "Context:"]
    for item in context:
        lines.append(f"- {item}")
    lines.append("Findings:")
    for finding in findings:
        lines.append(f"- {finding}")
    return "\n".join(lines)
