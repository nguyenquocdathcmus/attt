RISK_MAP = {
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Info",
    "": "Info",
}


def parse(raw: dict) -> list[dict]:
    alerts = raw.get("alerts", [])
    findings = []

    for alert in alerts:
        risk = alert.get("risk", "Info")
        severity = RISK_MAP.get(risk, risk or "Info")
        cweid = alert.get("cweid")
        wascid = alert.get("wascid")

        findings.append(
            {
                "type": "zap",
                "severity": severity,
                "title": alert.get("alert", "ZAP alert"),
                "description": alert.get("desc") or alert.get("description"),
                "evidence": {
                    "url": alert.get("url") or alert.get("uri"),
                    "param": alert.get("param"),
                    "method": alert.get("method"),
                    "evidence": alert.get("evidence"),
                    "confidence": alert.get("confidence"),
                    "solution": alert.get("solution"),
                },
                "cwe": f"CWE-{cweid}" if cweid and str(cweid) != "0" else None,
                "owasp": f"WASC-{wascid}" if wascid and str(wascid) != "0" else None,
            }
        )
    return findings
