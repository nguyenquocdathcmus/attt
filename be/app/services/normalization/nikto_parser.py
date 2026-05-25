def parse(raw: dict) -> list[dict]:
    data = raw.get("raw") if isinstance(raw, dict) else None

    hosts: list[dict] = []
    if isinstance(data, list):
        hosts = [h for h in data if isinstance(h, dict)]
    elif isinstance(data, dict):
        if isinstance(data.get("scan"), dict):
            hosts = [data["scan"]]
        else:
            hosts = [data]

    findings: list[dict] = []
    for host in hosts:
        vulnerabilities = host.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            continue
        for item in vulnerabilities:
            vid = item.get("id") or ""
            if vid == "FAIL":
                continue
            title = item.get("msg") or item.get("message") or "Nikto finding"
            findings.append(
                {
                    "type": "nikto",
                    "severity": "Medium",
                    "title": title,
                    "description": item.get("description") or item.get("msg"),
                    "evidence": {
                        "host": host.get("host"),
                        "port": host.get("port"),
                        "url": item.get("url"),
                        "method": item.get("method"),
                        "osvdb": item.get("osvdb"),
                        "refs": item.get("references") or item.get("refs"),
                    },
                    "cwe": None,
                    "owasp": None,
                }
            )
    return findings
