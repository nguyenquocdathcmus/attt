import logging

from app.services.ai.ollama_client import generate

logger = logging.getLogger(__name__)

# Maps lowercase title keywords → CWE ID
_STATIC_MAP: list[tuple[str, str]] = [
    ("sql injection", "CWE-89"),
    ("sqli", "CWE-89"),
    ("cross-site scripting", "CWE-79"),
    ("reflected xss", "CWE-79"),
    ("stored xss", "CWE-79"),
    ("dom xss", "CWE-79"),
    ("xss", "CWE-79"),
    ("open redirect", "CWE-601"),
    ("path traversal", "CWE-22"),
    ("directory traversal", "CWE-22"),
    ("local file inclusion", "CWE-22"),
    ("remote file inclusion", "CWE-98"),
    ("file inclusion", "CWE-98"),
    ("command injection", "CWE-78"),
    ("os command", "CWE-78"),
    ("server-side request forgery", "CWE-918"),
    ("ssrf", "CWE-918"),
    ("insecure deserialization", "CWE-502"),
    ("deserialization", "CWE-502"),
    ("csrf", "CWE-352"),
    ("cross-site request forgery", "CWE-352"),
    ("session fixation", "CWE-384"),
    ("broken authentication", "CWE-287"),
    ("hardcoded credential", "CWE-798"),
    ("hardcoded password", "CWE-798"),
    ("cleartext", "CWE-319"),
    ("sensitive data exposure", "CWE-200"),
    ("information disclosure", "CWE-200"),
    ("server version", "CWE-200"),
    ("stack trace", "CWE-209"),
    ("error message", "CWE-209"),
    ("directory listing", "CWE-548"),
    ("insecure direct object", "CWE-639"),
    ("idor", "CWE-639"),
    ("insecure file upload", "CWE-434"),
    ("unrestricted upload", "CWE-434"),
    ("clickjacking", "CWE-1021"),
    ("x-frame-options", "CWE-1021"),
    ("anti-clickjacking", "CWE-1021"),
    ("content security policy", "CWE-693"),
    ("missing csp", "CWE-693"),
    ("hsts", "CWE-311"),
    ("strict-transport-security", "CWE-311"),
    ("cookie without secure", "CWE-614"),
    ("secure flag", "CWE-614"),
    ("httponly", "CWE-1004"),
    ("http only", "CWE-1004"),
    ("outdated", "CWE-1104"),
    ("end-of-life", "CWE-1104"),
    ("weak password", "CWE-521"),
    ("buffer overflow", "CWE-120"),
    ("integer overflow", "CWE-190"),
    ("null pointer", "CWE-476"),
    ("use after free", "CWE-416"),
    ("xml injection", "CWE-91"),
    ("xpath injection", "CWE-643"),
    ("ldap injection", "CWE-90"),
    ("xxe", "CWE-611"),
    ("xml external entity", "CWE-611"),
    ("race condition", "CWE-362"),
]

_CWE_NAMES: dict[str, str] = {
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-98": "Remote File Inclusion",
    "CWE-120": "Buffer Overflow",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Error Message Information Disclosure",
    "CWE-287": "Improper Authentication",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-548": "Directory Listing",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-614": "Sensitive Cookie Without Secure Flag",
    "CWE-639": "IDOR",
    "CWE-643": "XPath Injection",
    "CWE-693": "Protection Mechanism Failure (CSP)",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1004": "Sensitive Cookie Without HttpOnly Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third Party Components",
}


def cwe_name(cwe_id: str) -> str:
    return _CWE_NAMES.get(cwe_id, "")


def _static_lookup(title: str) -> str | None:
    t = title.lower()
    for keyword, cwe in _STATIC_MAP:
        if keyword in t:
            return cwe
    return None


def _build_batch_prompt(findings: list[dict]) -> str:
    items = [
        f'{i}: title="{f.get("title")}" desc="{str(f.get("description") or "")[:100]}"'
        for i, f in enumerate(findings)
    ]
    listing = "\n".join(items)
    return f"""You are a security expert. Map each finding to a CWE ID.

Findings:
{listing}

Respond with ONLY a JSON array, no markdown, no explanation:
[{{"index": 0, "cwe": "CWE-79"}}, {{"index": 1, "cwe": null}}, ...]

Use null if you cannot determine the CWE confidently."""


def map_cwe(findings: list[dict]) -> list[dict]:
    """Fill missing CWE using static lookup, then LLM batch for remaining unknowns."""
    needs_llm: list[tuple[int, dict]] = []

    for i, f in enumerate(findings):
        if f.get("cwe"):
            continue
        static = _static_lookup(f.get("title", ""))
        if static:
            f["cwe"] = static
        else:
            needs_llm.append((i, f))

    if needs_llm:
        try:
            from app.schemas.ai_output import CWEItem, parse_llm_json_list

            llm_input = [f for _, f in needs_llm]
            raw = generate(_build_batch_prompt(llm_input))
            items = parse_llm_json_list(raw, CWEItem)
            cwe_map = {item.index: item.cwe for item in items}
            for llm_idx, (_, f) in enumerate(needs_llm):
                cwe = cwe_map.get(llm_idx)
                if cwe:
                    f["cwe"] = cwe
        except Exception as exc:
            logger.warning("CWE batch mapping failed: %s", exc)

    return findings
