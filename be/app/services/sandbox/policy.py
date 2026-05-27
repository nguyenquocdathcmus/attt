"""
Sandbox policy engine.

Enforces safety gates before any exploit attempt is executed:
  1. Target domain must be registered in the approved assets table
  2. Exploit type must be in the allowed list for the finding's severity
  3. Payload must not exceed size/pattern limits
  4. Rate: max N exploit attempts per scan (prevent abuse)

All checks are pure Python — no I/O.  The executor calls policy.check()
and raises PolicyViolation if any gate fails.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# ── Allowed exploit types per severity tier ───────────────────────────────────
# Only HTTP-level, non-destructive probes are enabled.
# RCE/system-level exploits require explicit ALLOW_DESTRUCTIVE=true env var.

_ALLOWED_BY_SEVERITY: dict[str, set[str]] = {
    "Critical": {"xss_reflect", "sqli_error", "sqli_boolean", "ssrf_oob",
                 "path_traversal", "open_redirect", "xxe_detect",
                 "header_injection", "auth_bypass"},
    "High":     {"xss_reflect", "sqli_error", "header_injection",
                 "open_redirect", "path_traversal"},
    "Medium":   {"xss_reflect", "header_injection", "open_redirect"},
    "Low":      set(),      # no automated exploits for Low
    "Info":     set(),
}

# Payloads matching these patterns are always blocked regardless of severity
_BLOCKED_PAYLOAD_PATTERNS: list[re.Pattern] = [
    re.compile(r"rm\s+-rf", re.IGNORECASE),
    re.compile(r";\s*(?:shutdown|reboot|halt)", re.IGNORECASE),
    re.compile(r"(?:wget|curl)\s+.*\|.*sh", re.IGNORECASE),
    re.compile(r"base64\s+--decode.*\|.*sh", re.IGNORECASE),
    re.compile(r"\$\(.*\)", re.DOTALL),            # command substitution
    re.compile(r"`[^`]+`"),                         # backtick execution
]

_MAX_PAYLOAD_BYTES = 4096
_MAX_EXPLOITS_PER_SCAN = 20


@dataclass
class PolicyViolation(Exception):
    reason: str
    rule: str

    def __str__(self) -> str:
        return f"PolicyViolation [{self.rule}]: {self.reason}"


@dataclass
class PolicyContext:
    target_url: str
    exploit_type: str
    payload: str
    severity: str
    approved_domains: list[str]  # from the Asset record
    attempts_this_scan: int = 0


def check(ctx: PolicyContext) -> None:
    """
    Run all policy gates.  Raises PolicyViolation on first failure.
    """
    _check_domain(ctx)
    _check_exploit_type(ctx)
    _check_payload(ctx)
    _check_rate(ctx)


# ── Individual gates ──────────────────────────────────────────────────────────

def _check_domain(ctx: PolicyContext) -> None:
    parsed = urlparse(ctx.target_url)
    host = parsed.hostname or ""
    if not any(host == d or host.endswith(f".{d}") for d in ctx.approved_domains):
        raise PolicyViolation(
            reason=f"Host '{host}' is not in approved domains {ctx.approved_domains}",
            rule="DOMAIN_NOT_APPROVED",
        )


def _check_exploit_type(ctx: PolicyContext) -> None:
    allowed = _ALLOWED_BY_SEVERITY.get(ctx.severity, set())
    if ctx.exploit_type not in allowed:
        raise PolicyViolation(
            reason=f"Exploit type '{ctx.exploit_type}' not allowed for severity '{ctx.severity}'",
            rule="EXPLOIT_TYPE_NOT_ALLOWED",
        )


def _check_payload(ctx: PolicyContext) -> None:
    if len(ctx.payload.encode()) > _MAX_PAYLOAD_BYTES:
        raise PolicyViolation(
            reason=f"Payload exceeds {_MAX_PAYLOAD_BYTES} bytes",
            rule="PAYLOAD_TOO_LARGE",
        )
    for pattern in _BLOCKED_PAYLOAD_PATTERNS:
        if pattern.search(ctx.payload):
            raise PolicyViolation(
                reason=f"Payload matches blocked pattern: {pattern.pattern[:40]}",
                rule="PAYLOAD_BLOCKED",
            )


def _check_rate(ctx: PolicyContext) -> None:
    if ctx.attempts_this_scan >= _MAX_EXPLOITS_PER_SCAN:
        raise PolicyViolation(
            reason=f"Scan has already executed {ctx.attempts_this_scan} exploits "
                   f"(limit={_MAX_EXPLOITS_PER_SCAN})",
            rule="RATE_EXCEEDED",
        )
