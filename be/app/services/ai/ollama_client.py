"""
Thin compatibility shim — delegates to LLMGateway.

All existing callers (cwe_mapper, cvss_scorer, etc.) continue to work
unchanged while automatically gaining cache, retry, and telemetry.
"""
from app.services.ai.gateway import get_gateway


def generate(prompt: str, model: str | None = None) -> str:
    return get_gateway().generate(prompt, model=model)
