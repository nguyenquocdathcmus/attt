"""
Prompt injection guard.

Usage:
    from app.services.ai.prompt_guard import harden, is_safe, PromptInjectionError

    safe_input = harden(user_url)          # wrap in hardened delimiters
    is_safe(user_text, raise_on_fail=True) # raises PromptInjectionError if suspicious
"""
import re

_INJECTION_PATTERNS: list[tuple[str, str]] = [
    ("ignore_instructions",    r"ignore\s+(all\s+)?previous\s+instructions?"),
    ("forget_instructions",    r"forget\s+(all\s+)?previous\s+(instructions?|prompts?)"),
    ("act_as",                 r"\bact\s+as\s+(?:a|an|the)\s+"),
    ("you_are_now",            r"you\s+are\s+now\s+(?:a|an)\s+"),
    ("disregard",              r"disregard\s+(all\s+)?(your\s+)?(previous\s+|prior\s+)?(instructions?|rules?|constraints?)"),
    ("jailbreak",              r"\bjailbreak\b"),
    ("role_tags",              r"<\s*/?(?:system|assistant|human|user)\s*>"),
    ("llm_special_tokens",     r"\[\s*(?:system|inst|\/inst|s|\/s)\s*\]"),
]

_COMPILED = [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in _INJECTION_PATTERNS]


class PromptInjectionError(ValueError):
    def __init__(self, matched: list[str]) -> None:
        self.matched = matched
        super().__init__(f"Prompt injection detected: {matched}")


def check(text: str) -> list[str]:
    """Return list of matched pattern names (empty = clean)."""
    return [name for name, rx in _COMPILED if rx.search(text)]


def is_safe(text: str, raise_on_fail: bool = False) -> bool:
    matched = check(text)
    if matched and raise_on_fail:
        raise PromptInjectionError(matched)
    return len(matched) == 0


def harden(user_data: str) -> str:
    """Wrap user-controlled data in hardened delimiters to isolate it from prompt instructions."""
    # Escape any existing delimiter sequences in user data
    safe = user_data.replace("<|USER_DATA_START|>", "").replace("<|USER_DATA_END|>", "")
    return f"<|USER_DATA_START|>\n{safe}\n<|USER_DATA_END|>"


def build_safe_prompt(template: str, **user_fields: str) -> str:
    """
    Build a prompt from a template, hardening all user-provided fields.

    Example:
        build_safe_prompt(
            "Analyze this URL: {url}\\n\\nFinding: {title}",
            url=user_url,
            title=user_title,
        )
    """
    hardened = {k: harden(v) for k, v in user_fields.items()}
    return template.format(**hardened)
