"""
Prompt version registry — versioned, tagged prompt templates.

Provides:
  - PromptTemplate: immutable record with version, tags, and render()
  - PromptRegistry: in-process store, loaded once at startup
  - get_prompt(name, version=None): fetch latest or specific version
  - Prometheus-compatible usage counter (no hard dep)

Design decisions:
  - Prompts are defined in code (not DB) to keep them in version control.
  - Each template carries an explicit semver string so A/B tests and
    rollbacks are reproducible without touching DB migrations.
  - "active" tag marks the production-default; older versions stay
    registered so historical evaluations can re-run the exact prompt.
"""
from __future__ import annotations

import logging
import string
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PromptTemplate:
    name: str           # logical name, e.g. "cwe_mapping"
    version: str        # semver string, e.g. "1.0.0"
    template: str       # Python str.format_map template
    tags: frozenset[str] = field(default_factory=frozenset)
    description: str = ""

    def render(self, **kwargs: Any) -> str:
        """Substitute *kwargs* into the template string.

        Raises KeyError if a required placeholder is missing.
        Uses string.Template for $var syntax; falls back to str.format_map
        for {var} syntax based on which placeholders are detected.
        """
        try:
            return self.template.format_map(kwargs)
        except (KeyError, IndexError) as exc:
            raise ValueError(
                f"Prompt '{self.name}' v{self.version} missing variable: {exc}"
            ) from exc

    @property
    def is_active(self) -> bool:
        return "active" in self.tags


class _UsageCounter:
    """Lightweight counter — increments an in-process dict.
    Compatible with Prometheus if metrics.py is loaded first.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def increment(self, name: str, version: str) -> None:
        key = f"{name}:{version}"
        self._counts[key] = self._counts.get(key, 0) + 1
        try:
            from app.core.metrics import PROMPT_USAGE
            PROMPT_USAGE.labels(prompt=name, version=version).inc()
        except Exception:
            pass

    def get(self, name: str, version: str) -> int:
        return self._counts.get(f"{name}:{version}", 0)

    def all(self) -> dict[str, int]:
        return dict(self._counts)


_counter = _UsageCounter()


class PromptRegistry:
    """Central store for all versioned prompt templates."""

    def __init__(self) -> None:
        # {name: {version: PromptTemplate}}
        self._store: dict[str, dict[str, PromptTemplate]] = {}

    def register(self, template: PromptTemplate) -> PromptTemplate:
        """Register a prompt template. Overwrites if same name+version."""
        self._store.setdefault(template.name, {})[template.version] = template
        logger.debug(
            "Registered prompt name=%s version=%s tags=%s",
            template.name, template.version, template.tags,
        )
        return template

    def get(self, name: str, version: str | None = None) -> PromptTemplate:
        """Return a prompt by name.

        If *version* is None, returns the template tagged "active".
        Falls back to the lexicographically highest version if no active tag.
        Raises KeyError if name unknown or version not found.
        """
        versions = self._store.get(name)
        if not versions:
            raise KeyError(f"No prompt registered with name '{name}'")

        if version is not None:
            tpl = versions.get(version)
            if tpl is None:
                raise KeyError(
                    f"Prompt '{name}' has no version '{version}'. "
                    f"Available: {sorted(versions)}"
                )
            _counter.increment(name, version)
            return tpl

        # prefer "active"-tagged
        for tpl in versions.values():
            if tpl.is_active:
                _counter.increment(name, tpl.version)
                return tpl

        # fallback: highest semver
        latest = sorted(versions.keys())[-1]
        _counter.increment(name, latest)
        return versions[latest]

    def list_names(self) -> list[str]:
        return sorted(self._store)

    def list_versions(self, name: str) -> list[str]:
        return sorted(self._store.get(name, {}))

    def usage(self) -> dict[str, int]:
        return _counter.all()


# ── Singleton ──────────────────────────────────────────────────────────────────

registry = PromptRegistry()


def get_prompt(name: str, version: str | None = None) -> PromptTemplate:
    """Module-level convenience accessor."""
    return registry.get(name, version)


# ── Built-in prompt definitions ───────────────────────────────────────────────
# Each call to registry.register() returns the template so it's also
# reachable as a module constant for direct import.

CWE_MAPPING_V1 = registry.register(PromptTemplate(
    name="cwe_mapping",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Map a security finding to CWE IDs.",
    template=(
        "You are a security expert. Given the finding below, output a JSON array "
        "of objects with keys: cwe_id (string, format CWE-NNN), name (string), "
        "confidence (float 0.0–1.0).\n\n"
        "Finding:\n{finding_text}\n\n"
        "Output ONLY valid JSON, no markdown fences."
    ),
))

CVSS_SCORING_V1 = registry.register(PromptTemplate(
    name="cvss_scoring",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Generate CVSS v3.1 vector + score for a finding.",
    template=(
        "You are a CVSS v3.1 expert. For the finding below, output a JSON object "
        "with keys: vector_string (CVSS:3.1/AV:…), base_score (float), "
        "severity (string: None/Low/Medium/High/Critical), rationale (string).\n\n"
        "Finding:\n{finding_text}\n\n"
        "Output ONLY valid JSON, no markdown fences."
    ),
))

RISK_PRIORITIZATION_V1 = registry.register(PromptTemplate(
    name="risk_prioritization",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Score finding risk 0.0–1.0 with reasoning.",
    template=(
        "You are a risk analyst. Rate the risk of this security finding as a float "
        "from 0.0 (negligible) to 1.0 (critical). Consider exploitability, impact, "
        "and asset value.\n\n"
        "Output a JSON object: {{\"risk_score\": float, \"reasoning\": string}}.\n\n"
        "Finding:\n{finding_text}\n"
        "Context:\n{context}"
    ),
))

FALSE_POSITIVE_V1 = registry.register(PromptTemplate(
    name="false_positive",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Determine probability that a finding is a false positive.",
    template=(
        "Analyse this security finding and decide if it is a false positive.\n"
        "Output JSON: {{\"fp_score\": float 0.0–1.0, \"reason\": string}}.\n"
        "0.0 = definitely real, 1.0 = definitely false positive.\n\n"
        "Finding:\n{finding_text}\n"
        "Scanner output:\n{raw_evidence}"
    ),
))

REMEDIATION_V1 = registry.register(PromptTemplate(
    name="remediation",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Generate actionable remediation steps.",
    template=(
        "You are a secure coding advisor. For the vulnerability below, produce "
        "remediation guidance.\n\n"
        "Output JSON: {{\"summary\": string, \"steps\": [string, ...], "
        "\"references\": [string, ...]}}.\n\n"
        "Vulnerability:\n{finding_text}\n"
        "RAG context:\n{rag_context}"
    ),
))

EXECUTIVE_SUMMARY_V1 = registry.register(PromptTemplate(
    name="executive_summary",
    version="1.0.0",
    tags=frozenset({"active", "reporting"}),
    description="Generate a non-technical executive summary.",
    template=(
        "Write a concise executive summary (≤200 words) for a security assessment.\n\n"
        "Stats: {stats_json}\n"
        "Top findings: {top_findings_json}\n\n"
        "Tone: professional, non-technical, action-oriented."
    ),
))

PATCH_GENERATION_V1 = registry.register(PromptTemplate(
    name="patch_generation",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Generate a secure code patch for a vulnerability.",
    template=(
        "You are a security engineer. Generate a minimal, secure patch for the "
        "vulnerability described below.\n\n"
        "Language: {language}\nFramework: {framework}\n"
        "Vulnerability:\n{finding_text}\n"
        "Vulnerable code snippet:\n```\n{code_snippet}\n```\n\n"
        "Output JSON: {{\"patched_code\": string, \"explanation\": string, "
        "\"confidence\": float}}.\n"
        "Output ONLY valid JSON, no markdown fences."
    ),
))

SECURE_REWRITE_V1 = registry.register(PromptTemplate(
    name="secure_rewrite",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline"}),
    description="Rewrite a full file to remove vulnerabilities.",
    template=(
        "Rewrite the following {language} file to eliminate all security "
        "vulnerabilities while preserving all public function signatures and "
        "behavior.\n\n"
        "Vulnerabilities to fix:\n{vulnerabilities_json}\n\n"
        "Original file:\n```\n{original_code}\n```\n\n"
        "Output ONLY the rewritten source code, no markdown fences."
    ),
))

# ── Batch variants (used by AI pipeline services) ─────────────────────────────
# These take a pre-built {listing} string (numbered findings) to minimise LLM calls.

CWE_MAPPING_BATCH_V1 = registry.register(PromptTemplate(
    name="cwe_mapping_batch",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline", "batch"}),
    description="Batch-map findings to CWE IDs.",
    template=(
        "You are a security expert. Map each finding to a CWE ID.\n\n"
        "Findings:\n{listing}\n\n"
        "Respond with ONLY a JSON array, no markdown, no explanation:\n"
        '[{{"index": 0, "cwe": "CWE-79"}}, {{"index": 1, "cwe": null}}, ...]\n\n'
        "Use null if you cannot determine the CWE confidently."
    ),
))

CVSS_SCORING_BATCH_V1 = registry.register(PromptTemplate(
    name="cvss_scoring_batch",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline", "batch"}),
    description="Batch-score CVSS v3.1 for findings.",
    template=(
        "You are a security expert calculating CVSS v3.1 base scores.\n"
        "For each finding, determine the CVSS vector and base score.\n\n"
        "Findings:\n{listing}\n\n"
        "Respond with ONLY a JSON array, no markdown:\n"
        "[{{{{'index': 0, 'score': 8.1, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'}}}}, ...]\n\n"
        "Rules:\n"
        "- score must be 0.0–10.0\n"
        "- vector must start with CVSS:3.1/\n"
        "- AV: N=Network, A=Adjacent, L=Local, P=Physical\n"
        "- AC: L=Low, H=High  |  PR: N=None, L=Low, H=High\n"
        "- UI: N=None, R=Required  |  S: U=Unchanged, C=Changed\n"
        "- C/I/A: N=None, L=Low, H=High"
    ),
))

RISK_PRIORITIZATION_BATCH_V1 = registry.register(PromptTemplate(
    name="risk_prioritization_batch",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline", "batch"}),
    description="Batch-score exploitability risk 0.0–1.0.",
    template=(
        "You are a security expert. Score each finding's exploitability risk from 0.0 to 1.0.\n\n"
        "Findings:\n{listing}\n\n"
        "Respond with ONLY a JSON array indexed by finding number, no markdown:\n"
        '[{{"index": 0, "risk_score": 0.85}}, {{"index": 1, "risk_score": 0.4}}, ...]'
    ),
))

FALSE_POSITIVE_BATCH_V1 = registry.register(PromptTemplate(
    name="false_positive_batch",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline", "batch"}),
    description="Batch false positive probability estimation.",
    template=(
        "You are a security expert reviewing automated scanner results.\n"
        "Estimate the false positive probability (0.0=definitely real, "
        "1.0=definitely false positive) for each finding.\n\n"
        "Findings:\n{listing}\n\n"
        "Respond with ONLY a JSON array, no markdown:\n"
        '[{{"index": 0, "false_positive_score": 0.1}}, {{"index": 1, "false_positive_score": 0.7}}, ...]'
    ),
))

REMEDIATION_BATCH_V1 = registry.register(PromptTemplate(
    name="remediation_batch",
    version="1.0.0",
    tags=frozenset({"active", "ai_pipeline", "batch"}),
    description="Batch remediation guidance for findings.",
    template=(
        "You are a security engineer. Provide remediation for each vulnerability below.\n\n"
        "Findings:\n{listing}\n\n"
        "Respond with ONLY a JSON array, no markdown:\n"
        "[\n"
        "  {{\n"
        '    "index": 0,\n'
        '    "summary": "<one sentence fix>",\n'
        '    "steps": ["<step 1>", "<step 2>", "<step 3>"],\n'
        '    "references": ["<OWASP or CWE link>"]\n'
        "  }},\n"
        "  ...\n"
        "]"
    ),
))

CONTEXTUAL_ENRICHMENT_V1 = registry.register(PromptTemplate(
    name="contextual_enrichment",
    version="1.0.0",
    tags=frozenset({"active", "rag"}),
    description="Add 1-2 sentences of security context before embedding a chunk.",
    template=(
        "Add 1-2 sentences of security context to the following knowledge chunk "
        "so it embeds better in a vulnerability knowledge base. "
        "Output ONLY the enriched chunk, no other text.\n\n"
        "Chunk:\n{chunk_text}"
    ),
))
