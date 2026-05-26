"""
Pydantic schemas for every LLM response type.

Every schema has strict validators so hallucinated / malformed data
is rejected before it can be written to the database.
Usage:
    from app.schemas.ai_output import parse_llm_json, CWEBatchResult
    results = parse_llm_json(raw_llm_text, CWEBatchResult)
"""
from __future__ import annotations

import json
import logging
import re
from typing import TypeVar, Type

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def _strip_fences(raw: str) -> str:
    """Remove markdown code fences that Ollama sometimes wraps around JSON."""
    match = _FENCE_RE.search(raw)
    if match:
        return match.group(1).strip()
    return raw.strip()


def parse_llm_json(raw: str, schema: Type[T]) -> T:
    """
    Parse + validate a raw LLM string into a Pydantic model.

    On failure logs a warning and raises ValueError so callers can
    fall back to their default/template behaviour — nothing hallucinates
    its way into the database.
    """
    cleaned = _strip_fences(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM output is not valid JSON: {exc}") from exc

    return schema.model_validate(data)


def parse_llm_json_list(raw: str, item_schema: Type[T]) -> list[T]:
    """Parse a JSON array where each element is validated against item_schema."""
    cleaned = _strip_fences(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM output is not valid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array, got {type(data).__name__}")

    items: list[T] = []
    for i, element in enumerate(data):
        try:
            items.append(item_schema.model_validate(element))
        except Exception as exc:
            logger.warning("Skipping invalid LLM item index=%d: %s", i, exc)
    return items


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------

_CWE_PATTERN = re.compile(r"^CWE-\d+$")


class CWEItem(BaseModel):
    index: int = Field(ge=0)
    cwe: str | None = None

    @field_validator("cwe", mode="before")
    @classmethod
    def validate_cwe(cls, v: object) -> str | None:
        if v is None:
            return None
        s = str(v).strip().upper()
        if not _CWE_PATTERN.match(s):
            raise ValueError(f"Invalid CWE format: {v!r}")
        return s


# ---------------------------------------------------------------------------
# CVSS scoring
# ---------------------------------------------------------------------------

_CVSS_VECTOR_PATTERN = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$"
)


class CVSSItem(BaseModel):
    index: int = Field(ge=0)
    score: float = Field(ge=0.0, le=10.0)
    vector: str

    @field_validator("score", mode="before")
    @classmethod
    def round_score(cls, v: object) -> float:
        return round(float(v), 1)

    @field_validator("vector", mode="before")
    @classmethod
    def validate_vector(cls, v: object) -> str:
        s = str(v).strip()
        if not _CVSS_VECTOR_PATTERN.match(s):
            raise ValueError(f"Invalid CVSS v3.1 vector: {v!r}")
        return s


# ---------------------------------------------------------------------------
# Risk prioritization
# ---------------------------------------------------------------------------

class RiskItem(BaseModel):
    index: int = Field(ge=0)
    risk_score: float = Field(ge=0.0, le=1.0)

    @field_validator("risk_score", mode="before")
    @classmethod
    def clamp(cls, v: object) -> float:
        return max(0.0, min(1.0, float(v)))


# ---------------------------------------------------------------------------
# False-positive scoring
# ---------------------------------------------------------------------------

class FalsePositiveItem(BaseModel):
    index: int = Field(ge=0)
    false_positive_score: float = Field(ge=0.0, le=1.0)

    @field_validator("false_positive_score", mode="before")
    @classmethod
    def clamp(cls, v: object) -> float:
        return max(0.0, min(1.0, float(v)))


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

class RemediationItem(BaseModel):
    index: int = Field(ge=0)
    summary: str = Field(min_length=5, max_length=600)
    steps: list[str] = Field(min_length=1, max_length=10)
    references: list[str] = Field(default_factory=list)

    @field_validator("steps", mode="before")
    @classmethod
    def ensure_list(cls, v: object) -> list:
        if isinstance(v, str):
            return [v]
        return list(v)  # type: ignore[arg-type]

    @field_validator("references", mode="before")
    @classmethod
    def filter_empty_refs(cls, v: object) -> list[str]:
        if not v:
            return []
        return [str(r) for r in v if str(r).strip()]  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Patch generation
# ---------------------------------------------------------------------------

class PatchOutput(BaseModel):
    patched_code: str = Field(min_length=5)
    explanation: str = Field(min_length=10, max_length=500)
    breaking_change: bool = False
    dependencies_added: list[str] = Field(default_factory=list)
    test_cases: list[dict] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp(cls, v: object) -> float:
        return max(0.0, min(1.0, float(v)))
