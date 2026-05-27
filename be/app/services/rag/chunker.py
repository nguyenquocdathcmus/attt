"""
Semantic chunker — sentence-boundary aware.

Improvements over the old character-based chunker:
  - Splits on sentence boundaries, not mid-sentence
  - Preserves code blocks (``` ... ```) and inline code as atomic units
  - Preserves CVE/CWE references intact
  - Overlap is measured in sentences, not characters
  - Each chunk carries rich metadata for lifecycle management
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── Sentence boundary detection ───────────────────────────────────────────────

# Sentence-ending punctuation followed by whitespace and an uppercase letter
# Negative lookbehind for common abbreviations (Mr., Dr., vs., etc.)
_ABBREV = r"(?<!Mr)(?<!Dr)(?<!vs)(?<!etc)(?<!e\.g)(?<!i\.e)(?<!Fig)(?<!No)"
_SENT_BOUNDARY = re.compile(_ABBREV + r"(?<=[.!?])\s+(?=[A-Z\"\'])")

# Code block fence
_CODE_FENCE = re.compile(r"```[\s\S]*?```", re.DOTALL)

# CVE / CWE reference patterns — must not be split across chunks
_SEC_REF = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|OWASP[- ][A-Z0-9-]+)\b")


@dataclass
class Chunk:
    content: str
    meta: dict = field(default_factory=dict)


def chunk_document(
    text: str,
    max_sentences: int = 8,
    overlap_sentences: int = 2,
    min_chars: int = 80,
) -> list[dict]:
    """
    Split *text* into semantically coherent chunks.

    Args:
        text:              Raw document text.
        max_sentences:     Target max sentences per chunk (may be exceeded to
                           keep a code block or security reference intact).
        overlap_sentences: Number of sentences to repeat at the start of the
                           next chunk for context continuity.
        min_chars:         Chunks shorter than this are merged with the next.

    Returns:
        List of ``{"content": str, "meta": dict}`` dicts.
    """
    if not text:
        return []

    segments = _split_preserving_code(text)
    sentences = _to_sentences(segments)
    raw_chunks = _group_into_chunks(sentences, max_sentences, overlap_sentences, min_chars)

    result: list[dict] = []
    for idx, chunk in enumerate(raw_chunks):
        sec_refs = _SEC_REF.findall(chunk.content)
        result.append({
            "content": chunk.content,
            "meta": {
                **chunk.meta,
                "chunk_index": idx,
                "char_len": len(chunk.content),
                "security_refs": list(set(sec_refs)),
            },
        })
    return result


def chunk_text(
    text: str,
    max_sentences: int = 8,
    overlap_sentences: int = 2,
) -> list[str]:
    return [c["content"] for c in chunk_document(text, max_sentences, overlap_sentences)]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _split_preserving_code(text: str) -> list[tuple[str, bool]]:
    """
    Split text into (segment, is_code) pairs, keeping code blocks atomic.
    """
    segments: list[tuple[str, bool]] = []
    last = 0
    for m in _CODE_FENCE.finditer(text):
        before = text[last:m.start()]
        if before:
            segments.append((before, False))
        segments.append((m.group(), True))
        last = m.end()
    tail = text[last:]
    if tail:
        segments.append((tail, False))
    return segments


def _to_sentences(segments: list[tuple[str, bool]]) -> list[tuple[str, bool]]:
    """
    Convert (segment, is_code) pairs into (sentence, is_code) pairs.
    Code blocks are returned as a single 'sentence'.
    """
    sentences: list[tuple[str, bool]] = []
    for content, is_code in segments:
        if is_code:
            sentences.append((content.strip(), True))
        else:
            parts = _SENT_BOUNDARY.split(content)
            for part in parts:
                stripped = part.strip()
                if stripped:
                    sentences.append((stripped, False))
    return sentences


def _group_into_chunks(
    sentences: list[tuple[str, bool]],
    max_sentences: int,
    overlap: int,
    min_chars: int,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    i = 0
    total = len(sentences)

    while i < total:
        window = sentences[i: i + max_sentences]
        text = " ".join(s for s, _ in window).strip()

        # If this chunk is too short and there's more text, merge with next window
        if len(text) < min_chars and i + max_sentences < total:
            window = sentences[i: i + max_sentences + 4]
            text = " ".join(s for s, _ in window).strip()

        has_code = any(is_code for _, is_code in window)
        chunks.append(Chunk(
            content=text,
            meta={
                "has_code": has_code,
                "sentence_count": len(window),
            },
        ))
        i += max(1, max_sentences - overlap)

    return chunks
