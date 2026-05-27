"""
Cross-encoder reranker.

Uses cross-encoder/ms-marco-MiniLM-L-6-v2 (via sentence-transformers) to
rescore a candidate list after the hybrid retriever. Falls back to the
original RRF score if sentence-transformers is not available.

The CrossEncoder is loaded once per process and kept in memory.
"""
from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

_MODEL_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"


@lru_cache(maxsize=1)
def _get_cross_encoder():
    from sentence_transformers import CrossEncoder
    return CrossEncoder(_MODEL_NAME, max_length=512)


def rerank(query: str, chunks: list[dict], top_k: int | None = None) -> list[dict]:
    """
    Re-score chunks using a cross-encoder and return sorted by rerank_score.

    Args:
        query:  The original user query.
        chunks: List of dicts with at least "content" and "score" keys.
        top_k:  Return only top_k results (None = return all, sorted).

    Returns:
        Chunks sorted by rerank_score DESC, each with a new "rerank_score" key.
    """
    if not chunks:
        return chunks

    try:
        model = _get_cross_encoder()
        pairs = [(query, c["content"]) for c in chunks]
        scores = model.predict(pairs)
        for i, chunk in enumerate(chunks):
            chunk["rerank_score"] = float(scores[i])
        ranked = sorted(chunks, key=lambda x: x["rerank_score"], reverse=True)
    except ImportError:
        logger.debug("sentence-transformers not available, skipping rerank")
        ranked = sorted(chunks, key=lambda x: x.get("score", 0.0), reverse=True)
    except Exception as exc:
        logger.warning("Reranker failed (%s), returning original order", exc)
        ranked = chunks

    return ranked[:top_k] if top_k is not None else ranked
