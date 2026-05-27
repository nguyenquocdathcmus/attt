"""
Hybrid retriever: cosine vector search + BM25 full-text search fused with
Reciprocal Rank Fusion (RRF, k=60).

Weights:
  alpha = 0.7  → vector (semantic)
  1-alpha = 0.3 → BM25  (keyword / exact match)

RRF score = alpha * 1/(k + vector_rank) + (1-alpha) * 1/(k + bm25_rank)

The HNSW index (migration 004) makes the vector leg O(log n) instead of O(n).
The GIN index (migration 004) makes the BM25 leg O(log n) instead of O(n).
"""
from __future__ import annotations

import logging

from sqlalchemy import select, text

from app.db.models.embedding import Embedding
from app.db.models.knowledge_doc import KnowledgeDoc
from app.db.session import SessionLocal
from app.services.rag.embedder import LocalEmbedder

logger = logging.getLogger(__name__)

_RRF_K = 60
_ALPHA = 0.7          # weight for vector leg
_FETCH_MULTIPLIER = 3  # fetch N*multiplier from each leg before fusion


def retrieve_context(
    query: str,
    limit: int = 5,
    sources: list[str] | None = None,
    alpha: float = _ALPHA,
) -> list[dict]:
    """
    Return top-`limit` chunks most relevant to `query`.

    Args:
        query:   Natural-language query string.
        limit:   Number of results to return.
        sources: Optional allowlist of KnowledgeDoc.source values.
        alpha:   Vector weight (0–1). 1.0 = pure vector, 0.0 = pure BM25.
    """
    embedder = LocalEmbedder()
    query_vector = embedder.embed_query(query)
    fetch_n = limit * _FETCH_MULTIPLIER

    session = SessionLocal()
    try:
        vector_results = _vector_search(session, query_vector, fetch_n, sources)
        bm25_results = _bm25_search(session, query, fetch_n, sources)

        fused = _rrf_fuse(vector_results, bm25_results, alpha=alpha)
        top = sorted(fused.values(), key=lambda x: x["rrf_score"], reverse=True)[:limit]

        return [
            {
                "content": r["content"],
                "source": r["source"],
                "title": r["title"],
                "uri": r["uri"],
                "score": r["rrf_score"],
                "metadata": r["metadata"],
            }
            for r in top
        ]
    finally:
        session.close()


# ── Vector leg ────────────────────────────────────────────────────────────────

def _vector_search(
    session,
    query_vector: list[float],
    limit: int,
    sources: list[str] | None,
) -> list[dict]:
    distance = Embedding.embedding.cosine_distance(query_vector)
    stmt = (
        select(Embedding, KnowledgeDoc, distance.label("distance"))
        .join(KnowledgeDoc, Embedding.doc_id == KnowledgeDoc.id)
        .where(Embedding.embedding.isnot(None))
    )
    if sources:
        stmt = stmt.where(KnowledgeDoc.source.in_(sources))
    stmt = stmt.order_by(distance).limit(limit)

    rows = session.execute(stmt).all()
    return [
        {
            "id": str(emb.id),
            "content": emb.content,
            "source": doc.source,
            "title": doc.title,
            "uri": doc.uri,
            "metadata": emb.meta,
            "vector_distance": float(dist) if dist is not None else 1.0,
        }
        for emb, doc, dist in rows
    ]


# ── BM25 leg (PostgreSQL tsvector + ts_rank_cd) ───────────────────────────────

def _bm25_search(
    session,
    query: str,
    limit: int,
    sources: list[str] | None,
) -> list[dict]:
    # tsquery: each word becomes a lexeme; multi-word joined with &
    try:
        source_filter = ""
        params: dict = {"query": query, "limit": limit}
        if sources:
            source_filter = "AND kd.source = ANY(:sources)"
            params["sources"] = sources

        sql = text(f"""
            SELECT
                e.id::text,
                e.content,
                e.metadata,
                kd.source,
                kd.title,
                kd.uri,
                ts_rank_cd(
                    to_tsvector('english', e.content),
                    websearch_to_tsquery('english', :query)
                ) AS bm25_score
            FROM embeddings e
            JOIN knowledge_docs kd ON kd.id = e.doc_id
            WHERE to_tsvector('english', e.content)
                  @@ websearch_to_tsquery('english', :query)
            {source_filter}
            ORDER BY bm25_score DESC
            LIMIT :limit
        """)
        rows = session.execute(sql, params).mappings().all()
        return [
            {
                "id": row["id"],
                "content": row["content"],
                "source": row["source"],
                "title": row["title"],
                "uri": row["uri"],
                "metadata": row["metadata"],
                "bm25_score": float(row["bm25_score"]),
            }
            for row in rows
        ]
    except Exception as exc:
        logger.warning("BM25 search failed, falling back to empty: %s", exc)
        return []


# ── RRF fusion ────────────────────────────────────────────────────────────────

def _rrf_fuse(
    vector_results: list[dict],
    bm25_results: list[dict],
    alpha: float,
    k: int = _RRF_K,
) -> dict[str, dict]:
    """
    Merge two ranked lists using Reciprocal Rank Fusion.
    Returns a dict keyed by chunk id → merged result with rrf_score.
    """
    merged: dict[str, dict] = {}

    for rank, item in enumerate(vector_results):
        cid = item["id"]
        merged.setdefault(cid, {**item, "rrf_score": 0.0})
        merged[cid]["rrf_score"] += alpha * (1.0 / (k + rank + 1))

    for rank, item in enumerate(bm25_results):
        cid = item["id"]
        merged.setdefault(cid, {**item, "rrf_score": 0.0})
        merged[cid]["rrf_score"] += (1.0 - alpha) * (1.0 / (k + rank + 1))

    return merged
