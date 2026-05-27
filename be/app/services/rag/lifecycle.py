"""
Embedding lifecycle manager.

Responsibilities:
  - Track which model each chunk was embedded with (stored in meta).
  - Detect chunks that need reindexing when the embedder model changes.
  - Expose a Celery-compatible function so a beat task can call it.

Usage:
    from app.services.rag.lifecycle import find_stale_doc_ids, reindex_stale

    stale = find_stale_doc_ids()      # list of doc UUIDs needing reindex
    reindex_stale(batch_size=50)      # re-embed and commit stale chunks
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text

from app.core.config import settings
from app.db.models.embedding import Embedding
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)

_META_MODEL_KEY = "embedder_model"


# ── Public API ────────────────────────────────────────────────────────────────

def find_stale_doc_ids(current_model: str | None = None) -> list[str]:
    """
    Return UUIDs of KnowledgeDocs that have at least one embedding created
    with a different model than *current_model*.
    """
    model = current_model or settings.embeddings_model
    session = SessionLocal()
    try:
        rows = session.execute(
            text("""
                SELECT DISTINCT doc_id::text
                FROM embeddings
                WHERE metadata->>'embedder_model' IS NULL
                   OR metadata->>'embedder_model' != :model
            """),
            {"model": model},
        ).fetchall()
        return [r[0] for r in rows]
    finally:
        session.close()


def reindex_stale(batch_size: int = 50, current_model: str | None = None) -> dict:
    """
    Re-embed all stale chunks in *batch_size* document batches.
    Called by the Celery beat task `rag.reindex_stale`.
    """
    model = current_model or settings.embeddings_model
    stale_ids = find_stale_doc_ids(model)

    if not stale_ids:
        logger.debug("Lifecycle: no stale embeddings found for model=%s", model)
        return {"reindexed": 0, "docs": 0}

    logger.info("Lifecycle: %d docs need reindexing (model=%s)", len(stale_ids), model)

    total_chunks = 0
    for i in range(0, len(stale_ids), batch_size):
        batch = stale_ids[i: i + batch_size]
        total_chunks += _reindex_docs(batch, model)

    return {"reindexed": total_chunks, "docs": len(stale_ids)}


def stamp_embeddings(doc_id: str, model: str | None = None) -> None:
    """
    Write the current embedder model name into the meta of all embeddings
    belonging to *doc_id*. Called after a fresh ingest so the lifecycle
    manager can detect staleness on future model changes.
    """
    model = model or settings.embeddings_model
    session = SessionLocal()
    try:
        session.execute(
            text("""
                UPDATE embeddings
                SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('embedder_model', :model)
                WHERE doc_id = :doc_id
            """),
            {"model": model, "doc_id": doc_id},
        )
        session.commit()
    finally:
        session.close()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _reindex_docs(doc_ids: list[str], model: str) -> int:
    from app.db.models.knowledge_doc import KnowledgeDoc
    from app.services.rag.chunker import chunk_document
    from app.services.rag.embedder import LocalEmbedder

    embedder = LocalEmbedder(model=model)
    session = SessionLocal()
    chunk_count = 0

    try:
        for doc_id in doc_ids:
            doc = session.get(KnowledgeDoc, uuid.UUID(doc_id))
            if not doc or not doc.raw_text:
                continue

            # Remove old embeddings for this doc
            session.query(Embedding).filter(
                Embedding.doc_id == uuid.UUID(doc_id)
            ).delete()

            chunks = chunk_document(doc.raw_text)
            if not chunks:
                continue

            vectors = embedder.embed_texts([c["content"] for c in chunks])

            for idx, chunk in enumerate(chunks):
                meta = {
                    **chunk["meta"],
                    "source": doc.source,
                    "title": doc.title,
                    "uri": doc.uri,
                    _META_MODEL_KEY: model,
                }
                session.add(Embedding(
                    doc_id=doc.id,
                    chunk_index=idx,
                    content=chunk["content"],
                    embedding=vectors[idx],
                    meta=meta,
                ))
                chunk_count += 1

        session.commit()
        logger.info("Lifecycle reindexed %d chunks for %d docs", chunk_count, len(doc_ids))
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    return chunk_count
