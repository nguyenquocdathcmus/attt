"""
RAG Celery tasks.

Tasks:
  rag.ingest          — chunk + embed a KnowledgeDoc
  rag.reindex_stale   — lifecycle task (beat, every 1h): re-embed stale chunks
"""
import logging
import uuid

from app.core.celery_app import celery_app
from app.db.models.embedding import Embedding
from app.db.models.knowledge_doc import KnowledgeDoc
from app.db.session import SessionLocal
from app.services.rag.chunker import chunk_document
from app.services.rag.embedder import LocalEmbedder

logger = logging.getLogger(__name__)

_CONTEXT_PROMPT = """You are a technical documentation assistant.
Given the following chunk of security documentation, write 1-2 sentences that
provide broader context for this chunk (what section it belongs to, what
vulnerability category it covers). Be concise.

Chunk:
{chunk}

Context sentences (output ONLY the context, no preamble):"""


def _enrich_chunk(content: str) -> str:
    """Prepend 1-2 LLM-generated context sentences to a chunk before embedding."""
    try:
        from app.services.ai.ollama_client import generate
        context = generate(_CONTEXT_PROMPT.format(chunk=content[:800])).strip()
        if context and len(context) < 300:
            return f"{context}\n\n{content}"
    except Exception as exc:
        logger.debug("Context enrichment failed (skipping): %s", exc)
    return content


@celery_app.task(
    name="rag.ingest",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": 2},
)
def ingest_knowledge(doc_id: str, enrich: bool = True) -> dict:
    """
    Chunk, (optionally) enrich, and embed a KnowledgeDoc.

    Args:
        doc_id:  UUID string of the KnowledgeDoc to process.
        enrich:  If True, prepend LLM-generated context to each chunk before
                 embedding (Sprint 3.6 contextual enrichment).
    """
    from app.core.config import settings
    from app.services.rag.lifecycle import stamp_embeddings

    session = SessionLocal()
    try:
        doc = session.get(KnowledgeDoc, uuid.UUID(doc_id))
        if not doc or not doc.raw_text:
            return {"doc_id": doc_id, "status": "skipped"}

        # Remove stale embeddings
        session.query(Embedding).filter(Embedding.doc_id == doc.id).delete()
        session.commit()

        chunks = chunk_document(doc.raw_text)
        if not chunks:
            return {"doc_id": doc_id, "status": "empty"}

        # Optionally enrich each chunk with LLM-generated context sentences
        contents = [
            _enrich_chunk(chunk["content"]) if enrich else chunk["content"]
            for chunk in chunks
        ]

        embedder = LocalEmbedder()
        vectors = embedder.embed_texts(contents)

        for index, chunk in enumerate(chunks):
            meta = {
                **chunk["meta"],
                "source": doc.source,
                "title": doc.title,
                "uri": doc.uri,
                "embedder_model": settings.embeddings_model,
                "enriched": enrich,
            }
            session.add(Embedding(
                doc_id=doc.id,
                chunk_index=index,
                content=contents[index],
                embedding=vectors[index],
                meta=meta,
            ))

        session.commit()
        stamp_embeddings(doc_id)
        return {"doc_id": doc_id, "status": "ok", "chunks": len(chunks)}
    finally:
        session.close()


@celery_app.task(
    name="rag.reindex_stale",
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 1},
)
def reindex_stale_embeddings(batch_size: int = 50) -> dict:
    """
    Celery beat task — run every 1 hour.
    Detects and reindexes any embeddings created with an outdated model.
    """
    from app.services.rag.lifecycle import reindex_stale
    result = reindex_stale(batch_size=batch_size)
    logger.info("reindex_stale result: %s", result)
    return result
