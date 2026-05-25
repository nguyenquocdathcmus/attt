import uuid

from app.core.celery_app import celery_app
from app.db.models.embedding import Embedding
from app.db.models.knowledge_doc import KnowledgeDoc
from app.db.session import SessionLocal
from app.services.rag.chunker import chunk_document
from app.services.rag.embedder import LocalEmbedder


@celery_app.task(
    name="rag.ingest",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": 2},
)
def ingest_knowledge(doc_id: str) -> dict:
    session = SessionLocal()
    try:
        doc = session.get(KnowledgeDoc, uuid.UUID(doc_id))
        if not doc or not doc.raw_text:
            return {"doc_id": doc_id, "status": "skipped"}

        session.query(Embedding).filter(Embedding.doc_id == doc.id).delete()
        session.commit()

        chunks = chunk_document(doc.raw_text)
        if not chunks:
            return {"doc_id": doc_id, "status": "empty"}

        embedder = LocalEmbedder()
        vectors = embedder.embed_texts([chunk["content"] for chunk in chunks])

        for index, chunk in enumerate(chunks):
            meta = {
                **chunk["meta"],
                "source": doc.source,
                "title": doc.title,
                "uri": doc.uri,
            }
            session.add(
                Embedding(
                    doc_id=doc.id,
                    chunk_index=index,
                    content=chunk["content"],
                    embedding=vectors[index],
                    meta=meta,
                )
            )

        session.commit()
        return {"doc_id": doc_id, "status": "ok", "chunks": len(chunks)}
    finally:
        session.close()
