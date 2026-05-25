from sqlalchemy import select

from app.db.models.embedding import Embedding
from app.db.models.knowledge_doc import KnowledgeDoc
from app.db.session import SessionLocal
from app.services.rag.embedder import LocalEmbedder


def retrieve_context(
    query: str,
    limit: int = 5,
    sources: list[str] | None = None,
) -> list[dict]:
    embedder = LocalEmbedder()
    query_vector = embedder.embed_query(query)

    session = SessionLocal()
    try:
        distance = Embedding.embedding.cosine_distance(query_vector)
        stmt = (
            select(Embedding, KnowledgeDoc, distance.label("distance"))
            .join(KnowledgeDoc, Embedding.doc_id == KnowledgeDoc.id)
            .where(Embedding.embedding.isnot(None))
        )

        if sources:
            stmt = stmt.where(KnowledgeDoc.source.in_(sources))

        stmt = stmt.order_by(distance).limit(limit)
        results = session.execute(stmt).all()

        context = []
        for embedding, doc, dist in results:
            context.append(
                {
                    "content": embedding.content,
                    "source": doc.source,
                    "title": doc.title,
                    "uri": doc.uri,
                    "score": float(dist) if dist is not None else None,
                    "metadata": embedding.meta,
                }
            )
        return context
    finally:
        session.close()
