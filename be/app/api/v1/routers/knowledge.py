from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.models.knowledge_doc import KnowledgeDoc
from app.db.session import get_db
from app.schemas.knowledge import KnowledgeIngest, KnowledgeOut
from app.tasks.rag_tasks import ingest_knowledge

router = APIRouter()

ANALYST_ROLES = ["analyst", "admin"]
ADMIN_ROLES = ["admin"]


@router.post("/ingest", response_model=KnowledgeOut)
def ingest_doc(
    payload: KnowledgeIngest,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ADMIN_ROLES)),
) -> KnowledgeDoc:
    doc = KnowledgeDoc(
        source=payload.source,
        title=payload.title,
        uri=payload.uri,
        raw_text=payload.raw_text,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    ingest_knowledge.apply_async((str(doc.id),), queue="rag", priority=5)
    return doc


@router.get("", response_model=list[KnowledgeOut])
def list_docs(
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> list[KnowledgeDoc]:
    return db.query(KnowledgeDoc).order_by(KnowledgeDoc.created_at.desc()).all()
