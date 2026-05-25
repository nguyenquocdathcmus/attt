from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class KnowledgeIngest(BaseModel):
    source: str
    title: str | None = None
    uri: str | None = None
    raw_text: str | None = None


class KnowledgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source: str
    title: str | None
    uri: str | None
    raw_text: str | None
    created_at: datetime
