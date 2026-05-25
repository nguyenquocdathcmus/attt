from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AssetCreate(BaseModel):
    url: str
    owner: str | None = None
    tags: list[str] | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    url: str
    owner: str | None
    tags: list[str] | None
    created_at: datetime
