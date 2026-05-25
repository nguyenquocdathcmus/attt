from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    asset_id: UUID
    scanner: str = Field(examples=["zap", "nikto"])
    config: dict | None = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    status: str
    scanner: str
    started_at: datetime | None
    finished_at: datetime | None
    config: dict | None
    created_at: datetime
