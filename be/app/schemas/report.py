from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ReportCreate(BaseModel):
    scan_id: UUID
    report_type: str = "executive"


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    report_type: str
    content: dict
    created_at: datetime
