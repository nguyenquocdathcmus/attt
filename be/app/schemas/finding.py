from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    type: str
    severity: str
    title: str
    description: str | None
    evidence: dict | None
    cwe: str | None
    owasp: str | None
    false_positive_score: float | None
    risk_score: float | None
    remediation: dict | None
    created_at: datetime
