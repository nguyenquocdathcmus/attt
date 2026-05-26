from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, computed_field

from app.services.ai.cwe_mapper import cwe_name as _cwe_name


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
    cvss_score: float | None
    cvss_vector: str | None
    duplicate_group: str | None
    remediation: dict | None
    created_at: datetime

    @computed_field
    @property
    def cwe_name(self) -> str | None:
        return _cwe_name(self.cwe) if self.cwe else None
