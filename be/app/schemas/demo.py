from uuid import UUID

from pydantic import BaseModel


class SeedOut(BaseModel):
    asset_id: UUID
    scan_id: UUID
    finding_ids: list[UUID]
    report_id: UUID
