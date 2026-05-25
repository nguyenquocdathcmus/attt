import logging

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.models.base import Base
from app.db import models  # noqa: F401

logger = logging.getLogger(__name__)

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation JSONB",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS raw_output JSONB",
]


def init_db() -> None:
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        logger.warning("DB init skipped: %s", exc)

    with engine.begin() as conn:
        for stmt in _MIGRATIONS:
            try:
                conn.execute(text(stmt))
            except Exception as exc:
                logger.warning("Migration skipped (%s): %s", stmt, exc)
