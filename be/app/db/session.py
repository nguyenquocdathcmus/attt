import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _seed_default_users() -> None:
    """Create default demo users if they don't exist yet."""
    from app.core.security import get_password_hash
    from app.db.models.user import User

    defaults = [
        ("admin",   "admin123",   ["admin"]),
        ("analyst", "analyst123", ["analyst"]),
        ("viewer",  "viewer123",  ["viewer"]),
    ]

    db: Session = SessionLocal()
    try:
        for username, password, roles in defaults:
            if not db.query(User).filter(User.username == username).first():
                db.add(User(
                    username=username,
                    hashed_password=get_password_hash(password),
                    roles=roles,
                ))
        db.commit()
        logger.info("Default users seeded")
    except Exception as exc:
        db.rollback()
        logger.warning("Failed to seed default users: %s", exc)
    finally:
        db.close()


def init_db() -> None:
    """Run Alembic migrations on startup, then seed default users."""
    try:
        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config("alembic.ini")
        # Always override with runtime DATABASE_URL so Docker env vars win
        alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url)
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations applied successfully")
    except Exception as exc:
        # Degraded mode: fall back to create_all so the app can still start
        logger.warning("Alembic migration failed (%s), falling back to create_all", exc)
        from app.db.models.base import Base
        import app.db.models  # noqa: F401
        Base.metadata.create_all(bind=engine)

    _seed_default_users()
