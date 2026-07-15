"""
config/database.py
------------------
Database connection, session management, and ORM base.
Supports SQLite (dev) and PostgreSQL (production) via DATABASE_URL.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from engine.config.settings import DB_URL

# ── Engine ────────────────────────────────────────────────────
_connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}

engine = create_engine(
    DB_URL,
    connect_args=_connect_args,
    echo=False,
    pool_pre_ping=True,
)

# ── Session factory ───────────────────────────────────────────
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# ── Declarative base — all ORM models inherit this ───────────
Base = declarative_base()


# ── FastAPI dependency ────────────────────────────────────────
def get_db():
    """
    Yield a DB session; close it when the request ends.

    Usage in FastAPI:
        from fastapi import Depends
        from sqlalchemy.orm import Session

        @router.get("/items")
        def items(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Startup helper ────────────────────────────────────────────
def init_db():
    """
    Create all tables that are registered with Base.
    Called once at app startup (app.py on_event("startup")).
    """
    # Import every ORM model so SQLAlchemy knows about them
    # before calling create_all().
    from engine.database.models import scan_session   # noqa: F401
    from engine.database.models import vulnerability  # noqa: F401
    from engine.database.models import exploit_result # noqa: F401
    from engine.database.models import mitre_finding  # noqa: F401
    from engine.database.models import report         # noqa: F401

    Base.metadata.create_all(bind=engine)
    print("[DB] All tables created / verified.")


# ── Health-check ──────────────────────────────────────────────
def ping() -> bool:
    """Return True if the database is reachable."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        print(f"[DB] Ping failed: {exc}")
        return False
