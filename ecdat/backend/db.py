"""Database layer for ECDAT backend (M7).

Uses SQLAlchemy with SQLite default for zero-ops local deployment and testing,
while maintaining full compatibility with PostgreSQL.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DB_URL = os.getenv("ECDAT_DB_URL", "sqlite:///./ecdat.db")

# SQLite connection args for multithreaded FastAPI access
connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}

engine = create_engine(DB_URL, echo=False, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    """Stores scan job metadata and raw CBOM output."""

    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    source_type = Column(String(32), nullable=False)
    target = Column(String(512), nullable=False)
    status = Column(String(32), default="queued", index=True)  # queued, running, completed, failed
    progress = Column(Float, default=0.0)
    findings_count = Column(Integer, default=0)
    assets_count = Column(Integer, default=0)
    created_at = Column(String(64), default=lambda: datetime.now(timezone.utc).isoformat())
    completed_at = Column(String(64), nullable=True)
    cbom_json = Column(Text, nullable=True)


class AssetRecord(Base):
    """Indexed relational storage for individual canonical CBOM assets."""

    __tablename__ = "assets"

    id = Column(String(128), primary_key=True)  # unique internal row id
    bom_ref = Column(String(128), index=True, nullable=False)  # CycloneDX bom-ref
    scan_id = Column(String(64), index=True, nullable=False)
    name = Column(String(128), index=True, nullable=False)
    primitive = Column(String(64), index=True, nullable=False)
    risk_tier = Column(String(32), index=True, nullable=False)
    business_criticality = Column(String(32), index=True, nullable=False)
    exposure = Column(String(32), index=True, nullable=False)
    quantum_vulnerable = Column(Boolean, default=True)
    mosca_x = Column(Float, default=3.0)
    mosca_y = Column(Float, default=0.5)
    mosca_z = Column(Float, default=8.0)
    mosca_r = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    raw_json = Column(Text, nullable=False)


class ThreatModelRecord(Base):
    """Persistent threat model configuration."""

    __tablename__ = "threat_model_config"

    id = Column(Integer, primary_key=True)
    threat_timeline_years = Column(Float, default=8.0)
    config_json = Column(Text, nullable=False)


def init_db() -> None:
    """Create database tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


# Auto-initialize tables
init_db()


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
