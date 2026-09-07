"""
SQLAlchemy database models for ECDAT.
Indexed fields for fast asset filtering, and JSON columns for full CBOM data.
"""
from datetime import datetime
import json
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from backend.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    source_type = Column(String(32), nullable=False)
    target = Column(Text, nullable=False)
    status = Column(String(32), default="queued", index=True)
    progress = Column(Float, default=0.0)
    asset_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    raw_cbom_json = Column(Text, nullable=True)

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), nullable=False, index=True)
    bom_ref = Column(String(64), nullable=False)
    name = Column(String(64), nullable=False, index=True)
    primitive_category = Column(String(64), nullable=True)
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    library = Column(String(128), nullable=True)

    # Risk & Mosca parameters
    risk_tier = Column(String(32), nullable=False, index=True)  # Critical, High, Medium, Low
    risk_score = Column(Float, nullable=False)
    business_criticality = Column(String(32), nullable=False, index=True)
    exposure = Column(String(32), nullable=False, index=True)

    shelf_life_x = Column(Float, nullable=False)
    migration_effort_y = Column(Float, nullable=False)
    threat_timeline_z = Column(Float, nullable=False)
    urgency_ratio_r = Column(Float, nullable=False)
    quantum_vulnerable = Column(Boolean, default=True)

    # Full canonical JSON payload
    asset_json = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="assets")
    recommendations = relationship("Recommendation", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_asset_filter", "scan_id", "risk_tier", "business_criticality", "exposure"),
    )


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(String(64), primary_key=True, index=True)
    asset_id = Column(String(64), ForeignKey("assets.id"), nullable=False, index=True)
    recommended_algorithm = Column(String(128), nullable=False)
    mode = Column(String(64), nullable=False)
    complexity = Column(String(32), nullable=False)
    rationale = Column(Text, nullable=True)
    reference_standard = Column(String(128), nullable=True)

    asset = relationship("Asset", back_populates="recommendations")


class ThreatModelConfig(Base):
    __tablename__ = "threat_model_config"

    id = Column(Integer, primary_key=True, default=1)
    threat_timeline_z = Column(Float, default=8.0)
    weights_json = Column(Text, nullable=False)
    shelf_life_json = Column(Text, nullable=False)
    migration_effort_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
