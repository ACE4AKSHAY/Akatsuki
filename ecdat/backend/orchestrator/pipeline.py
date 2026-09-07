"""Scan pipeline orchestrator (M7).

Connects M4 Normalizer -> M5 Risk Assessment Engine -> M6 Recommendation Engine -> Storage.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.db import AssetRecord, ScanRecord, SessionLocal
from backend.engine.normalizer import build_cbom_document, normalize
from backend.engine.recommend import recommend
from backend.engine.risk import score_assets
from backend.models.schemas import (
    CBOMAsset,
    CBOMDocument,
    ConstraintConfig,
    RawFinding,
    RiskWeights,
    ThreatModelConfig,
)


def run_pipeline(
    raw_findings: list[RawFinding | dict[str, Any]],
    scan_id: str,
    source_type: str = "path",
    target: str = "local",
    threat_model: ThreatModelConfig | None = None,
    weights: RiskWeights | None = None,
    constraints: ConstraintConfig | None = None,
    tagging_config: dict[str, Any] | None = None,
    db: Session | None = None,
) -> CBOMDocument:
    """Execute the complete M4 -> M5 -> M6 cryptographic analysis pipeline."""
    close_db_when_done = False
    if db is None:
        db = SessionLocal()
        close_db_when_done = True

    try:
        # Step 1: M4 CBOM Normalization and Deduplication
        normalized_assets = normalize(raw_findings, tagging_config=tagging_config)

        # Step 2: M5 Quantum Risk Assessment
        scored_assets = score_assets(normalized_assets, threat_model=threat_model, weights=weights)

        # Step 3: M6 PQC / Hybrid Recommendations
        recommended_assets = recommend(scored_assets, constraints=constraints)

        # Step 4: Wrap into CycloneDX 1.6 Document
        cbom_doc = build_cbom_document(
            assets=recommended_assets,
            serial_number=f"urn:uuid:{scan_id}",
        )
        cbom_json_str = cbom_doc.model_dump_json(by_alias=True, indent=2)

        # Output canonical per-scan CBOM file (cbom.json) per Section 7 / M4
        try:
            from pathlib import Path
            export_dir = Path("exports") / scan_id
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "cbom.json").write_text(cbom_json_str, encoding="utf-8")
        except Exception:
            pass

        # Step 5: Persist Scan Record
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        now_str = datetime.now(timezone.utc).isoformat()
        if not scan:
            scan = ScanRecord(
                id=scan_id,
                source_type=source_type,
                target=target,
                status="completed",
                progress=1.0,
                findings_count=len(raw_findings),
                assets_count=len(recommended_assets),
                created_at=now_str,
                completed_at=now_str,
                cbom_json=cbom_json_str,
            )
            db.add(scan)
        else:
            scan.status = "completed"
            scan.progress = 1.0
            scan.findings_count = len(raw_findings)
            scan.assets_count = len(recommended_assets)
            scan.completed_at = now_str
            scan.cbom_json = cbom_json_str

        # Clear existing assets for this scan_id to allow re-runs
        db.query(AssetRecord).filter(AssetRecord.scan_id == scan_id).delete()

        # Step 6: Persist Individual Indexed Assets
        for asset in recommended_assets:
            enr = asset.ecdatEnrichment
            rec = AssetRecord(
                id=f"{scan_id}_{asset.bom_ref}",
                bom_ref=asset.bom_ref,
                scan_id=scan_id,
                name=asset.name,
                primitive=asset.cryptoProperties.algorithmProperties.primitive,
                risk_tier=enr.moscaRiskTier,
                business_criticality=enr.businessCriticality,
                exposure=enr.exposure,
                quantum_vulnerable=enr.quantumVulnerable,
                mosca_x=enr.moscaX,
                mosca_y=enr.moscaY,
                mosca_z=enr.moscaZ,
                mosca_r=enr.moscaR,
                risk_score=enr.riskScore or 0.0,
                raw_json=asset.model_dump_json(by_alias=True),
            )
            db.add(rec)

        db.commit()
        return cbom_doc

    finally:
        if close_db_when_done:
            db.close()
