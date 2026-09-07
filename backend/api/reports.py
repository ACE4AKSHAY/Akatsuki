"""
Report Export API route: GET /reports/{scanId}?format=pdf|csv|json
Delegates to the M9 reporting module.
"""
import json
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Scan, Asset, Recommendation
from backend.engine.reporting import generate_report

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{scan_id}")
def export_scan_report(
    scan_id: str,
    format: Literal["pdf", "csv", "xlsx", "json"] = Query("json", description="Report format: pdf, csv, xlsx, or json"),
    db: Session = Depends(get_db),
):
    """
    Generates and downloads a report for the specified scan.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan '{scan_id}' is '{scan.status}'. Reports are only available once scan completes."
        )

    # Fetch flat asset records for CSV/PDF generation
    db_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    assets_data = []

    for a in db_assets:
        rec = db.query(Recommendation).filter(Recommendation.asset_id == a.id).first()
        assets_data.append({
            "id": a.id,
            "bom_ref": a.bom_ref,
            "name": a.name,
            "primitive_category": a.primitive_category,
            "file_path": a.file_path,
            "line_number": a.line_number,
            "library": a.library,
            "risk_tier": a.risk_tier,
            "risk_score": a.risk_score,
            "urgency_ratio_r": a.urgency_ratio_r,
            "shelf_life_x": a.shelf_life_x,
            "migration_effort_y": a.migration_effort_y,
            "threat_timeline_z": a.threat_timeline_z,
            "business_criticality": a.business_criticality,
            "exposure": a.exposure,
            "quantum_vulnerable": a.quantum_vulnerable,
            "recommended_replacement": rec.recommended_algorithm if rec else "",
            "reference_standard": rec.reference_standard if rec else "",
        })

    content_bytes, media_type, filename = generate_report(
        scan_id=scan_id,
        raw_cbom_json=scan.raw_cbom_json or "{}",
        assets_data=assets_data,
        report_format=format,
    )

    return Response(
        content=content_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""},
    )
