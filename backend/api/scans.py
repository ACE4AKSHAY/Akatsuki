"""
Scan lifecycle API routes: POST /scans, GET /scans/{id}, GET /scans
"""
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Scan
from backend.models.schemas import ScanCreate, ScanResponse
from backend.engine.orchestrator import run_scan_pipeline_sync

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(
    request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Kicks off an asynchronous cryptographic discovery scan.
    Returns immediately with a scanId and 'queued' status.
    """
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"

    new_scan = Scan(
        id=scan_id,
        source_type=request.sourceType,
        target=request.target,
        status="queued",
        progress=0.0,
        asset_count=0,
        created_at=datetime.utcnow(),
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Dispatch to background task execution
    background_tasks.add_task(
        run_scan_pipeline_sync,
        scan_id=scan_id,
        source_type=request.sourceType,
        target=request.target,
        compliance_target=request.complianceTarget or "NIST-general",
        threat_timeline_override=request.threatTimelineOverride,
    )

    return ScanResponse(
        scanId=new_scan.id,
        sourceType=new_scan.source_type,
        target=new_scan.target,
        status=new_scan.status,
        progress=new_scan.progress,
        assetCount=new_scan.asset_count,
        createdAt=new_scan.created_at.isoformat(),
        completedAt=new_scan.completed_at.isoformat() if new_scan.completed_at else None,
        error=new_scan.error,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Polls the status of an ongoing or completed scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    return ScanResponse(
        scanId=scan.id,
        sourceType=scan.source_type,
        target=scan.target,
        status=scan.status,
        progress=scan.progress,
        assetCount=scan.asset_count,
        createdAt=scan.created_at.isoformat(),
        completedAt=scan.completed_at.isoformat() if scan.completed_at else None,
        error=scan.error,
    )


@router.get("", response_model=List[ScanResponse])
def list_scans(limit: int = 20, db: Session = Depends(get_db)):
    """Lists recent scans."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
    return [
        ScanResponse(
            scanId=s.id,
            sourceType=s.source_type,
            target=s.target,
            status=s.status,
            progress=s.progress,
            assetCount=s.asset_count,
            createdAt=s.created_at.isoformat(),
            completedAt=s.completed_at.isoformat() if s.completed_at else None,
            error=s.error,
        )
        for s in scans
    ]
