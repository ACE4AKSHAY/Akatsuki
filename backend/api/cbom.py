"""
CBOM Export API route: GET /cbom/{scanId}
Exports CycloneDX 1.6 Cryptographic Bill of Materials JSON document.
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Scan

router = APIRouter(prefix="/cbom", tags=["CBOM"])


@router.get("/{scan_id}")
def download_cbom_json(scan_id: str, db: Session = Depends(get_db)):
    """
    Returns the standardized CycloneDX 1.6 CBOM document for the specified scan ID.
    Delivered with Content-Disposition: attachment.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan '{scan_id}' is currently in state '{scan.status}'. CBOM is only available once completed."
        )

    content = scan.raw_cbom_json or "{}"
    filename = f"cyclonedx-cbom-{scan_id}.json"

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=\"{filename}\"",
            "X-CycloneDX-Spec": "1.6",
        },
    )
