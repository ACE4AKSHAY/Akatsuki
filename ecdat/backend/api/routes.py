"""FastAPI routing layer for ECDAT (M7).

Exposes scan lifecycle, asset inventory, dynamic Z risk recalculation,
CycloneDX 1.6 CBOM export, and reporting endpoints.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db import AssetRecord, ScanRecord, ThreatModelRecord, get_db
from backend.engine.risk.risk_engine import is_classically_broken
from backend.models.schemas import (
    CBOMAsset,
    CBOMDocument,
    ConstraintConfig,
    RawFinding,
    RiskWeights,
    ThreatModelConfig,
)
from backend.orchestrator.pipeline import run_pipeline

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class ScanCreateRequest(BaseModel):
    sourceType: Literal["git", "upload", "image", "path"] = "path"
    target: str = "src/"
    rawFindings: list[RawFinding | dict[str, Any]] = Field(default_factory=list)
    threatModel: ThreatModelConfig | None = None
    weights: RiskWeights | None = None
    constraints: ConstraintConfig | None = None
    taggingConfig: dict[str, Any] | None = None


class ScanResponse(BaseModel):
    scanId: str
    status: str
    createdAt: str
    message: str | None = None


class ScanDetailResponse(BaseModel):
    id: str
    sourceType: str
    target: str
    status: str
    progress: float
    findingsCount: int
    assetsCount: int
    createdAt: str
    completedAt: str | None = None


class AssetListResponse(BaseModel):
    total: int
    page: int
    pageSize: int
    assets: list[CBOMAsset]


# ---------------------------------------------------------------------------
# Scan Lifecycle Endpoints
# ---------------------------------------------------------------------------

@router.post("/scans", response_model=ScanResponse)
def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Initiate a scan job.

    Accepts raw findings directly or launches discovery over the target.
    """
    scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y_%m_%d')}_{uuid.uuid4().hex[:6]}"
    now_str = datetime.now(timezone.utc).isoformat()

    # If raw findings were supplied (e.g. from M1-M3 or test harness), run immediately
    if request.rawFindings:
        run_pipeline(
            raw_findings=request.rawFindings,
            scan_id=scan_id,
            source_type=request.sourceType,
            target=request.target,
            threat_model=request.threatModel,
            weights=request.weights,
            constraints=request.constraints,
            tagging_config=request.taggingConfig,
            db=db,
        )
        return ScanResponse(
            scanId=scan_id,
            status="completed",
            createdAt=now_str,
            message="Scan pipeline executed successfully.",
        )

    # Otherwise enqueue for background execution
    scan = ScanRecord(
        id=scan_id,
        source_type=request.sourceType,
        target=request.target,
        status="queued",
        progress=0.0,
        findings_count=0,
        assets_count=0,
        created_at=now_str,
    )
    db.add(scan)
    db.commit()

    background_tasks.add_task(
        run_pipeline,
        raw_findings=[],
        scan_id=scan_id,
        source_type=request.sourceType,
        target=request.target,
        threat_model=request.threatModel,
        weights=request.weights,
        constraints=request.constraints,
        tagging_config=request.taggingConfig,
    )

    return ScanResponse(
        scanId=scan_id,
        status="queued",
        createdAt=now_str,
        message="Scan queued for background execution.",
    )


@router.get("/scans", response_model=list[ScanDetailResponse])
def list_scans(db: Session = Depends(get_db)):
    """List all discovery scans."""
    records = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).all()
    return [
        ScanDetailResponse(
            id=r.id,
            sourceType=r.source_type,
            target=r.target,
            status=r.status,
            progress=r.progress,
            findingsCount=r.findings_count,
            assetsCount=r.assets_count,
            createdAt=r.created_at,
            completedAt=r.completed_at,
        )
        for r in records
    ]


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve status and metadata for a specific scan."""
    r = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return ScanDetailResponse(
        id=r.id,
        sourceType=r.source_type,
        target=r.target,
        status=r.status,
        progress=r.progress,
        findingsCount=r.findings_count,
        assetsCount=r.assets_count,
        createdAt=r.created_at,
        completedAt=r.completed_at,
    )


# ---------------------------------------------------------------------------
# Asset Inventory & Dynamic Z Re-scoring
# ---------------------------------------------------------------------------

@router.get("/assets", response_model=AssetListResponse)
def list_assets(
    scanId: str | None = Query(None, description="Filter by scanId"),
    risk: str | None = Query(None, description="Filter by risk tier (Critical, High, Medium, Low)"),
    riskTier: str | None = Query(None, description="Filter by risk tier (Critical, High, Medium, Low)"),
    exposure: str | None = Query(None, description="Filter by exposure"),
    businessCriticality: str | None = Query(None, description="Filter by business criticality"),
    algorithm: str | None = Query(None, description="Filter by algorithm name"),
    quantumVulnerable: bool | None = Query(None, description="Filter by quantum vulnerability"),
    z: float | None = Query(None, description="Dynamic Z slider override for real-time recalculation"),
    page: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Query canonical CBOM assets with multi-parameter filtering and dynamic Z re-scoring.

    When `z` is provided, urgency ratio r and risk tier are recalculated on the fly
    without requiring a full scan re-execution.
    """
    effective_risk = risk or riskTier
    q = db.query(AssetRecord)

    if scanId:
        q = q.filter(AssetRecord.scan_id == scanId)
    if effective_risk and not z:
        q = q.filter(AssetRecord.risk_tier == effective_risk)
    if exposure:
        q = q.filter(AssetRecord.exposure == exposure)
    if businessCriticality:
        q = q.filter(AssetRecord.business_criticality == businessCriticality)
    if algorithm:
        q = q.filter(AssetRecord.name.ilike(f"%{algorithm}%"))
    if quantumVulnerable is not None:
        q = q.filter(AssetRecord.quantum_vulnerable == quantumVulnerable)

    total_count = q.count()
    records = q.offset((page - 1) * pageSize).limit(pageSize).all()

    assets: list[CBOMAsset] = []
    for rec in records:
        data = json.loads(rec.raw_json)
        asset = CBOMAsset.model_validate(data)

        # Apply dynamic Z slider re-scoring if requested
        if z is not None and z > 0:
            x = asset.ecdatEnrichment.moscaX
            y = asset.ecdatEnrichment.moscaY
            new_r = round((x + y) / z, 2)
            asset.ecdatEnrichment.moscaZ = z
            asset.ecdatEnrichment.moscaR = new_r

            # Classically broken primitives stay Critical unconditionally
            if not is_classically_broken(asset.name):
                if new_r >= 1.2:
                    asset.ecdatEnrichment.moscaRiskTier = "Critical"
                elif new_r >= 0.9:
                    asset.ecdatEnrichment.moscaRiskTier = "High"
                elif new_r >= 0.6:
                    asset.ecdatEnrichment.moscaRiskTier = "Medium"
                else:
                    asset.ecdatEnrichment.moscaRiskTier = "Low"

        # If filtering by risk while dynamic z is applied
        if effective_risk and z:
            if asset.ecdatEnrichment.moscaRiskTier != effective_risk:
                continue

        assets.append(asset)

    return AssetListResponse(
        total=total_count,
        page=page,
        pageSize=pageSize,
        assets=assets,
    )


@router.get("/assets/{asset_id}", response_model=CBOMAsset)
def get_asset_detail(asset_id: str, db: Session = Depends(get_db)):
    """Retrieve full detail for a single canonical CBOM asset."""
    rec = db.query(AssetRecord).filter(
        (AssetRecord.id == asset_id) | (AssetRecord.bom_ref == asset_id)
    ).first()
    if not rec:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    data = json.loads(rec.raw_json)
    return CBOMAsset.model_validate(data)


# ---------------------------------------------------------------------------
# CBOM Export & Reporting (M9 Integration)
# ---------------------------------------------------------------------------

@router.get("/cbom/{scan_id}")
def export_cbom(scan_id: str, db: Session = Depends(get_db)):
    """Download the raw CycloneDX 1.6 CBOM document for a scan."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan or not scan.cbom_json:
        raise HTTPException(status_code=404, detail=f"CBOM for scan {scan_id} not found")

    return Response(
        content=scan.cbom_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="cbom-{scan_id}.json"',
        },
    )


@router.get("/reports/{scan_id}")
def get_report(
    scan_id: str,
    format: Literal["pdf", "csv", "json"] = Query("json"),
    db: Session = Depends(get_db),
):
    """Generate and download executive reports in CSV, JSON, or printable HTML/PDF."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    assets = db.query(AssetRecord).filter(AssetRecord.scan_id == scan_id).all()

    if format == "json":
        return {
            "scanId": scan_id,
            "status": scan.status,
            "findingsCount": scan.findings_count,
            "assetsCount": len(assets),
            "createdAt": scan.created_at,
            "completedAt": scan.completed_at,
            "cbom": json.loads(scan.cbom_json) if scan.cbom_json else {},
        }

    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "bom-ref", "name", "primitive", "riskTier", "riskScore",
            "businessCriticality", "exposure", "quantumVulnerable",
            "moscaX", "moscaY", "moscaZ", "moscaR",
            "recommendedReplacement", "referenceStandard", "location",
        ])
        for a in assets:
            parsed = json.loads(a.raw_json)
            enr = parsed.get("ecdatEnrichment", {})
            occs = parsed.get("occurrences", [])
            loc = occs[0].get("location", "") if occs else ""
            writer.writerow([
                a.id, a.name, a.primitive, a.risk_tier, a.risk_score,
                a.business_criticality, a.exposure, a.quantum_vulnerable,
                a.mosca_x, a.mosca_y, a.mosca_z, a.mosca_r,
                enr.get("recommendedReplacement", ""),
                enr.get("referenceStandard", ""),
                loc,
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="report-{scan_id}.csv"',
            },
        )

    elif format == "pdf":
        # Generate executive HTML summary suitable for print/PDF conversion
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ECDAT Executive Post-Quantum Security Report — {scan_id}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 40px; color: #1e293b; line-height: 1.5; }}
    h1 {{ color: #0f172a; margin-bottom: 4px; }}
    .subtitle {{ color: #64748b; font-size: 14px; margin-bottom: 24px; }}
    .summary-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
    th {{ background: #f1f5f9; color: #475569; font-weight: 600; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; text-transform: uppercase; }}
    .badge-critical {{ background: #fee2e2; color: #991b1b; }}
    .badge-high {{ background: #ffedd5; color: #9a3412; }}
    .badge-medium {{ background: #fef9c3; color: #854d0e; }}
    .badge-low {{ background: #dcfce7; color: #166534; }}
  </style>
</head>
<body>
  <h1>ECDAT Cryptographic Security Report</h1>
  <div class="subtitle">Scan Target: {scan.target} · Scan ID: {scan_id} · Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>

  <div class="summary-card">
    <h3>Executive Posture Summary</h3>
    <p>Discovered <strong>{len(assets)}</strong> canonical cryptographic assets across <strong>{scan.findings_count}</strong> detection signals.</p>
  </div>

  <h3>Asset Risk & PQC Recommendations</h3>
  <table>
    <thead>
      <tr>
        <th>Asset</th>
        <th>Primitive</th>
        <th>Risk Tier</th>
        <th>r = (X+Y)/Z</th>
        <th>Criticality</th>
        <th>Recommended Replacement</th>
        <th>Standard</th>
      </tr>
    </thead>
    <tbody>
"""
        for a in assets:
            parsed = json.loads(a.raw_json)
            enr = parsed.get("ecdatEnrichment", {})
            badge_class = f"badge-{a.risk_tier.lower()}"
            html += f"""      <tr>
        <td><strong>{a.name}</strong></td>
        <td>{a.primitive}</td>
        <td><span class="badge {badge_class}">{a.risk_tier}</span></td>
        <td>{a.mosca_r}</td>
        <td>{a.business_criticality}</td>
        <td>{enr.get('recommendedReplacement', '')}</td>
        <td>{enr.get('referenceStandard', '')}</td>
      </tr>\n"""
        html += """    </tbody>
  </table>
</body>
</html>"""
        return Response(
            content=html,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="report-{scan_id}.html"',
            },
        )


# ---------------------------------------------------------------------------
# Threat Model Configuration
# ---------------------------------------------------------------------------

@router.get("/config/threat-model", response_model=ThreatModelConfig)
def get_threat_model(db: Session = Depends(get_db)):
    """Fetch stored default threat model assumptions."""
    rec = db.query(ThreatModelRecord).filter(ThreatModelRecord.id == 1).first()
    if rec:
        return ThreatModelConfig.model_validate_json(rec.config_json)
    return ThreatModelConfig()


@router.patch("/config/threat-model", response_model=ThreatModelConfig)
def update_threat_model(
    config: ThreatModelConfig,
    db: Session = Depends(get_db),
):
    """Update stored default threat model assumptions."""
    rec = db.query(ThreatModelRecord).filter(ThreatModelRecord.id == 1).first()
    cfg_json = config.model_dump_json()
    if not rec:
        rec = ThreatModelRecord(
            id=1,
            threat_timeline_years=config.threatTimelineYears,
            config_json=cfg_json,
        )
        db.add(rec)
    else:
        rec.threat_timeline_years = config.threatTimelineYears
        rec.config_json = cfg_json
    db.commit()
    return config


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@router.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "1.0.0"}
