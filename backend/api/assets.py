"""
Asset Inventory & Detail API routes: GET /assets, GET /assets/{id}
Supports filtering and dynamic Z-slider re-scoring for interactive heatmap simulator.
"""
import json
import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Asset, Recommendation
from backend.models.schemas import (
    AssetSummaryResponse,
    AssetDetailResponse,
    CanonicalCBOMAsset,
)
from backend.engine.risk import calculate_mosca_ratio, get_mosca_tier

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=AssetSummaryResponse)
def list_assets(
    scanId: Optional[str] = Query(None, description="Filter by scan job ID"),
    riskTier: Optional[str] = Query(None, description="Filter by risk tier (Critical, High, Medium, Low)"),
    exposure: Optional[str] = Query(None, description="Filter by exposure (external-facing, internal-only)"),
    businessCriticality: Optional[str] = Query(None, description="Filter by business criticality"),
    algorithm: Optional[str] = Query(None, description="Filter by algorithm name (e.g. SHA-1, RSA-2048)"),
    page: int = Query(1, ge=1, description="Page number"),
    pageSize: int = Query(50, ge=1, le=200, description="Items per page"),
    z: Optional[float] = Query(None, ge=0.5, le=50.0, description="Interactive threat-timeline Z slider override"),
    db: Session = Depends(get_db),
):
    """
    Returns paginated assets matching filter criteria.
    If 'z' query parameter is provided, recomputes Mosca r = (X+Y)/Z and risk tier dynamically!
    """
    query = db.query(Asset)

    if scanId:
        query = query.filter(Asset.scan_id == scanId)
    if exposure:
        query = query.filter(Asset.exposure.ilike(f"%{exposure}%"))
    if businessCriticality:
        query = query.filter(Asset.business_criticality.ilike(f"%{businessCriticality}%"))
    if algorithm:
        query = query.filter(Asset.name.ilike(f"%{algorithm}%"))

    all_matching_db_assets = query.all()

    # Recompute risk tier if Z slider is active, or use stored tier
    parsed_assets = []
    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0

    for db_asset in all_matching_db_assets:
        try:
            asset_dict = json.loads(db_asset.asset_json)
        except Exception:
            continue

        enrichment = asset_dict.get("ecdatEnrichment", {})

        # If dynamic Z is requested
        if z is not None and z > 0:
            x = db_asset.shelf_life_x
            y = db_asset.migration_effort_y
            r_dyn = calculate_mosca_ratio(x, y, z)
            
            # Check auto-escalation
            if enrichment.get("autoEscalated"):
                current_tier = "Critical"
            else:
                current_tier = get_mosca_tier(r_dyn)

            enrichment["moscaZ"] = z
            enrichment["moscaR"] = r_dyn
            enrichment["moscaRiskTier"] = current_tier
            asset_dict["ecdatEnrichment"] = enrichment
        else:
            current_tier = enrichment.get("moscaRiskTier", db_asset.risk_tier)

        # Count distribution
        if current_tier == "Critical":
            crit_count += 1
        elif current_tier == "High":
            high_count += 1
        elif current_tier == "Medium":
            med_count += 1
        elif current_tier == "Low":
            low_count += 1

        # If riskTier filter was passed, apply it here
        if riskTier and current_tier.lower() != riskTier.lower():
            continue

        try:
            parsed_assets.append(CanonicalCBOMAsset.model_validate(asset_dict))
        except Exception:
            continue

    total_items = len(parsed_assets)
    total_pages = math.ceil(total_items / pageSize) if total_items > 0 else 1

    start_idx = (page - 1) * pageSize
    end_idx = start_idx + pageSize
    paged_items = parsed_assets[start_idx:end_idx]

    z_used = z if z is not None else (all_matching_db_assets[0].threat_timeline_z if all_matching_db_assets else 8.0)

    return AssetSummaryResponse(
        items=paged_items,
        total=total_items,
        page=page,
        pageSize=pageSize,
        pages=total_pages,
        zUsed=z_used,
        criticalCount=crit_count,
        highCount=high_count,
        mediumCount=med_count,
        lowCount=low_count,
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset_detail(asset_id: str, db: Session = Depends(get_db)):
    """
    Returns full asset details including exact file/line, complete Mosca breakdown,
    and side-by-side migration recommendation.
    """
    # Look up by ID or by bom_ref
    db_asset = db.query(Asset).filter(
        (Asset.id == asset_id) | (Asset.bom_ref == asset_id)
    ).first()

    if not db_asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    asset_dict = json.loads(db_asset.asset_json)
    canonical_asset = CanonicalCBOMAsset.model_validate(asset_dict)
    enrichment = canonical_asset.ecdatEnrichment

    rec = db.query(Recommendation).filter(Recommendation.asset_id == db_asset.id).first()
    rec_dict = {
        "recommendedReplacement": rec.recommended_algorithm if rec else enrichment.recommendedReplacement,
        "mode": rec.mode if rec else enrichment.recommendationMode,
        "complexity": rec.complexity if rec else enrichment.migrationComplexity,
        "rationale": rec.rationale if rec else enrichment.vulnerabilityReason,
        "referenceStandard": rec.reference_standard if rec else enrichment.referenceStandard,
        "relativeSizeDelta": enrichment.relativeSizeDelta,
    }

    mosca_breakdown = {
        "x": enrichment.moscaX,
        "y": enrichment.moscaY,
        "z": enrichment.moscaZ,
        "r": enrichment.moscaR,
        "riskTier": enrichment.moscaRiskTier,
        "riskScore": enrichment.riskScore,
        "quantumVulnerable": enrichment.quantumVulnerable,
        "autoEscalated": enrichment.autoEscalated,
        "escalationReason": enrichment.escalationReason or enrichment.vulnerabilityReason,
        "businessCriticality": enrichment.businessCriticality,
        "exposure": enrichment.exposure,
        "dataClassification": enrichment.dataClassification,
    }

    return AssetDetailResponse(
        asset=canonical_asset,
        moscaBreakdown=mosca_breakdown,
        recommendation=rec_dict,
    )
