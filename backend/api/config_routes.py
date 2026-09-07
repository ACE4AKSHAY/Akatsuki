"""
Threat Model Configuration API routes: PATCH /config/threat-model, GET /config/threat-model
"""
import json
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import ThreatModelConfig
from backend.models.schemas import ThreatModelUpdateRequest
from backend.config import threat_model_settings

router = APIRouter(prefix="/config", tags=["Configuration"])


@router.get("/threat-model")
def get_threat_model_config(db: Session = Depends(get_db)):
    """Returns the current threat model assumptions and risk weights."""
    cfg = db.query(ThreatModelConfig).filter(ThreatModelConfig.id == 1).first()
    if not cfg:
        return {
            "threatTimelineYears": threat_model_settings.threat_timeline_z,
            "weights": {
                "weight_quantum": threat_model_settings.weight_quantum,
                "weight_ratio": threat_model_settings.weight_ratio,
                "weight_business": threat_model_settings.weight_business,
                "weight_exposure": threat_model_settings.weight_exposure,
            },
            "shelfLifeDefaults": threat_model_settings.shelf_life_defaults,
            "migrationEffortDefaults": threat_model_settings.migration_effort_defaults,
        }

    return {
        "threatTimelineYears": cfg.threat_timeline_z,
        "weights": json.loads(cfg.weights_json),
        "shelfLifeDefaults": json.loads(cfg.shelf_life_json),
        "migrationEffortDefaults": json.loads(cfg.migration_effort_json),
        "updatedAt": cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


@router.patch("/threat-model")
def update_threat_model_config(
    update_req: ThreatModelUpdateRequest,
    db: Session = Depends(get_db),
):
    """
    Updates the stored default threat-model config (Z timeline, risk weights).
    """
    cfg = db.query(ThreatModelConfig).filter(ThreatModelConfig.id == 1).first()
    if not cfg:
        cfg = ThreatModelConfig(
            id=1,
            threat_timeline_z=threat_model_settings.threat_timeline_z,
            weights_json=json.dumps({
                "weight_quantum": threat_model_settings.weight_quantum,
                "weight_ratio": threat_model_settings.weight_ratio,
                "weight_business": threat_model_settings.weight_business,
                "weight_exposure": threat_model_settings.weight_exposure,
            }),
            shelf_life_json=json.dumps(threat_model_settings.shelf_life_defaults),
            migration_effort_json=json.dumps(threat_model_settings.migration_effort_defaults),
            updated_at=datetime.utcnow(),
        )
        db.add(cfg)

    if update_req.threatTimelineYears is not None:
        cfg.threat_timeline_z = update_req.threatTimelineYears

    weights = json.loads(cfg.weights_json)
    if update_req.weightQuantum is not None:
        weights["weight_quantum"] = update_req.weightQuantum
    if update_req.weightRatio is not None:
        weights["weight_ratio"] = update_req.weightRatio
    if update_req.weightBusiness is not None:
        weights["weight_business"] = update_req.weightBusiness
    if update_req.weightExposure is not None:
        weights["weight_exposure"] = update_req.weightExposure
    cfg.weights_json = json.dumps(weights)

    if update_req.shelfLifeDefaults is not None:
        cfg.shelf_life_json = json.dumps(update_req.shelfLifeDefaults)

    if update_req.migrationEffortDefaults is not None:
        cfg.migration_effort_json = json.dumps(update_req.migrationEffortDefaults)

    cfg.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(cfg)

    return {
        "status": "updated",
        "threatTimelineYears": cfg.threat_timeline_z,
        "weights": json.loads(cfg.weights_json),
        "shelfLifeDefaults": json.loads(cfg.shelf_life_json),
        "migrationEffortDefaults": json.loads(cfg.migration_effort_json),
        "updatedAt": cfg.updated_at.isoformat(),
    }
