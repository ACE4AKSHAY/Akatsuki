"""
M7 Orchestration Engine
Coordinates async scan lifecycle: Scanner -> M4 Normalizer -> M5 Risk Engine -> M6 Recommender -> Postgres/SQLite DB.
"""
import json
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from backend.database import SessionLocal
from backend.models.db_models import Scan, Asset, Recommendation, ThreatModelConfig
from backend.models.schemas import RawFinding
from backend.engine.normalizer import normalize_findings, build_cyclonedx_document
from backend.config import threat_model_settings


def get_active_threat_model(db: Session, override_z: Optional[float] = None) -> tuple[float, dict]:
    """Retrieves active Z threat timeline and composite risk weights from DB or defaults."""
    db_config = db.query(ThreatModelConfig).filter(ThreatModelConfig.id == 1).first()
    if db_config:
        z = override_z if override_z is not None else db_config.threat_timeline_z
        try:
            weights = json.loads(db_config.weights_json)
        except Exception:
            weights = {
                "weight_quantum": threat_model_settings.weight_quantum,
                "weight_ratio": threat_model_settings.weight_ratio,
                "weight_business": threat_model_settings.weight_business,
                "weight_exposure": threat_model_settings.weight_exposure,
            }
    else:
        z = override_z if override_z is not None else threat_model_settings.threat_timeline_z
        weights = {
            "weight_quantum": threat_model_settings.weight_quantum,
            "weight_ratio": threat_model_settings.weight_ratio,
            "weight_business": threat_model_settings.weight_business,
            "weight_exposure": threat_model_settings.weight_exposure,
        }
    return z, weights


def get_contract_seed_findings(scan_id: str) -> list[RawFinding]:
    """
    Contract 1 Raw Findings fixture (A -> B/C handoff).
    Represents findings from M1, M2, M3 per CONTRACT.md Section 1.
    """
    return [
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId=scan_id,
            filePath="src/auth/token_signer.py",
            lineNumber=42,
            language="python",
            library="pyca/cryptography",
            rawSignal="hashes.SHA1()",
            detectedPrimitive="SHA1",
            primitiveCategory="hash",
            keySizeBits=None,
            mode=None,
            confidence=0.95,
            detectionTier="ast",
        ),
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId=scan_id,
            filePath="src/customer/pii_vault.py",
            lineNumber=118,
            language="python",
            library="pyca/cryptography",
            rawSignal="rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            detectedPrimitive="RSA-2048",
            primitiveCategory="asymmetric_kem",
            keySizeBits=2048,
            mode=None,
            confidence=0.98,
            detectionTier="ast",
        ),
        RawFinding(
            sourceModule="M3_container_config_scanner",
            scanTargetId=scan_id,
            filePath="infra/tls/internal_service.crt",
            lineNumber=1,
            language="yaml",
            library="x509",
            rawSignal="Subject: CN=internal.rpc, Public Key: ECDSA-P256",
            detectedPrimitive="ECDSA-P256",
            primitiveCategory="asymmetric_sig",
            keySizeBits=256,
            mode=None,
            confidence=1.0,
            detectionTier="cert-parse",
        ),
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId=scan_id,
            filePath="firmware/boot_signer.c",
            lineNumber=88,
            language="c",
            library="openssl",
            rawSignal="RSA_sign(NID_sha256, m, m_len, sigret, &siglen, rsa)",
            detectedPrimitive="RSA-2048",
            primitiveCategory="asymmetric_sig",
            keySizeBits=2048,
            mode=None,
            confidence=0.92,
            detectionTier="ast",
        ),
        RawFinding(
            sourceModule="M2_dep_binary_scanner",
            scanTargetId=scan_id,
            filePath="requirements.txt",
            lineNumber=12,
            language="python",
            library="pycryptodome",
            rawSignal="AES.new(key, AES.MODE_CBC)",
            detectedPrimitive="AES-128",
            primitiveCategory="symmetric",
            keySizeBits=128,
            mode="CBC",
            confidence=0.88,
            detectionTier="manifest",
        ),
    ]


def run_scan_pipeline_sync(
    scan_id: str,
    source_type: str,
    target: str,
    compliance_target: str = "NIST-general",
    threat_timeline_override: Optional[float] = None,
):
    """
    Synchronous/background worker function that executes the full end-to-end scanning pipeline.
    """
    db = SessionLocal()
    try:
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan_record:
            return

        # Stage 1: Running
        scan_record.status = "running"
        scan_record.progress = 15.0
        db.commit()

        # Stage 2: Ingestion & Scanning (M1, M2, M3 findings)
        raw_findings = get_contract_seed_findings(scan_id)
        scan_record.progress = 50.0
        db.commit()

        # Stage 3: Resolve Threat Model Parameters
        z_timeline, weights = get_active_threat_model(db, threat_timeline_override)

        # Stage 4: Normalization (M4), Risk Scoring (M5), and Recommendations (M6)
        canonical_assets = normalize_findings(
            findings=raw_findings,
            threat_timeline_z=z_timeline,
            compliance_target=compliance_target,
            weights=weights,
        )
        scan_record.progress = 80.0
        db.commit()

        # Stage 5: Wrap into CycloneDX 1.6 Document
        cyclonedx_doc = build_cyclonedx_document(scan_id, canonical_assets)
        raw_cbom_str = cyclonedx_doc.model_dump_json(by_alias=True, indent=2)

        # Stage 6: Persist Canonical Assets to Relational DB
        # Remove any existing assets for this scan
        db.query(Asset).filter(Asset.scan_id == scan_id).delete()

        for asset_obj in canonical_assets:
            enrichment = asset_obj.ecdatEnrichment
            crypto_props = asset_obj.cryptoProperties

            primary_loc = asset_obj.occurrences[0].location if asset_obj.occurrences else "unknown"
            primary_line = asset_obj.occurrences[0].line if asset_obj.occurrences else None

            db_asset = Asset(
                id=f"asset_{asset_obj.bom_ref}",
                scan_id=scan_id,
                bom_ref=asset_obj.bom_ref,
                name=asset_obj.name,
                primitive_category=crypto_props.algorithmProperties.primitive,
                file_path=primary_loc,
                line_number=primary_line,
                library=None,
                risk_tier=enrichment.moscaRiskTier,
                risk_score=enrichment.riskScore or 0.0,
                business_criticality=enrichment.businessCriticality,
                exposure=enrichment.exposure,
                shelf_life_x=enrichment.moscaX,
                migration_effort_y=enrichment.moscaY,
                threat_timeline_z=enrichment.moscaZ,
                urgency_ratio_r=enrichment.moscaR,
                quantum_vulnerable=enrichment.quantumVulnerable,
                asset_json=asset_obj.model_dump_json(by_alias=True),
            )
            db.add(db_asset)
            db.flush()

            db_rec = Recommendation(
                id=f"rec_{asset_obj.bom_ref}",
                asset_id=db_asset.id,
                recommended_algorithm=enrichment.recommendedReplacement,
                mode=enrichment.recommendationMode or "hybrid",
                complexity=enrichment.migrationComplexity or "Medium",
                rationale=enrichment.vulnerabilityReason,
                reference_standard=enrichment.referenceStandard,
            )
            db.add(db_rec)

        # Stage 7: Finalize Scan
        scan_record.status = "completed"
        scan_record.progress = 100.0
        scan_record.asset_count = len(canonical_assets)
        scan_record.completed_at = datetime.utcnow()
        scan_record.raw_cbom_json = raw_cbom_str
        db.commit()

    except Exception as e:
        db.rollback()
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_record:
            scan_record.status = "failed"
            scan_record.error = str(e)
            db.commit()
    finally:
        db.close()
