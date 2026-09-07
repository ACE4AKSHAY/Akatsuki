"""
ECDAT Configuration and Threat Model Defaults
"""
import os
from pydantic import BaseModel, Field

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ecdat.db")

class ThreatModelConfigDefaults(BaseModel):
    """
    Default assumptions for Mosca's Inequality: X + Y > Z
    X = Security Shelf-Life (years)
    Y = Migration Time (years)
    Z = Threat Timeline (years to Cryptographically-Relevant Quantum Computer)
    """
    threat_timeline_z: float = Field(default=8.0, description="Default years until CRQC (Z)")
    
    # Default shelf-life (X) by data classification (years)
    shelf_life_defaults: dict[str, float] = Field(
        default={
            "Customer-PII": 15.0,
            "Authentication-Token": 2.0,
            "Firmware": 10.0,
            "Financial-Record": 10.0,
            "Health-Data": 25.0,
            "Internal-Operational": 3.0,
            "General": 5.0,
        }
    )
    
    # Default migration effort (Y) by asset category / type (years)
    migration_effort_defaults: dict[str, float] = Field(
        default={
            "asymmetric_kem": 1.5,
            "asymmetric_sig": 2.0,
            "symmetric": 0.5,
            "hash": 0.25,
            "certificate": 0.5,
            "protocol": 1.0,
        }
    )
    
    # Weights for Section 9.3 Composite RiskScore
    # RiskScore = w_q * QuantumVulnerability + w_r * normalize(r) + w_b * BusinessCriticality + w_e * Exposure
    weight_quantum: float = 0.40
    weight_ratio: float = 0.25
    weight_business: float = 0.20
    weight_exposure: float = 0.15

threat_model_settings = ThreatModelConfigDefaults()
