"""Celery application and task definitions for ECDAT (M7).

Enables asynchronous distributed execution of long-running discovery scans
against Redis message broker.
"""

from __future__ import annotations

import os
from typing import Any

# Only initialize celery if installed/configured
try:
    from celery import Celery
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None  # type: ignore

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

if CELERY_AVAILABLE:
    celery_app = Celery(
        "ecdat",
        broker=REDIS_URL,
        backend=REDIS_URL,
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
    )

    @celery_app.task(name="ecdat.tasks.execute_scan", bind=True)
    def execute_scan_task(
        self,
        raw_findings: list[dict[str, Any]],
        scan_id: str,
        source_type: str = "path",
        target: str = "src/",
        threat_model: dict[str, Any] | None = None,
        weights: dict[str, Any] | None = None,
        constraints: dict[str, Any] | None = None,
        tagging_config: dict[str, Any] | None = None,
    ):
        """Asynchronous Celery task for scan execution."""
        from backend.models.schemas import ConstraintConfig, RiskWeights, ThreatModelConfig
        from backend.orchestrator.pipeline import run_pipeline

        tm = ThreatModelConfig.model_validate(threat_model) if threat_model else None
        rw = RiskWeights.model_validate(weights) if weights else None
        cc = ConstraintConfig.model_validate(constraints) if constraints else None

        return run_pipeline(
            raw_findings=raw_findings,
            scan_id=scan_id,
            source_type=source_type,
            target=target,
            threat_model=tm,
            weights=rw,
            constraints=cc,
            tagging_config=tagging_config,
        )

else:
    celery_app = None

