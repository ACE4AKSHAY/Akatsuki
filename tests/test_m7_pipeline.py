"""
Integration tests for ECDAT Module M7 (Backend API & Orchestration).
Tests full scan pipeline, dynamic Z slider rescoring, CBOM export, reports, and threat model updates.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db
from backend.engine.orchestrator import run_scan_pipeline_sync


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Ensure database tables exist before tests."""
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "M7" in data["service"]


def test_full_scan_pipeline_and_endpoints(client):
    """
    Runs an end-to-end scan pipeline test:
    1. POST /scans
    2. Synchronously execute worker
    3. GET /scans/{id}
    4. GET /assets with filters
    5. GET /assets with dynamic Z override
    6. GET /assets/{id}
    7. GET /cbom/{scanId}
    8. GET /reports/{scanId}?format=csv
    9. PATCH /config/threat-model
    """
    # 1. Trigger scan
    scan_payload = {
        "sourceType": "path",
        "target": "demo_repo",
        "complianceTarget": "NIST-general",
        "threatTimelineOverride": 8.0,
    }
    create_res = client.post("/scans", json=scan_payload)
    assert create_res.status_code == 202
    scan_info = create_res.json()
    scan_id = scan_info["scanId"]
    assert scan_id.startswith("scan_")

    # In TestClient, BackgroundTasks run during the request, but let's also ensure sync execution has finished:
    # If not already completed, execute sync:
    run_scan_pipeline_sync(
        scan_id=scan_id,
        source_type="path",
        target="demo_repo",
        compliance_target="NIST-general",
        threat_timeline_override=8.0,
    )

    # 2. Verify scan status is completed
    poll_res = client.get(f"/scans/{scan_id}")
    assert poll_res.status_code == 200
    scan_status = poll_res.json()
    assert scan_status["status"] == "completed"
    assert scan_status["progress"] == 100.0
    assert scan_status["assetCount"] >= 4

    # 3. Retrieve assets inventory
    assets_res = client.get(f"/assets?scanId={scan_id}")
    assert assets_res.status_code == 200
    assets_data = assets_res.json()
    assert assets_data["total"] >= 4
    assert len(assets_data["items"]) >= 4
    assert assets_data["criticalCount"] >= 1

    # Verify canonical CBOM structure in item
    first_asset = assets_data["items"][0]
    assert "bom-ref" in first_asset
    assert first_asset["type"] == "cryptographic-asset"
    assert "cryptoProperties" in first_asset
    assert "ecdatEnrichment" in first_asset
    enrichment = first_asset["ecdatEnrichment"]
    assert "moscaX" in enrichment
    assert "moscaY" in enrichment
    assert "moscaZ" in enrichment
    assert "moscaR" in enrichment
    assert "moscaRiskTier" in enrichment
    assert "recommendedReplacement" in enrichment
    assert "referenceStandard" in enrichment

    # 4. Interactive Z Slider "What-If" Re-scoring Test
    # When Z drops from 8 to 2 years, urgency ratio r = (X+Y)/Z quadruples, pushing more assets to Critical!
    slider_z2_res = client.get(f"/assets?scanId={scan_id}&z=2.0")
    assert slider_z2_res.status_code == 200
    z2_data = slider_z2_res.json()
    assert z2_data["zUsed"] == 2.0
    assert z2_data["criticalCount"] >= assets_data["criticalCount"]

    # When Z increases to 25 years, urgency ratio drops
    slider_z25_res = client.get(f"/assets?scanId={scan_id}&z=25.0")
    assert slider_z25_res.status_code == 200
    z25_data = slider_z25_res.json()
    assert z25_data["zUsed"] == 25.0

    # 5. Asset Detail drilldown
    first_bom_ref = first_asset["bom-ref"]
    detail_res = client.get(f"/assets/{first_bom_ref}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert "moscaBreakdown" in detail
    assert "recommendation" in detail
    assert detail["moscaBreakdown"]["r"] is not None
    assert detail["recommendation"]["recommendedReplacement"] is not None

    # 6. CycloneDX 1.6 CBOM Export
    cbom_res = client.get(f"/cbom/{scan_id}")
    assert cbom_res.status_code == 200
    assert "attachment" in cbom_res.headers.get("Content-Disposition", "")
    cbom_json = cbom_res.json()
    assert cbom_json["bomFormat"] == "CycloneDX"
    assert cbom_json["specVersion"] == "1.6"
    assert len(cbom_json["components"]) >= 4

    # 7. Reports Export (CSV & JSON)
    csv_res = client.get(f"/reports/{scan_id}?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers.get("Content-Type", "")
    csv_text = csv_res.text
    assert "Asset ID,BOM Ref,Type,Algorithm" in csv_text
    assert "Critical" in csv_text

    json_report_res = client.get(f"/reports/{scan_id}?format=json")
    assert json_report_res.status_code == 200
    assert "application/json" in json_report_res.headers.get("Content-Type", "")

    # 8. Threat Model Config API
    get_cfg = client.get("/config/threat-model")
    assert get_cfg.status_code == 200
    assert "threatTimelineYears" in get_cfg.json()

    patch_cfg = client.patch(
        "/config/threat-model",
        json={"threatTimelineYears": 7.5, "weightQuantum": 0.45},
    )
    assert patch_cfg.status_code == 200
    updated_cfg = patch_cfg.json()
    assert updated_cfg["threatTimelineYears"] == 7.5
    assert updated_cfg["weights"]["weight_quantum"] == 0.45
