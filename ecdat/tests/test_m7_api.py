"""Integration tests for M7 Backend API endpoints."""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health_check():
    """Verify health endpoint."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": "1.0.0"}


def test_scan_lifecycle_and_asset_retrieval():
    """Verify scan creation, execution, and asset retrieval."""
    raw_findings = [
        {
            "sourceModule": "M1_source_scanner",
            "scanTargetId": "scan_test_lifecycle",
            "filePath": "src/auth/token_signer.py",
            "lineNumber": 42,
            "language": "python",
            "library": "pyca/cryptography",
            "rawSignal": "hashes.SHA1()",
            "detectedPrimitive": "SHA1",
            "primitiveCategory": "hash",
            "keySizeBits": None,
            "mode": None,
            "confidence": 0.95,
            "detectionTier": "ast",
        },
        {
            "sourceModule": "M1_source_scanner",
            "scanTargetId": "scan_test_lifecycle",
            "filePath": "src/crypto/session.py",
            "lineNumber": 15,
            "language": "python",
            "library": "pyca/cryptography",
            "rawSignal": "AES.new()",
            "detectedPrimitive": "AES-128",
            "primitiveCategory": "cipher",
            "keySizeBits": 128,
            "mode": "GCM",
            "confidence": 0.95,
            "detectionTier": "ast",
        },
    ]

    # 1. POST /scans
    post_resp = client.post(
        "/scans",
        json={
            "sourceType": "path",
            "target": "src/",
            "rawFindings": raw_findings,
        },
    )
    assert post_resp.status_code == 200
    scan_data = post_resp.json()
    scan_id = scan_data["scanId"]
    assert scan_id.startswith("scan_")

    # 2. GET /scans/{id}
    scan_resp = client.get(f"/scans/{scan_id}")
    assert scan_resp.status_code == 200
    detail = scan_resp.json()
    assert detail["status"] == "completed"
    assert detail["findingsCount"] == 2
    assert detail["assetsCount"] == 2

    # 3. GET /assets with scanId filter
    assets_resp = client.get(f"/assets?scanId={scan_id}")
    assert assets_resp.status_code == 200
    assets_data = assets_resp.json()
    assert assets_data["total"] == 2
    assert len(assets_data["assets"]) == 2

    # Check asset fields adhere to CONTRACT.md
    asset_names = {a["name"] for a in assets_data["assets"]}
    assert "SHA1" in asset_names

    # 4. GET /assets/{id} detail
    first_asset_ref = assets_data["assets"][0]["bom-ref"]
    asset_detail_resp = client.get(f"/assets/{first_asset_ref}")
    assert asset_detail_resp.status_code == 200
    asset_detail = asset_detail_resp.json()
    assert asset_detail["bom-ref"] == first_asset_ref
    assert "ecdatEnrichment" in asset_detail

    # 5. Dynamic Z slider recalculation
    # When Z is very large (e.g. z=50.0), urgency ratio drops, moving non-classically-broken items to Low
    slider_resp = client.get(f"/assets?scanId={scan_id}&z=50.0")
    assert slider_resp.status_code == 200
    slider_assets = slider_resp.json()["assets"]

    aes_asset = next(a for a in slider_assets if a["name"] == "AES-128")
    assert aes_asset["ecdatEnrichment"]["moscaZ"] == 50.0
    assert aes_asset["ecdatEnrichment"]["moscaR"] < 0.6
    assert aes_asset["ecdatEnrichment"]["moscaRiskTier"] == "Low"

    # 6. Filter by risk and exposure (GET /assets?risk=Critical&exposure=external-facing)
    filtered_resp = client.get(f"/assets?scanId={scan_id}&risk=Critical&exposure=external-facing")
    assert filtered_resp.status_code == 200
    filtered_assets = filtered_resp.json()["assets"]
    assert len(filtered_assets) >= 1
    for a in filtered_assets:
        assert a["ecdatEnrichment"]["moscaRiskTier"] == "Critical"
        assert a["ecdatEnrichment"]["exposure"] == "external-facing"


def test_cbom_and_report_exports():
    """Verify CycloneDX 1.6 CBOM export and CSV/JSON report endpoints."""
    raw = {
        "sourceModule": "M1_source_scanner",
        "scanTargetId": "scan_test_export",
        "filePath": "src/auth/token_signer.py",
        "lineNumber": 42,
        "language": "python",
        "library": "pyca/cryptography",
        "rawSignal": "hashes.SHA1()",
        "detectedPrimitive": "SHA1",
        "primitiveCategory": "hash",
        "keySizeBits": None,
        "mode": None,
        "confidence": 0.95,
        "detectionTier": "ast",
    }
    create_resp = client.post(
        "/scans",
        json={"sourceType": "path", "target": "src/", "rawFindings": [raw]},
    )
    scan_id = create_resp.json()["scanId"]

    # 1. Download CBOM JSON
    cbom_resp = client.get(f"/cbom/{scan_id}")
    assert cbom_resp.status_code == 200
    assert "application/json" in cbom_resp.headers["content-type"]
    assert f'filename="cbom-{scan_id}.json"' in cbom_resp.headers["content-disposition"]
    cbom_doc = cbom_resp.json()
    assert cbom_doc["bomFormat"] == "CycloneDX"
    assert cbom_doc["specVersion"] == "1.6"

    # 2. Download CSV Report
    csv_resp = client.get(f"/reports/{scan_id}?format=csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    csv_text = csv_resp.text
    assert "bom-ref,name,primitive" in csv_text
    assert "SHA1" in csv_text

    # 3. Download HTML/PDF summary
    pdf_resp = client.get(f"/reports/{scan_id}?format=pdf")
    assert pdf_resp.status_code == 200
    assert "text/html" in pdf_resp.headers["content-type"]
    assert "ECDAT Cryptographic Security Report" in pdf_resp.text


def test_threat_model_config_endpoint():
    """Verify GET and PATCH /config/threat-model."""
    get_resp = client.get("/config/threat-model")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert "threatTimelineYears" in data

    patch_resp = client.patch("/config/threat-model", json={"threatTimelineYears": 10.0})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["threatTimelineYears"] == 10.0
