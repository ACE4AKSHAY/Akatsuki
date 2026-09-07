"""
Unit & Integration tests for ECDAT Module M9 (Reporting & Export Engine).
Verifies:
1. PDF Executive Summary with valid binary '%PDF-' header and ReportLab structures.
2. Excel XLSX spreadsheet export validating via openpyxl.load_workbook.
3. CSV asset inventory export validating via csv.reader.
4. CycloneDX 1.6 CBOM JSON export.
5. End-to-end API export endpoints.
"""
import io
import csv
import json
import pytest
import openpyxl
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db
from backend.engine.orchestrator import run_scan_pipeline_sync
from backend.engine.reporting import generate_report


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture
def sample_assets_fixture():
    return [
        {
            "id": "asset-001",
            "bom_ref": "crypto-asset-0af3e9",
            "type": "Algorithm",
            "name": "SHA-1",
            "file_path": "src/auth/token_signer.py",
            "line_number": 42,
            "library": "pyca/cryptography",
            "key_size": None,
            "business_criticality": "High",
            "exposure": "external-facing",
            "risk_tier": "Critical",
            "risk_score": 0.88,
            "urgency_ratio_r": 1.34,
            "shelf_life_x": 2.0,
            "migration_effort_y": 0.25,
            "threat_timeline_z": 8.0,
            "quantum_vulnerable": True,
            "recommended_replacement": "SHA-384 or SHA3-384",
            "complexity": "Low",
            "reference_standard": "FIPS 180-4 / FIPS 202",
        },
        {
            "id": "asset-002",
            "bom_ref": "crypto-asset-7bf21c",
            "type": "Algorithm",
            "name": "RSA-2048",
            "file_path": "services/pii/encrypt.py",
            "line_number": 88,
            "library": "cryptography.hazmat",
            "key_size": 2048,
            "business_criticality": "Critical",
            "exposure": "internal-only",
            "risk_tier": "Critical",
            "risk_score": 0.95,
            "urgency_ratio_r": 2.06,
            "shelf_life_x": 15.0,
            "migration_effort_y": 1.5,
            "threat_timeline_z": 8.0,
            "quantum_vulnerable": True,
            "recommended_replacement": "ML-KEM-768 (hybrid)",
            "complexity": "Medium",
            "reference_standard": "FIPS 203",
        },
        {
            "id": "asset-003",
            "bom_ref": "crypto-asset-91a0e4",
            "type": "Certificate",
            "name": "ECDSA-P256",
            "file_path": "infra/mtls/service.crt",
            "line_number": 1,
            "library": "x509",
            "key_size": 256,
            "business_criticality": "Low",
            "exposure": "internal-only",
            "risk_tier": "Low",
            "risk_score": 0.25,
            "urgency_ratio_r": 0.44,
            "shelf_life_x": 3.0,
            "migration_effort_y": 0.5,
            "threat_timeline_z": 8.0,
            "quantum_vulnerable": True,
            "recommended_replacement": "ML-DSA-65",
            "complexity": "Low",
            "reference_standard": "FIPS 204",
        },
    ]


@pytest.fixture
def sample_cbom_json_fixture():
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-scan-12345",
        "version": 1,
        "components": [
            {
                "bom-ref": "crypto-asset-0af3e9",
                "type": "cryptographic-asset",
                "name": "SHA-1",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "hash",
                        "parameterSetIdentifier": "SHA-1",
                    },
                    "oid": "1.3.14.3.2.26",
                },
                "occurrences": [{"location": "src/auth/token_signer.py", "line": 42}],
                "ecdatEnrichment": {
                    "quantumVulnerable": True,
                    "vulnerabilityReason": "classically broken",
                    "businessCriticality": "High",
                    "dataClassification": "Authentication-Token",
                    "exposure": "external-facing",
                    "estimatedShelfLifeYears": 2.0,
                    "estimatedMigrationEffortYears": 0.25,
                    "moscaX": 2.0,
                    "moscaY": 0.25,
                    "moscaZ": 8.0,
                    "moscaR": 1.34,
                    "moscaRiskTier": "Critical",
                    "recommendedReplacement": "SHA-384 or SHA3-384",
                    "referenceStandard": "FIPS 180-4",
                },
            }
        ],
    })


def test_m9_pdf_export_well_formed(sample_assets_fixture):
    """Verifies that PDF export outputs valid binary starting with %PDF- and compiles cleanly."""
    pdf_bytes, mime_type, filename = generate_report(
        scan_id="scan_test_001",
        assets_data=sample_assets_fixture,
        report_format="pdf",
    )

    assert mime_type == "application/pdf"
    assert filename.endswith(".pdf")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # Strict PDF specification requirement: header must start with %PDF-
    assert pdf_bytes.startswith(b"%PDF-")


def test_m9_xlsx_export_well_formed(sample_assets_fixture):
    """Verifies that XLSX export opens cleanly with openpyxl and has styled data matching assets."""
    xlsx_bytes, mime_type, filename = generate_report(
        scan_id="scan_test_001",
        assets_data=sample_assets_fixture,
        report_format="xlsx",
    )

    assert mime_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert filename.endswith(".xlsx")
    assert isinstance(xlsx_bytes, bytes)

    # Open with openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(xlsx_bytes))
    assert "Cryptographic Assets" in wb.sheetnames
    ws = wb["Cryptographic Assets"]

    # Header check
    headers = [cell.value for cell in ws[1]]
    assert "Asset ID" in headers
    assert "Algorithm" in headers
    assert "Risk Tier" in headers
    assert "Recommended Algorithm" in headers

    # Row count check (1 header + 3 assets)
    assert ws.max_row == 4
    # Check cell values
    assert ws.cell(row=2, column=4).value == "SHA-1"
    assert ws.cell(row=3, column=4).value == "RSA-2048"


def test_m9_csv_export_well_formed(sample_assets_fixture):
    """Verifies that CSV export parses correctly with standard csv.reader."""
    csv_bytes, mime_type, filename = generate_report(
        scan_id="scan_test_001",
        assets_data=sample_assets_fixture,
        report_format="csv",
    )

    assert mime_type == "text/csv"
    assert filename.endswith(".csv")

    csv_text = csv_bytes.decode("utf-8")
    rows = list(csv.reader(io.StringIO(csv_text)))
    assert len(rows) == 4  # Header + 3 assets
    assert rows[0][0] == "Asset ID"
    assert rows[1][3] == "SHA-1"
    assert rows[2][3] == "RSA-2048"


def test_m9_cbom_json_export_well_formed(sample_cbom_json_fixture):
    """Verifies that CBOM JSON export parses and adheres to CycloneDX 1.6 envelope."""
    json_bytes, mime_type, filename = generate_report(
        scan_id="scan_test_001",
        raw_cbom_json=sample_cbom_json_fixture,
        report_format="json",
    )

    assert mime_type == "application/json"
    assert filename.endswith(".json")

    parsed = json.loads(json_bytes.decode("utf-8"))
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert len(parsed["components"]) == 1
    assert parsed["components"][0]["name"] == "SHA-1"


def test_m9_api_endpoints():
    """Tests M7 API endpoints for M9 reporting (PDF, CSV, XLSX, JSON)."""
    client = TestClient(app)

    # 1. Run a scan to populate test data
    scan_res = client.post("/scans", json={"sourceType": "path", "target": "demo_target"})
    assert scan_res.status_code == 202
    scan_id = scan_res.json()["scanId"]

    run_scan_pipeline_sync(
        scan_id=scan_id,
        source_type="path",
        target="demo_target",
    )

    # 2. Test PDF export via API
    pdf_api_res = client.get(f"/reports/{scan_id}?format=pdf")
    assert pdf_api_res.status_code == 200
    assert pdf_api_res.headers["content-type"] == "application/pdf"
    assert pdf_api_res.content.startswith(b"%PDF-")

    # 3. Test XLSX export via API
    xlsx_api_res = client.get(f"/reports/{scan_id}?format=xlsx")
    assert xlsx_api_res.status_code == 200
    wb = openpyxl.load_workbook(io.BytesIO(xlsx_api_res.content))
    assert "Cryptographic Assets" in wb.sheetnames

    # 4. Test CSV export via API
    csv_api_res = client.get(f"/reports/{scan_id}?format=csv")
    assert csv_api_res.status_code == 200
    assert "Asset ID,BOM Ref,Type" in csv_api_res.text

    # 5. Test JSON report export via API
    json_api_res = client.get(f"/reports/{scan_id}?format=json")
    assert json_api_res.status_code == 200
    assert json_api_res.json()["bomFormat"] == "CycloneDX"

    # 6. Test direct /cbom/{scanId} endpoint
    cbom_api_res = client.get(f"/cbom/{scan_id}")
    assert cbom_api_res.status_code == 200
    cbom_doc = cbom_api_res.json()
    assert cbom_doc["specVersion"] == "1.6"
    assert len(cbom_doc["components"]) > 0
