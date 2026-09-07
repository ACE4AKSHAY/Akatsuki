"""
M9: CBOM JSON Export Submodule
Returns CycloneDX 1.6 Cryptography Bill of Materials JSON document.
"""
import json
from typing import Tuple


def export_cbom_json(scan_id: str, raw_cbom_json: str) -> Tuple[bytes, str, str]:
    """
    Exports CycloneDX 1.6 document.
    Returns (bytes, mime_type, filename).
    """
    if not raw_cbom_json:
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{scan_id}",
            "version": 1,
            "components": [],
        }
        content = json.dumps(data, indent=2).encode("utf-8")
    else:
        try:
            parsed = json.loads(raw_cbom_json)
            content = json.dumps(parsed, indent=2).encode("utf-8")
        except Exception:
            content = raw_cbom_json.encode("utf-8")

    filename = f"cyclonedx-cbom-{scan_id}.json"
    return content, "application/json", filename
