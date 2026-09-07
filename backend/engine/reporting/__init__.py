"""
ECDAT Module M9: Reporting & Export Engine
Provides unified report generation across formats:
- CycloneDX 1.6 CBOM JSON
- PDF Executive Summary (ReportLab)
- Excel XLSX Spreadsheet (openpyxl)
- Flat CSV Asset Inventory
"""
from typing import Literal, Tuple, List, Dict, Any
from backend.engine.reporting.cbom_report import export_cbom_json
from backend.engine.reporting.spreadsheet_report import export_csv, export_xlsx
from backend.engine.reporting.pdf_report import export_pdf


def generate_report(
    scan_id: str,
    raw_cbom_json: str = "",
    assets_data: List[Dict[str, Any]] = None,
    report_format: Literal["pdf", "csv", "xlsx", "json"] = "json",
) -> Tuple[bytes, str, str]:
    """
    Unified entrypoint for M9 report generation.
    Returns: (content_bytes, mime_type, filename)
    """
    fmt = (report_format or "json").lower().strip()
    data = assets_data or []

    if fmt == "json":
        return export_cbom_json(scan_id=scan_id, raw_cbom_json=raw_cbom_json)
    elif fmt == "csv":
        return export_csv(scan_id=scan_id, assets_data=data)
    elif fmt in ["xlsx", "excel"]:
        return export_xlsx(scan_id=scan_id, assets_data=data)
    elif fmt == "pdf":
        return export_pdf(scan_id=scan_id, assets_data=data)
    else:
        raise ValueError(f"Unsupported report format '{report_format}'. Must be 'pdf', 'csv', 'xlsx', or 'json'.")


__all__ = [
    "generate_report",
    "export_cbom_json",
    "export_csv",
    "export_xlsx",
    "export_pdf",
]
