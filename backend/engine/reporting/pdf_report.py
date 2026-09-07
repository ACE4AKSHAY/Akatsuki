"""
M9: PDF Executive Summary Report Generation Submodule
Uses ReportLab to generate a clean, executive-ready PDF report with
posture overview, risk-tier breakdown, and top prioritized assets.
"""
import io
from datetime import datetime
from typing import List, Dict, Any, Tuple
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Brand kit colors
COLOR_INK = colors.HexColor("#12151B")
COLOR_INK_SOFT = colors.HexColor("#4B5262")
COLOR_INK_FAINT = colors.HexColor("#7B8394")
COLOR_CIPHER = colors.HexColor("#263A73")
COLOR_CIPHER_SOFT = colors.HexColor("#E9ECF6")
COLOR_QUBIT = colors.HexColor("#0E9C90")
COLOR_QUBIT_SOFT = colors.HexColor("#DEF3F0")
COLOR_BORDER = colors.HexColor("#E1E5E8")
COLOR_PAPER = colors.HexColor("#F2F4F5")

COLOR_CRITICAL = colors.HexColor("#B3261E")
COLOR_CRITICAL_BG = colors.HexColor("#FBEAE9")
COLOR_HIGH = colors.HexColor("#B5590F")
COLOR_HIGH_BG = colors.HexColor("#FBEEDF")
COLOR_MEDIUM = colors.HexColor("#93790E")
COLOR_MEDIUM_BG = colors.HexColor("#F8F1D8")
COLOR_LOW = colors.HexColor("#2E7D5B")
COLOR_LOW_BG = colors.HexColor("#E4F2EB")


def export_pdf(scan_id: str, assets_data: List[Dict[str, Any]]) -> Tuple[bytes, str, str]:
    """
    Generates an executive PDF report for the scan.
    Returns (bytes, mime_type, filename).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=COLOR_INK,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=14,
        textColor=COLOR_INK_SOFT,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=COLOR_CIPHER,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=COLOR_INK_SOFT,
    )
    body_bold = ParagraphStyle(
        "DocBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
        textColor=COLOR_INK,
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=COLOR_INK,
    )
    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )
    mono_cell = ParagraphStyle(
        "MonoCell",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=COLOR_INK,
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("ECDAT — Enterprise Cryptographic Discovery & Analysis Tool", title_style))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"Post-Quantum Cryptographic Risk & Migration Executive Summary · Scan ID: <b>{scan_id}</b> · Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            subtitle_style,
        )
    )
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_QUBIT, spaceBefore=2, spaceAfter=12))

    # 2. Key Metrics & Posture Calculation
    total_assets = len(assets_data)
    qv_count = sum(1 for a in assets_data if a.get("quantum_vulnerable", True))
    crit_count = sum(1 for a in assets_data if a.get("risk_tier") == "Critical")
    high_count = sum(1 for a in assets_data if a.get("risk_tier") == "High")
    med_count = sum(1 for a in assets_data if a.get("risk_tier") == "Medium")
    low_count = sum(1 for a in assets_data if a.get("risk_tier") == "Low")

    # Estimate average migration time for critical assets
    crit_migrations = [a.get("migration_effort_y", 1.5) for a in assets_data if a.get("risk_tier") == "Critical"]
    avg_migration = round(sum(crit_migrations) / len(crit_migrations), 1) if crit_migrations else 1.5
    threat_z = assets_data[0].get("threat_timeline_z", 8.0) if assets_data else 8.0

    # 3. Overall Posture Paragraph (Prompt 9 Requirement)
    story.append(Paragraph("1. Executive Posture Statement", section_heading))
    posture_text = (
        f"<b>{qv_count} of {total_assets}</b> cryptographic assets inventoried across the organization are "
        f"vulnerable to quantum cryptanalysis (Shor's or Grover's algorithms). <b>{crit_count} assets</b> are currently "
        f"rated at <b>Critical risk</b> under Mosca's Inequality (<i>X + Y &gt; Z</i>), meaning security shelf-life "
        f"and required migration effort exceed the estimated {threat_z}-year threat timeline to a cryptographically-relevant "
        f"quantum computer (CRQC). Immediate remediation is required within an estimated <b>{avg_migration} years</b> to protect "
        f"sensitive data against Harvest Now, Decrypt Later (HNDL) exploitation."
    )
    story.append(Paragraph(posture_text, body_style))
    story.append(Spacer(1, 14))

    # 4. Risk-Tier Distribution Summary
    story.append(Paragraph("2. Risk-Tier Distribution", section_heading))
    dist_data = [
        [
            Paragraph("Risk Tier", table_header),
            Paragraph("Count", table_header),
            Paragraph("Percentage", table_header),
            Paragraph("Action Required", table_header),
        ],
        [
            Paragraph("<b>Critical</b> (r ≥ 1.2 or broken)", table_cell),
            Paragraph(str(crit_count), table_cell),
            Paragraph(f"{(crit_count / total_assets * 100):.1f}%" if total_assets else "0%", table_cell),
            Paragraph("Immediate migration planning; deploy hybrid PQC or deprecate legacy algorithm", table_cell),
        ],
        [
            Paragraph("<b>High</b> (0.9 ≤ r < 1.2)", table_cell),
            Paragraph(str(high_count), table_cell),
            Paragraph(f"{(high_count / total_assets * 100):.1f}%" if total_assets else "0%", table_cell),
            Paragraph("Prioritize in next 12–18 month engineering cycle", table_cell),
        ],
        [
            Paragraph("<b>Medium</b> (0.6 ≤ r < 0.9)", table_cell),
            Paragraph(str(med_count), table_cell),
            Paragraph(f"{(med_count / total_assets * 100):.1f}%" if total_assets else "0%", table_cell),
            Paragraph("Schedule migration before CRQC arrival threshold", table_cell),
        ],
        [
            Paragraph("<b>Low</b> (r < 0.6)", table_cell),
            Paragraph(str(low_count), table_cell),
            Paragraph(f"{(low_count / total_assets * 100):.1f}%" if total_assets else "0%", table_cell),
            Paragraph("Adequate safety margin; monitor threat timeline", table_cell),
        ],
    ]

    dist_table = Table(dist_data, colWidths=[1.8 * inch, 0.8 * inch, 0.9 * inch, 4.0 * inch])
    dist_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_CIPHER),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, 1), COLOR_CRITICAL_BG),
            ("BACKGROUND", (0, 2), (-1, 2), COLOR_HIGH_BG),
            ("BACKGROUND", (0, 3), (-1, 3), COLOR_MEDIUM_BG),
            ("BACKGROUND", (0, 4), (-1, 4), COLOR_LOW_BG),
            ("ALIGN", (1, 1), (2, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(dist_table)
    story.append(Spacer(1, 16))

    # 5. Top 15 Prioritized Migration Assets Table (Prompt 9 Requirement)
    story.append(Paragraph("3. Top Prioritized Migration Targets (Ranked by Risk)", section_heading))
    
    # Sort assets: highest risk score or auto-escalated first
    sorted_assets = sorted(
        assets_data,
        key=lambda x: (1 if x.get("auto_escalated") else 0, x.get("risk_score", 0), x.get("urgency_ratio_r", 0)),
        reverse=True,
    )[:15]

    asset_table_data = [
        [
            Paragraph("#", table_header),
            Paragraph("Algorithm", table_header),
            Paragraph("Location", table_header),
            Paragraph("Urgency (r)", table_header),
            Paragraph("Tier", table_header),
            Paragraph("Recommended Replacement", table_header),
            Paragraph("Standard", table_header),
        ]
    ]

    for idx, a in enumerate(sorted_assets, 1):
        r_val = a.get("urgency_ratio_r", 0.0)
        tier_str = a.get("risk_tier", "Low")
        loc_str = f"{a.get('file_path', '')}{(':' + str(a.get('line_number'))) if a.get('line_number') else ''}"
        
        asset_table_data.append([
            Paragraph(str(idx), table_cell),
            Paragraph(a.get("name", "Unknown"), mono_cell),
            Paragraph(loc_str, mono_cell),
            Paragraph(f"{r_val:.2f}", table_cell),
            Paragraph(f"<b>{tier_str}</b>", table_cell),
            Paragraph(a.get("recommended_replacement", "ML-KEM-768"), table_cell),
            Paragraph(a.get("reference_standard", "FIPS 203"), mono_cell),
        ])

    top_table = Table(
        asset_table_data,
        colWidths=[0.3 * inch, 1.1 * inch, 1.7 * inch, 0.7 * inch, 0.7 * inch, 2.0 * inch, 1.0 * inch],
    )
    top_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_CIPHER),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (3, 1), (4, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_PAPER]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(top_table)
    story.append(Spacer(1, 16))

    # 6. Report Footer Note
    story.append(
        Paragraph(
            "<b>Compliance & Methodology Note:</b> PQC recommendations are aligned with NIST finalized standards "
            "(FIPS 203 / ML-KEM, FIPS 204 / ML-DSA, FIPS 205 / SLH-DSA). Classical auto-escalations reflect NIST SP 800-131A Rev 2 deprecations. "
            "Report exported from ECDAT (CycloneDX 1.6 Cryptography Bill of Materials compliant).",
            ParagraphStyle("FooterNote", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=7.5, leading=10, textColor=COLOR_INK_FAINT),
        )
    )

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    filename = f"ecdat-executive-summary-{scan_id}.pdf"
    return pdf_bytes, "application/pdf", filename
