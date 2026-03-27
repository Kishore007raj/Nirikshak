"""
PDF Report generation using reportlab.platypus for proper text wrapping
and multi-page support.
"""

import os
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
    HRFlowable,
)

from core.models import ScanResult
from utils.fallback import generate_description, generate_impact, generate_fix


def _get_styles():
    """Build custom paragraph styles."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontSize=22,
        leading=26,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        fontSize=14,
        leading=18,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#334155"),
        spaceBefore=16,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="MetaLabel",
        fontSize=10,
        leading=14,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#475569"),
    ))
    styles.add(ParagraphStyle(
        name="MetaValue",
        fontSize=10,
        leading=14,
        fontName="Helvetica",
        textColor=colors.HexColor("#1e293b"),
    ))
    styles.add(ParagraphStyle(
        name="CellText",
        fontSize=8,
        leading=11,
        fontName="Helvetica",
        textColor=colors.HexColor("#1e293b"),
        wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="CellBold",
        fontSize=8,
        leading=11,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1e293b"),
        wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="FooterStyle",
        fontSize=7,
        leading=10,
        fontName="Helvetica",
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_CENTER,
    ))
    return styles


def _severity_color(severity: str) -> colors.Color:
    """Return a background color for severity badges."""
    sev = severity.upper() if severity else "LOW"
    mapping = {
        "CRITICAL": colors.HexColor("#fee2e2"),
        "HIGH": colors.HexColor("#ffedd5"),
        "MEDIUM": colors.HexColor("#fef9c3"),
        "LOW": colors.HexColor("#dbeafe"),
    }
    return mapping.get(sev, colors.HexColor("#f1f5f9"))


def _severity_text_color(severity: str) -> colors.Color:
    """Return text color for severity."""
    sev = severity.upper() if severity else "LOW"
    mapping = {
        "CRITICAL": colors.HexColor("#991b1b"),
        "HIGH": colors.HexColor("#9a3412"),
        "MEDIUM": colors.HexColor("#854d0e"),
        "LOW": colors.HexColor("#1e40af"),
    }
    return mapping.get(sev, colors.HexColor("#334155"))


def _footer(canvas_obj, doc):
    """Add page number footer."""
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(colors.HexColor("#94a3b8"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2,
        20 * mm,
        f"NIRIKSHAK Security Report — Page {doc.page}",
    )
    canvas_obj.restoreState()


def generate_pdf_report(scan_result: ScanResult) -> str:
    """Generate a multi-page PDF report with text wrapping via platypus."""

    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)

    file_name = f"report_{scan_result.scan_id}.pdf"
    pdf_path = str(output_dir / file_name)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=50,
        bottomMargin=50,
    )

    styles = _get_styles()
    story = []

    # ── Title ────────────────────────────────────────────────────────────
    story.append(Paragraph("NIRIKSHAK Security Report", styles["ReportTitle"]))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(
        width="100%", thickness=2,
        color=colors.HexColor("#3b82f6"),
        spaceBefore=4, spaceAfter=12,
    ))

    # ── Metadata ─────────────────────────────────────────────────────────
    meta_data = [
        ["Scan ID:", scan_result.scan_id],
        ["Provider:", scan_result.provider.upper()],
        ["Timestamp:", scan_result.timestamp],
        ["Risk Score:", str(scan_result.risk_score)],
    ]

    sc = scan_result.severity_count or {}
    summary_str = (
        f"CRITICAL: {sc.get('CRITICAL', 0)} | "
        f"HIGH: {sc.get('HIGH', 0)} | "
        f"MEDIUM: {sc.get('MEDIUM', 0)} | "
        f"LOW: {sc.get('LOW', 0)}"
    )
    meta_data.append(["Summary:", summary_str])

    meta_table_data = []
    for label, value in meta_data:
        meta_table_data.append([
            Paragraph(label, styles["MetaLabel"]),
            Paragraph(value, styles["MetaValue"]),
        ])

    meta_table = Table(meta_table_data, colWidths=[90, 420])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ── Findings ─────────────────────────────────────────────────────────
    story.append(Paragraph("Findings Detail", styles["SectionHeader"]))
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=colors.HexColor("#e2e8f0"),
        spaceBefore=2, spaceAfter=8,
    ))

    if not scan_result.findings:
        story.append(Paragraph(
            "No security findings detected during this scan.",
            styles["MetaValue"],
        ))
    else:
        # Build findings table
        header = [
            Paragraph("<b>Resource</b>", styles["CellBold"]),
            Paragraph("<b>Type</b>", styles["CellBold"]),
            Paragraph("<b>Severity</b>", styles["CellBold"]),
            Paragraph("<b>Description</b>", styles["CellBold"]),
            Paragraph("<b>Impact</b>", styles["CellBold"]),
            Paragraph("<b>Fix Suggestion</b>", styles["CellBold"]),
            Paragraph("<b>Compliance</b>", styles["CellBold"]),
        ]

        table_data = [header]
        col_widths = [75, 60, 55, 115, 85, 100, 45]

        for f in scan_result.findings:
            res_type = f.resource_type or "unknown"
            sev = f.severity or "MEDIUM"

            description = f.description if f.description else generate_description(res_type, sev)
            impact = f.impact if f.impact else generate_impact(res_type, sev)
            fix = f.fix_suggestion if f.fix_suggestion else generate_fix(res_type, sev)

            # Format compliance
            compliance_list = f.compliance if f.compliance else []
            if isinstance(compliance_list, str):
                compliance_str = compliance_list
            elif isinstance(compliance_list, list) and compliance_list:
                parts = []
                for c in compliance_list:
                    if isinstance(c, dict):
                        fw = c.get("framework", "")
                        ctrl = c.get("control_id", "")
                        if fw and ctrl:
                            parts.append(f"{fw} {ctrl}")
                        elif ctrl:
                            parts.append(ctrl)
                    elif isinstance(c, str):
                        parts.append(c)
                compliance_str = ", ".join(parts) if parts else "CIS Benchmark"
            else:
                compliance_str = "CIS Benchmark"

            row = [
                Paragraph(f.resource_id or "N/A", styles["CellText"]),
                Paragraph(res_type, styles["CellText"]),
                Paragraph(sev, styles["CellBold"]),
                Paragraph(description, styles["CellText"]),
                Paragraph(impact, styles["CellText"]),
                Paragraph(fix, styles["CellText"]),
                Paragraph(compliance_str, styles["CellText"]),
            ]
            table_data.append(row)

        findings_table = Table(table_data, colWidths=col_widths, repeatRows=1)

        # Style the table
        style_commands = [
            # Header row
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            # All cells
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]

        # Color severity cells per row
        for row_idx in range(1, len(table_data)):
            sev_val = scan_result.findings[row_idx - 1].severity or "LOW"
            style_commands.append(
                ("BACKGROUND", (2, row_idx), (2, row_idx), _severity_color(sev_val))
            )
            style_commands.append(
                ("TEXTCOLOR", (2, row_idx), (2, row_idx), _severity_text_color(sev_val))
            )

        findings_table.setStyle(TableStyle(style_commands))
        story.append(findings_table)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

    return f"/download/{scan_result.scan_id}"
