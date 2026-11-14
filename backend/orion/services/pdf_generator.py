"""
Orion Security Platform — Executive PDF Report Generator.

PURPOSE: Generates a professional, branded security assessment PDF report
using ReportLab, detailing discovered vulnerabilities, AI risk scores,
remediation guidelines, and executive summaries.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Color Palette (Orion Branded)
COLOR_PRIMARY_HEX = "#111116"
COLOR_ACCENT_RED_HEX = "#e84057"
COLOR_CRITICAL_HEX = "#e84057"
COLOR_HIGH_HEX = "#f97316"
COLOR_MEDIUM_HEX = "#f59e0b"
COLOR_LOW_HEX = "#3b82f6"
COLOR_INFO_HEX = "#6b7280"


async def generate_pdf_report(scan_result: dict[str, Any], target_url: str) -> bytes:
    """
    Generates a professional executive security report as PDF bytes.
    Accepts raw dict or ScanResult model.
    """
    try:
        from reportlab.lib.colors import HexColor, white, black, whitesmoke
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        logger.error("ReportLab is not installed. Returning fallback text PDF.")
        return _generate_fallback_pdf(scan_result, target_url)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Brand Styles
    title_style = ParagraphStyle(
        "OrionTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=32,
        textColor=HexColor(COLOR_PRIMARY_HEX)
    )
    subtitle_style = ParagraphStyle(
        "OrionSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=HexColor(COLOR_ACCENT_RED_HEX)
    )
    h1_style = ParagraphStyle(
        "OrionH1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=HexColor(COLOR_PRIMARY_HEX),
        spaceAfter=10
    )
    h2_style = ParagraphStyle(
        "OrionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=HexColor(COLOR_PRIMARY_HEX),
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "OrionBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=HexColor("#374151")
    )
    code_style = ParagraphStyle(
        "OrionCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=HexColor("#1f2937")
    )

    story: list[Any] = []

    # Extract Data from Scan Result
    vulns: list[dict[str, Any]] = scan_result.get("vulnerabilities", [])
    if hasattr(vulns, "model_dump"):
        vulns = vulns.model_dump()

    ai_analysis = scan_result.get("ai_analysis", {})
    if hasattr(ai_analysis, "model_dump"):
        ai_analysis = ai_analysis.model_dump()

    risk_score = float(scan_result.get("risk_score", ai_analysis.get("risk_score", 0.0)))
    summary_text = ai_analysis.get("summary", "Automated security scan completed.")
    recommendations: list[str] = ai_analysis.get("top_recommendations", [])
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count Severities
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        s = v.get("severity", "info").lower()
        if s in sev_counts:
            sev_counts[s] += 1
        else:
            sev_counts["info"] += 1

    # ──────────────────────────────────────────────────────────────────
    # PAGE 1: COVER PAGE
    # ──────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(Paragraph("ORION SECURITY PLATFORM", subtitle_style))
    story.append(Paragraph("Executive Vulnerability Assessment Report", title_style))
    story.append(HRFlowable(width="100%", thickness=3, color=HexColor(COLOR_ACCENT_RED_HEX), spaceAfter=25, spaceBefore=10))

    # Target & Meta Box
    meta_data = [
        [Paragraph("<b>Target Assessment URL:</b>", body_style), Paragraph(target_url, body_style)],
        [Paragraph("<b>Report Generated On:</b>", body_style), Paragraph(scan_date, body_style)],
        [Paragraph("<b>Total Findings Identified:</b>", body_style), Paragraph(str(len(vulns)), body_style)],
        [Paragraph("<b>Scanners Deployed:</b>", body_style), Paragraph(", ".join(scan_result.get("tools_used", ["Nmap", "Headers", "SSL", "XSS"])), body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[2.2 * inch, 4.8 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f9fafb")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 1, HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 30))

    # Risk Score Big Callout
    risk_color_hex = COLOR_ACCENT_RED_HEX if risk_score >= 70 else (COLOR_MEDIUM_HEX if risk_score >= 30 else "#22c55e")
    risk_level_label = "CRITICAL RISK" if risk_score >= 70 else ("ELEVATED RISK" if risk_score >= 30 else "LOW RISK")
    
    score_table_data = [
        [
            Paragraph(f"<font size=11 color='#6b7280'>OVERALL SECURITY RISK SCORE</font><br/><br/>"
                      f"<font size=38 color='{risk_color_hex}'><b>{risk_score:.1f}</b></font>"
                      f"<font size=14 color='#9ca3af'> / 100</font><br/><br/>"
                      f"<font size=12 color='{risk_color_hex}'><b>● {risk_level_label}</b></font>", body_style)
        ]
    ]
    score_table = Table(score_table_data, colWidths=[7.0 * inch])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#111116")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("BOX", (0, 0), (-1, -1), 2, HexColor(risk_color_hex)),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 25))

    # Severity Counts Grid
    sev_row_data = [
        [
            Paragraph(f"<font color='{COLOR_CRITICAL_HEX}'><b>Critical</b></font><br/><font size=16><b>{sev_counts['critical']}</b></font>", body_style),
            Paragraph(f"<font color='{COLOR_HIGH_HEX}'><b>High</b></font><br/><font size=16><b>{sev_counts['high']}</b></font>", body_style),
            Paragraph(f"<font color='{COLOR_MEDIUM_HEX}'><b>Medium</b></font><br/><font size=16><b>{sev_counts['medium']}</b></font>", body_style),
            Paragraph(f"<font color='{COLOR_LOW_HEX}'><b>Low</b></font><br/><font size=16><b>{sev_counts['low']}</b></font>", body_style),
            Paragraph(f"<font color='{COLOR_INFO_HEX}'><b>Info</b></font><br/><font size=16><b>{sev_counts['info']}</b></font>", body_style),
        ]
    ]
    sev_table = Table(sev_row_data, colWidths=[1.4 * inch] * 5)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f3f4f6")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("BOX", (0, 0), (-1, -1), 1, HexColor("#d1d5db")),
        ("INNERGRID", (0, 0), (-1, -1), 1, HexColor("#e5e7eb")),
    ]))
    story.append(sev_table)

    story.append(PageBreak())

    # ──────────────────────────────────────────────────────────────────
    # PAGE 2: EXECUTIVE SUMMARY & RECOMMENDATIONS
    # ──────────────────────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary & AI Analysis", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e5e7eb"), spaceAfter=12))
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 15))

    if recommendations:
        story.append(Paragraph("Key Remediation Priorities:", h2_style))
        for idx, rec in enumerate(recommendations, start=1):
            story.append(Paragraph(f"<b>{idx}.</b> {rec}", body_style))
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 15))

    # Findings Table Overview
    story.append(Paragraph("2. Discovered Vulnerabilities Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e5e7eb"), spaceAfter=12))

    if not vulns:
        story.append(Paragraph("No vulnerabilities were identified for this target.", body_style))
    else:
        table_headers = ["#", "Severity", "Finding Title", "Service / Port", "CVE ID"]
        table_rows = [table_headers]

        # Sort: critical first, then high, medium, low, info
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            vulns,
            key=lambda x: severity_order.get(x.get("severity", "info").lower(), 99)
        )

        for i, v in enumerate(sorted_vulns, start=1):
            sev = v.get("severity", "info").upper()
            title = v.get("title", "Untitled")[:45]
            service_port = f"{v.get('service', 'N/A')} :{v.get('port', '')}".strip()
            cve = v.get("cve_id") or "N/A"
            table_rows.append([str(i), sev, title, service_port, cve])

        vuln_summary_table = Table(table_rows, colWidths=[0.4 * inch, 1.0 * inch, 3.4 * inch, 1.2 * inch, 1.0 * inch])
        vuln_summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor(COLOR_PRIMARY_HEX)),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e5e7eb")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(vuln_summary_table)

    story.append(PageBreak())

    # ──────────────────────────────────────────────────────────────────
    # PAGE 3+: DETAILED TECHNICAL FINDINGS
    # ──────────────────────────────────────────────────────────────────
    story.append(Paragraph("3. Detailed Vulnerability Findings & Fixes", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e5e7eb"), spaceAfter=15))

    import html

    for idx, v in enumerate(sorted_vulns, start=1):
        sev_color = HexColor(COLOR_ACCENT_RED_HEX) if v.get("severity") == "critical" else HexColor("#f59e0b")
        item_story = []
        safe_title = html.escape(str(v.get('title', 'Unknown')))
        item_story.append(
            Paragraph(f"<b>#{idx}. {safe_title}</b> "
                      f"[<font color='{sev_color}'><b>{v.get('severity', 'info').upper()}</b></font>]", h2_style)
        )
        
        score_val = v.get("cvss_score")
        score_badge = f" | <b>CVSS v3.1 Score:</b> <font color='{sev_color}'><b>{score_val:.1f}</b></font>" if score_val is not None else ""
        safe_service = html.escape(str(v.get('service', 'N/A')))
        safe_cve = html.escape(str(v.get('cve_id') or 'N/A'))
        details_text = (
            f"<b>Service:</b> {safe_service} | "
            f"<b>Port:</b> {v.get('port', 'N/A')} | "
            f"<b>CWE/CVE ID:</b> {safe_cve}"
            f"{score_badge}"
        )
        item_story.append(Paragraph(details_text, body_style))
        item_story.append(Spacer(1, 6))

        if v.get("description"):
            # Escape literal XML/HTML entities first so raw payloads like <script> don't break ReportLab
            raw_desc = html.escape(str(v.get("description", "")))
            desc_html = raw_desc.replace("### 📍 Vulnerability Location", "<br/><b>📍 Vulnerability Location:</b>")
            desc_html = desc_html.replace("### 💥 Exploitation Proof &amp; Payload", "<br/><b>💥 Exploitation Proof & Payload:</b>")
            desc_html = desc_html.replace("### 💥 Exploitation Proof & Payload", "<br/><b>💥 Exploitation Proof & Payload:</b>")
            desc_html = desc_html.replace("### 🔬 Technical Analysis &amp; Vulnerability Mechanics", "<br/><b>🔬 Technical Analysis & Vulnerability Mechanics:</b>")
            desc_html = desc_html.replace("### 🔬 Technical Analysis & Vulnerability Mechanics", "<br/><b>🔬 Technical Analysis & Vulnerability Mechanics:</b>")
            desc_html = desc_html.replace("### 📊 Threat Severity &amp; CVSS v3.1 Scoring", "<br/><b>📊 Threat Severity & CVSS v3.1 Scoring:</b>")
            desc_html = desc_html.replace("### 📊 Threat Severity & CVSS v3.1 Scoring", "<br/><b>📊 Threat Severity & CVSS v3.1 Scoring:</b>")
            desc_html = desc_html.replace("\n", "<br/>")
            desc_html = desc_html.replace("`", " ")
            item_story.append(Paragraph(desc_html, body_style))
            item_story.append(Spacer(1, 6))

        steps = v.get("remediation_steps", [])
        if steps:
            item_story.append(Paragraph("<b>Remediation Steps:</b>", body_style))
            for step in steps:
                safe_step = html.escape(str(step))
                item_story.append(Paragraph(f"• {safe_step}", code_style))
                item_story.append(Spacer(1, 2))

        item_story.append(Spacer(1, 10))
        item_story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb"), spaceAfter=10))
        story.append(KeepTogether(item_story))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def _generate_fallback_pdf(scan_result: dict[str, Any], target_url: str) -> bytes:
    """Fallback plain-text / minimal PDF generator if ReportLab encounters an issue."""
    output = io.BytesIO()
    timestamp = datetime.now(timezone.utc).isoformat()
    content = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 200 >> stream
BT
/F1 16 Tf
50 700 Td
(Orion Security Platform - Executive Report) Tj
/F1 10 Tf
0 -30 Td
(Target: {target_url}) Tj
0 -20 Td
(Date: {timestamp}) Tj
0 -20 Td
(Risk Score: {scan_result.get('risk_score', 'N/A')}) Tj
0 -20 Td
(Total Findings: {len(scan_result.get('vulnerabilities', []))}) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000494 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
568
%%EOF
"""
    output.write(content.encode("utf-8"))
    return output.getvalue()

