"""
PDF report generation for a completed evidence analysis.
"""
import os
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak)

from ..models import CustodyLog


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"],
        spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#1e3a8a"),
    ))
    styles.add(ParagraphStyle(
        name="MonoSmall", parent=styles["Normal"],
        fontName="Courier", fontSize=8, leading=10,
    ))
    return styles


def generate_report(evidence, output_path: str):
    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    story = []

    story.append(Paragraph("Network Forensic Investigation Report", styles["Title"]))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Case &amp; Evidence Summary", styles["SectionHeading"]))
    case = evidence.case
    summary_data = [
        ["Case Name", case.name],
        ["Investigator", case.investigator or "unassigned"],
        ["Evidence File", evidence.original_filename],
        ["File Size", f"{evidence.file_size:,} bytes"],
        ["SHA-256", evidence.sha256],
        ["MD5", evidence.md5 or "n/a"],
        ["Uploaded", f"{evidence.uploaded_at.strftime('%Y-%m-%d %H:%M UTC')} by {evidence.uploaded_by}"],
        ["Analysis Status", evidence.analysis_status],
        ["Packet Count", str(evidence.packet_count or 0)],
        ["Capture Window",
         (f"{evidence.capture_start.strftime('%Y-%m-%d %H:%M:%S')} -> "
          f"{evidence.capture_end.strftime('%H:%M:%S')} UTC")
         if evidence.capture_start else "n/a"],
    ]
    t = Table(summary_data, colWidths=[1.6 * inch, 4.9 * inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#fafafa")]),
    ]))
    story.append(t)

    story.append(Paragraph("Suspicious Pattern Alerts", styles["SectionHeading"]))
    alerts = sorted(evidence.alerts, key=lambda a: a.severity)
    if alerts:
        alert_rows = [["Severity", "Title", "Description"]]
        for a in alerts:
            alert_rows.append([
                a.severity.upper(),
                Paragraph(a.title, styles["Normal"]),
                Paragraph(a.description or "", styles["Normal"]),
            ])
        t = Table(alert_rows, colWidths=[0.7 * inch, 2.0 * inch, 3.8 * inch])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No suspicious patterns detected.", styles["Normal"]))

    story.append(PageBreak())
    story.append(Paragraph("Network Sessions", styles["SectionHeading"]))
    sessions = sorted(evidence.sessions, key=lambda s: s.byte_count or 0, reverse=True)
    if sessions:
        session_rows = [["Source", "Destination", "Proto/App", "Pkts", "Bytes", "Notes"]]
        for s in sessions[:50]:
            session_rows.append([
                f"{s.src_ip}:{s.src_port}",
                f"{s.dst_ip}:{s.dst_port}",
                f"{s.protocol}/{s.app_protocol or '-'}",
                str(s.packet_count),
                str(s.byte_count),
                Paragraph(s.summary or "", styles["MonoSmall"]),
            ])
        t = Table(session_rows, colWidths=[1.1 * inch, 1.1 * inch, 0.8 * inch,
                                            0.4 * inch, 0.6 * inch, 2.5 * inch])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
        if len(sessions) > 50:
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                f"({len(sessions) - 50} additional session(s) omitted from this report; "
                "see the full session list in the application.)",
                styles["Normal"]
            ))
    else:
        story.append(Paragraph("No sessions extracted.", styles["Normal"]))

    story.append(PageBreak())
    story.append(Paragraph("Chain of Custody", styles["SectionHeading"]))
    is_valid, broken_at = CustodyLog.verify_chain(evidence.id)
    integrity_note = (
        "Chain integrity: VERIFIED - no tampering detected."
        if is_valid else
        f"Chain integrity: BROKEN at log entry #{broken_at} - possible tampering."
    )
    story.append(Paragraph(integrity_note, styles["Normal"]))
    story.append(Spacer(1, 8))

    logs = evidence.custody_logs
    if logs:
        log_rows = [["#", "Timestamp (UTC)", "Action", "Actor", "Details"]]
        for log in logs:
            log_rows.append([
                str(log.id),
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.action,
                log.actor,
                Paragraph(log.details or "", styles["MonoSmall"]),
            ])
        t = Table(log_rows, colWidths=[0.3 * inch, 1.2 * inch, 1.0 * inch,
                                        0.8 * inch, 3.2 * inch])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    doc.build(story)
    return output_path


def report_path_for(evidence, reports_folder: str) -> str:
    filename = f"report_evidence_{evidence.id}.pdf"
    return os.path.join(reports_folder, filename)