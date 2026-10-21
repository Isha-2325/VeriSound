from pathlib import Path
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ForensicReportGenerator:
    """
    Generates standardized forensic laboratory examination reports in PDF format
    focusing on splice, cut, and tampering detection with AI automated diagnostic summaries.
    """

    @classmethod
    def generate_pdf(cls, output_path: Path, evidence_info: Dict[str, Any], results: Dict[str, Any]) -> Path:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=17,
            textColor=colors.HexColor("#0f172a"),
            alignment=1,
            spaceAfter=3
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#475569"),
            alignment=1,
            spaceAfter=10
        )
        h2_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=11,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=8,
            spaceAfter=4
        )
        body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#334155"), leading=11)
        bold_style = ParagraphStyle("BoldBody", parent=body_style, fontName="Helvetica-Bold")

        story = []

        # Header
        story.append(Paragraph("DIGITAL AUDIO FORENSIC EXAMINATION REPORT", title_style))
        story.append(Paragraph("AUDIO TAMPERING & SPLICE VERIFICATION LAB // AUTOMATED AI SCAN", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=10))

        # Evidence Details
        hashes = results.get("hashes", {})
        ai = results.get("ai_assessment", {})
        sig = results.get("signal_metrics", {})

        ev_table_data = [
            [Paragraph("File Examined:", bold_style), Paragraph(str(evidence_info.get("filename", "N/A")), body_style),
             Paragraph("File Size:", bold_style), Paragraph(f"{hashes.get('file_size_bytes', 0):,} bytes", body_style)],
            [Paragraph("SHA-256 Digest:", bold_style), Paragraph(f"<font name='Courier'>{hashes.get('sha256', 'N/A')}</font>", body_style),
             Paragraph("MD5 Digest:", bold_style), Paragraph(f"<font name='Courier'>{hashes.get('md5', 'N/A')}</font>", body_style)],
            [Paragraph("Duration:", bold_style), Paragraph(f"{sig.get('duration_seconds', 0)} seconds", body_style),
             Paragraph("Sample Rate:", bold_style), Paragraph(f"{sig.get('sample_rate_hz', 0)} Hz ({sig.get('channels', 1)} ch)", body_style)]
        ]
        t1 = Table(ev_table_data, colWidths=[1.3 * inch, 2.5 * inch, 1.2 * inch, 2.5 * inch])
        t1.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t1)
        story.append(Spacer(1, 10))

        # Executive Forensic Verdict
        story.append(Paragraph("1. Executive Forensic Verdict & AI Assessment", h2_style))
        verdict_color = colors.HexColor("#dc2626") if ai.get("is_tampered") else colors.HexColor("#16a34a")
        
        verdict_data = [
            [Paragraph("Forensic Classification:", bold_style),
             Paragraph(f"<font color='{verdict_color}' size='11'><b>{ai.get('verdict', 'INCONCLUSIVE')}</b></font>", body_style)],
            [Paragraph("Tamper Probability:", bold_style),
             Paragraph(f"<b>{ai.get('tamper_probability_pct', 0.0)}%</b>", body_style)],
            [Paragraph("AI Investigator Summary:", bold_style),
             Paragraph(ai.get("summary_statement", "No statement generated."), body_style)],
            [Paragraph("Total Flagged Anomalies:", bold_style),
             Paragraph(f"{ai.get('total_anomalies_count', 0)} suspicious event(s) detected across timeline", body_style)]
        ]
        t2 = Table(verdict_data, colWidths=[1.8 * inch, 5.7 * inch])
        t2.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t2)
        story.append(Spacer(1, 10))

        # Splice & Tamper Findings Breakdown
        story.append(Paragraph("2. Splice & Tamper Anomaly Timeline", h2_style))
        findings = ai.get("findings", [])
        if findings:
            findings_data = [
                [Paragraph("Timestamp", bold_style), Paragraph("Anomaly Category", bold_style),
                 Paragraph("Severity", bold_style), Paragraph("AI Diagnostic Finding", bold_style)]
            ]
            for f in findings:
                sev_color = colors.HexColor("#dc2626") if f.get("severity") == "CRITICAL" else colors.HexColor("#d97706")
                findings_data.append([
                    Paragraph(f"<b>{f.get('timestamp', '00:00')}</b>", body_style),
                    Paragraph(f.get("type", "Anomaly"), body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{f.get('severity', 'HIGH')}</b></font>", body_style),
                    Paragraph(f.get("ai_diagnosis", ""), body_style)
                ])
            t3 = Table(findings_data, colWidths=[1.0 * inch, 1.8 * inch, 1.0 * inch, 3.7 * inch])
            t3.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t3)
        else:
            story.append(Paragraph("<i>No splice cuts, digital zero redactions, or room noise shifts were detected across the recording.</i>", body_style))

        story.append(Spacer(1, 14))

        # Certification Block
        story.append(Paragraph("3. Examiner Verification & Certification", h2_style))
        cert_text = (
            "This document is an automated forensic examination report generated by the Digital Audio Forensic Lab. "
            "All cryptographic digests and acoustic anomaly timestamps were extracted following deterministic mathematical signal analysis."
        )
        story.append(Paragraph(cert_text, body_style))
        story.append(Spacer(1, 25))

        sig_data = [
            [Paragraph("<b>Forensic Examiner Signature:</b> ___________________________", body_style),
             Paragraph("<b>Date of Verification:</b> ___________________________", body_style)]
        ]
        t4 = Table(sig_data, colWidths=[4.5 * inch, 3.0 * inch])
        t4.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(t4)

        doc.build(story)
        return output_path
