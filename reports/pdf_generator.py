"""
PrivWatch 3.0 - Professional PDF Report Generator
Generates enterprise-grade executive and technical PDF security reports using ReportLab.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import List, Optional, Any, Dict

from core.models import Finding, Severity, SystemPosture, utc_now


class PDFGenerator:
    """Generates professional PDF audit reports using ReportLab with clean fallbacks"""

    @staticmethod
    def generate_report(findings: List[Finding], output_file: str, mode: str = "red",
                        posture: Optional[SystemPosture] = None) -> str:
        """Generate PDF report using ReportLab if installed; fallback to text report if missing"""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            return PDFGenerator._generate_with_reportlab(findings, str(out_path), mode, posture)
        except ImportError:
            return PDFGenerator._generate_text_fallback(findings, str(out_path), mode, posture)
        except Exception as e:
            # Fallback if ReportLab rendering hits an environmental font or styling error
            return PDFGenerator._generate_text_fallback(findings, str(out_path), mode, posture)

    @staticmethod
    def _generate_with_reportlab(findings: List[Finding], output_file: str,
                                 mode: str, posture: Optional[SystemPosture]) -> str:
        """Construct multi-page professional PDF using ReportLab Flowables"""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
        )

        doc = SimpleDocTemplate(
            output_file,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold'
        )

        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569')
        )

        heading2_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold'
        )

        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )

        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#0f172a'),
            fontName='Courier',
            backColor=colors.HexColor('#f1f5f9')
        )

        posture_obj = posture or SystemPosture.calculate(findings)
        elements = []

        # 1. Header Banner
        elements.append(Paragraph("PrivWatch 3.0 — Security Assessment Report", title_style))
        elements.append(Paragraph(
            f"Operation Mode: <b>{mode.upper()}</b> &nbsp;|&nbsp; "
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; "
            f"Total Findings: {len(findings)}",
            subtitle_style
        ))
        elements.append(Spacer(1, 15))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#cbd5e1')))
        elements.append(Spacer(1, 15))

        # 2. Executive Summary Metrics Table
        elements.append(Paragraph("Executive Summary & Security Posture", heading2_style))
        elements.append(Spacer(1, 8))

        posture_color = colors.HexColor('#16a34a') if posture_obj.score >= 80 else (
            colors.HexColor('#d97706') if posture_obj.score >= 50 else colors.HexColor('#dc2626')
        )

        summary_data = [
            ["Security Posture Score", f"{posture_obj.score} / 100 ({posture_obj.status})"],
            ["Critical Findings", str(posture_obj.critical_count)],
            ["High Severity Findings", str(posture_obj.high_count)],
            ["Medium Severity Findings", str(posture_obj.medium_count)],
            ["Low / Info Findings", str(posture_obj.low_count + posture_obj.info_count)],
            ["Total Evaluated Findings", str(len(findings))]
        ]

        summary_table = Table(summary_data, colWidths=[200, 330])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # 3. Detailed Findings
        elements.append(Paragraph("Detailed Security Findings", heading2_style))
        elements.append(Spacer(1, 10))

        if not findings:
            elements.append(Paragraph("No security vulnerabilities or elevated privileges were identified during this assessment.", body_style))
        else:
            for i, f in enumerate(findings, 1):
                sev_color = {
                    'CRITICAL': colors.HexColor('#dc2626'),
                    'HIGH': colors.HexColor('#ea580c'),
                    'MEDIUM': colors.HexColor('#d97706'),
                    'LOW': colors.HexColor('#2563eb'),
                    'INFO': colors.HexColor('#64748b')
                }.get(f.severity, colors.HexColor('#64748b'))

                finding_elements = [
                    Paragraph(f"<b>#{i} &nbsp; [{f.severity}] &nbsp; {f.title}</b>", ParagraphStyle(
                        'FindingHeading',
                        parent=body_style,
                        fontSize=10,
                        leading=13,
                        textColor=sev_color,
                        fontName='Helvetica-Bold'
                    )),
                    Spacer(1, 4),
                    Paragraph(f"<b>Vector:</b> {f.vector} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Resource:</b> {f.affected_resource or 'N/A'}", body_style),
                    Spacer(1, 4),
                    Paragraph(f"<b>Description:</b> {f.description}", body_style),
                    Spacer(1, 4),
                    Paragraph(f"<b>Risk Explanation:</b> {f.risk_explanation}", body_style),
                    Spacer(1, 4),
                    Paragraph(f"<b>Defensive Remediation:</b>", body_style),
                    Paragraph(f.remediation.replace('\n', '<br/>'), code_style),
                    Spacer(1, 10),
                    HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')),
                    Spacer(1, 10)
                ]
                elements.append(KeepTogether(finding_elements))

        doc.build(elements)
        return output_file

    @staticmethod
    def generate_item_report(item: Any, output_file: str, related_events: Optional[List[Any]] = None) -> str:
        """Generate ReportLab PDF for a single Finding or Incident with evidence hashes and limitations."""
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

            doc = SimpleDocTemplate(str(out_path), pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle('ItemTitle', parent=styles['Heading1'], fontSize=18, leading=22, textColor=colors.HexColor('#0f172a'), fontName='Helvetica-Bold')
            sub_style = ParagraphStyle('ItemSub', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor('#475569'))
            h2_style = ParagraphStyle('ItemH2', parent=styles['Heading2'], fontSize=12, leading=16, textColor=colors.HexColor('#1e293b'), fontName='Helvetica-Bold')
            body_style = ParagraphStyle('ItemBody', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor('#334155'))
            code_style = ParagraphStyle('ItemCode', parent=styles['Normal'], fontSize=8, leading=11, fontName='Courier', textColor=colors.HexColor('#0f172a'), backColor=colors.HexColor('#f8fafc'))

            elements = []
            is_finding = hasattr(item, "finding_id")
            item_type = "Finding" if is_finding else "Incident"
            item_id = getattr(item, "finding_id", None) or getattr(item, "incident_id", "unknown")
            sev = getattr(item, "severity", "HIGH")

            sev_color = colors.HexColor('#dc2626') if sev in ("CRITICAL", "HIGH") else colors.HexColor('#d97706')

            elements.append(Paragraph(f"UATU Security Report — {item_type} #{item_id}", title_style))
            elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; Target Host: localhost", sub_style))
            elements.append(Spacer(1, 10))
            elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#cbd5e1')))
            elements.append(Spacer(1, 12))

            # Summary Table
            table_rows = [
                ["Item Type", item_type],
                ["Identifier", item_id],
                ["Title", getattr(item, "title", "")],
                ["Severity", sev],
                ["Confidence", f"{getattr(item, 'confidence', 1.0):.2f}"],
            ]
            if is_finding:
                table_rows.append(["Vector", getattr(item, "vector", "GENERIC")])
                table_rows.append(["Affected Resource", getattr(item, "affected_resource", "")])
                table_rows.append(["Evidence Hash (SHA-256)", item.evidence_hash() if hasattr(item, "evidence_hash") else "N/A"])
            else:
                table_rows.append(["Status", getattr(item, "status", "NEW")])
                table_rows.append(["Attribution", json.dumps(getattr(item, "attribution", {}))])
                table_rows.append(["Constituent Events", str(len(getattr(item, "event_ids", [])))])

            t = Table(table_rows, colWidths=[160, 370])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 15))

            # Narrative / Details
            if is_finding:
                elements.append(Paragraph("Vulnerability Description", h2_style))
                elements.append(Paragraph(getattr(item, "description", ""), body_style))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph("Risk Explanation", h2_style))
                elements.append(Paragraph(getattr(item, "risk_explanation", ""), body_style))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph("Defensive Remediation", h2_style))
                elements.append(Paragraph(getattr(item, "remediation", "").replace('\n', '<br/>'), code_style))
            else:
                elements.append(Paragraph("Incident Hypothesis & Forensics", h2_style))
                elements.append(Paragraph(getattr(item, "hypothesis", ""), body_style))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph("Ordered Evidence Timeline", h2_style))
                if related_events:
                    for idx, ev in enumerate(related_events, 1):
                        ts_str = ev.timestamp.isoformat() if hasattr(ev, "timestamp") else "N/A"
                        elements.append(Paragraph(f"<b>Event {idx}:</b> [{ts_str}] {getattr(ev, 'event_type', '')} by user={getattr(ev, 'user', '')} (exe: {getattr(ev, 'exe', getattr(ev, 'command', ''))})", code_style))
                        elements.append(Spacer(1, 2))
                else:
                    elements.append(Paragraph(f"Event IDs: {', '.join(getattr(item, 'event_ids', []))}", code_style))

            elements.append(Spacer(1, 15))
            # Collection Limitations Section
            elements.append(Paragraph("Collection Limitations & Methodology", h2_style))
            elements.append(Paragraph(
                "• Static findings are evaluated based on POSIX filesystem permission bits and system configurations.<br/>"
                "• Telemetry events represent observed live kernel (auditd) or systemd journal logs.<br/>"
                "• In absence of active kernel audit rules, transient processes executing under 50ms may not appear.",
                body_style
            ))

            doc.build(elements)
            return str(out_path)
        except Exception:
            return PDFGenerator._generate_text_fallback([item] if is_finding else [], str(out_path), "audit", None)


    @staticmethod
    def _generate_text_fallback(findings: List[Finding], output_file: str,
                                mode: str, posture: Optional[SystemPosture]) -> str:
        """Fallback generator producing a clean text file"""
        txt_path = output_file.replace('.pdf', '.txt')
        posture_obj = posture or SystemPosture.calculate(findings)

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 78 + "\n")
            f.write(f"PRIVWATCH 3.0 SECURITY ASSESSMENT REPORT\n")
            f.write(f"Mode: {mode.upper()}  |  Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"Posture Score: {posture_obj.score}/100 ({posture_obj.status})\n")
            f.write("=" * 78 + "\n\n")

            f.write("SUMMARY BY SEVERITY:\n")
            f.write(f"  CRITICAL : {posture_obj.critical_count}\n")
            f.write(f"  HIGH     : {posture_obj.high_count}\n")
            f.write(f"  MEDIUM   : {posture_obj.medium_count}\n")
            f.write(f"  LOW/INFO : {posture_obj.low_count + posture_obj.info_count}\n\n")

            f.write("DETAILED FINDINGS:\n")
            f.write("-" * 78 + "\n")
            for i, fnd in enumerate(findings, 1):
                f.write(f"[{i}] [{fnd.severity}] {fnd.title}\n")
                f.write(f"Vector   : {fnd.vector}\n")
                f.write(f"Resource : {fnd.affected_resource}\n")
                f.write(f"Details  : {fnd.description}\n")
                f.write(f"Risk     : {fnd.risk_explanation}\n")
                f.write(f"Fix      : {fnd.remediation}\n\n")

        return txt_path
