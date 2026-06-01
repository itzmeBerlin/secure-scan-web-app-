"""
report_gen.py — Generates professional PDF and HTML security reports.
Uses ReportLab for PDF. Falls back gracefully if not installed.
"""

import os
import json
import datetime

# ─── PDF Report ───────────────────────────────────────────────────────────────

def generate_pdf_report(data: dict, output_dir: str) -> str:
    """Generate a PDF report. Returns the path to the generated file."""
    scan_id = data.get('scan_id', 'report')
    pdf_path = os.path.join(output_dir, f'{scan_id}_report.pdf')

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle('Title', parent=styles['Title'],
                                     fontSize=22, textColor=colors.HexColor('#7b2cbf'),
                                     alignment=TA_CENTER, spaceAfter=6)
        h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                                  fontSize=14, textColor=colors.HexColor('#4b0082'),
                                  spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10)

        SEVERITY_COLORS = {
            'Critical': colors.HexColor('#ff4757'),
            'High':     colors.HexColor('#ffa502'),
            'Medium':   colors.HexColor('#ffd500'),
            'Low':      colors.HexColor('#2ed573'),
            'Info':     colors.HexColor('#54a0ff'),
        }

        story = []
        risks = data.get('risks', {})
        nmap  = data.get('nmap', {})
        curl  = data.get('curl', {})

        # Title
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Paragraph("Prepared by: Arcane Security Matrix Automated Engine", styles['Italic']))
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#c77dff')))
        story.append(Spacer(1, 0.4*cm))        # Executive Summary
        story.append(Paragraph("Executive Summary", h2_style))
        if data.get('custom_exec_summary'):
            exec_summary_text = data['custom_exec_summary']
        else:
            exec_summary_text = f"This report details the findings of a comprehensive security assessment conducted on the target system ({data.get('target', 'N/A')}). The objective of this assessment was to identify potential vulnerabilities, misconfigurations, and active services that could be leveraged by an adversary."
            if risks.get('overall_risk') in ['Critical', 'High']:
                exec_summary_text += " The assessment identified severe security exposures that pose a significant risk to the integrity, confidentiality, and availability of the system. Immediate remediation of the findings listed in this document is strongly advised to prevent potential exploitation."
            elif risks.get('overall_risk') == 'Medium':
                exec_summary_text += " The assessment identified moderate vulnerabilities. While not immediately critical, these findings represent potential attack vectors or configuration weaknesses that should be addressed in the next available maintenance window to improve the overall security posture."
            else:
                exec_summary_text += " The assessment concluded with a low risk profile. The system demonstrates a strong baseline security posture. However, adherence to the minor recommendations provided below will further harden the environment against emerging threats."
        story.append(Paragraph(exec_summary_text, body_style))
        story.append(Spacer(1, 0.4*cm))

        # Assessment Methodology
        story.append(Paragraph("Assessment Methodology", h2_style))
        if data.get('custom_methodology'):
            methodology_text = data['custom_methodology']
        else:
            methodology_text = "The assessment was performed using non-intrusive port scanning, service enumeration, and protocol analysis. Discovered network topologies and active services were cross-referenced against proprietary threat intelligence and the Common Vulnerabilities and Exposures (CVE) database. Risk scores were algorithmically calculated based on standard CVSS metrics, weighted by the specific context of service exposure and identified configuration weaknesses."
        story.append(Paragraph(methodology_text, body_style))
        story.append(Spacer(1, 0.6*cm))
        

        # Meta info
        meta = [
            ['Target Assessed', data.get('target', 'N/A')],
            ['Assessment Type', data.get('scan_type', 'N/A').title()],
            ['Date of Scan', data.get('timestamp', '')[:19].replace('T', ' ')],
            ['Overall Risk Level', risks.get('overall_risk', 'N/A')],
            ['Calculated Risk Score', f"{risks.get('risk_score', 0)} / 100"],
            ['Total Findings', str(risks.get('total_findings', 0))],
        ]
        meta_table = Table(meta, colWidths=[5*cm, 11*cm])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f0fe')),
            ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 10),
            ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING',    (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.6*cm))

        # Summary
        story.append(Paragraph("Vulnerability Breakdown", h2_style))
        story.append(Paragraph("The following table provides a quantitative breakdown of the vulnerabilities discovered, categorized by their critical severity levels.", body_style))
        story.append(Spacer(1, 0.2*cm))
        summary = risks.get('summary', {})
        sum_data = [['Severity Level', 'Number of Findings']] + [[k, str(v)] for k, v in summary.items() if v > 0]
        if len(sum_data) > 1:
            sum_table = Table(sum_data, colWidths=[6*cm, 4*cm])
            sum_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
                ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
                ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING',    (0, 0), (-1, -1), 6),
                ('FONTSIZE',   (0, 0), (-1, -1), 10),
            ]))
            story.append(sum_table)
        story.append(Spacer(1, 0.6*cm))

        # Open Ports
        story.append(Paragraph("Network Attack Surface Analysis", h2_style))
        story.append(Paragraph("The following network ports and services were found to be exposed and reachable from the scanning source. Unnecessary services should be disabled or firewalled to minimize the attack surface.", body_style))
        story.append(Spacer(1, 0.2*cm))
        ports = nmap.get('ports', [])
        if ports:
            port_data = [['Port', 'Protocol', 'State', 'Service', 'Version Info']]
            for p in ports:
                port_data.append([str(p['port']), p['protocol'], p['state'], p['service'], p.get('version','')[:40]])
            port_table = Table(port_data, colWidths=[2*cm, 2.5*cm, 2.5*cm, 3.5*cm, 5.5*cm])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
                ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
                ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING',    (0, 0), (-1, -1), 5),
                ('FONTSIZE',   (0, 0), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f7fa')]),
            ]))
            story.append(port_table)
        story.append(Spacer(1, 0.6*cm))

        # Findings
        story.append(Paragraph("Critical Findings & Business Impact", h2_style))
        story.append(Paragraph("The following security flaws represent the highest immediate risk to your infrastructure. Each critical or high severity finding is detailed below along with its projected business impact and actionable remediation advice.", body_style))
        story.append(Spacer(1, 0.3*cm))
        
        critical_findings = [f for f in risks.get('findings', []) if f['severity'] in ['Critical', 'High']]
        
        if critical_findings:
            for f in critical_findings:
                sev = f['severity']
                sev_color = SEVERITY_COLORS.get(sev, colors.grey)
                sev_style = ParagraphStyle('Sev', parent=styles['Normal'], fontSize=10,
                                           textColor=sev_color, fontName='Helvetica-Bold')
                story.append(Paragraph(f"[{sev.upper()}] {f['title']}", sev_style))
                story.append(Spacer(1, 0.1*cm))
                story.append(Paragraph(f"<b>Technical Description:</b> {f['description']}", body_style))
                story.append(Spacer(1, 0.1*cm))
                
                impact = f.get('attack', {}).get('impact', 'Potential for severe business disruption, unauthenticated data access, and complete system compromise.')
                impact_style = ParagraphStyle('Impact', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#d35400'))
                story.append(Paragraph(f"<b>Business Impact:</b> {impact}", impact_style))
                story.append(Spacer(1, 0.1*cm))
                
                story.append(Paragraph(f"<b>Actionable Remediation:</b> {f['recommendation']}", body_style))
                story.append(Spacer(1, 0.4*cm))
        else:
            story.append(Paragraph("No critical or high severity findings were detected during this assessment.", body_style))
            story.append(Spacer(1, 0.4*cm))

        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Paragraph("Generated by Intelligent Web Security Testing Platform | Confidential & Proprietary",
                                ParagraphStyle('Footer', parent=styles['Normal'],
                                               fontSize=8, textColor=colors.grey, alignment=TA_CENTER)))

        doc.build(story)

    except ImportError:
        # Fallback: write a plain text report
        with open(pdf_path.replace('.pdf', '.txt'), 'w') as f:
            f.write("ReportLab not installed. Run: pip install reportlab\n")
            f.write(json.dumps(data, indent=2))
        return pdf_path.replace('.pdf', '.txt')

    return pdf_path


# ─── HTML Report ──────────────────────────────────────────────────────────────

def generate_html_report(data: dict, output_dir: str) -> str:
    """Generate a professional HTML report."""
    scan_id = data.get('scan_id', 'report')
    html_path = os.path.join(output_dir, f'{scan_id}_report.html')
    risks = data.get('risks', {})
    nmap  = data.get('nmap', {})
    curl  = data.get('curl', {})

    severity_badge = {
        'Critical': 'background:#ff2d55;color:#fff',
        'High':     'background:#ff6b35;color:#fff',
        'Medium':   'background:#ffd60a;color:#000',
        'Low':      'background:#34c759;color:#fff',
        'Info':     'background:#5ac8fa;color:#000',
    }

    def badge(sev):
        style = severity_badge.get(sev, 'background:#aaa;color:#fff')
        return f'<span style="padding:2px 10px;border-radius:12px;font-weight:700;font-size:12px;{style}">{sev}</span>'

    ports_rows = ''.join(
        f"<tr><td>{p['port']}</td><td>{p['protocol']}</td><td>{p['state']}</td>"
        f"<td>{p['service']}</td><td>{p.get('version','')}</td></tr>"
        for p in nmap.get('ports', [])
    )

    critical_findings = [f for f in risks.get('findings', []) if f['severity'] in ['Critical', 'High']]

    findings_html = ''
    for f in critical_findings:
        impact = f.get('attack', {}).get('impact', 'Potential for severe business disruption, unauthenticated data access, and complete system compromise.')
        findings_html += f"""
        <div class="finding {f['severity'].lower()}">
          <div class="finding-header">{badge(f['severity'])} &nbsp; {f['title']}</div>
          <div class="finding-body">
            <p><strong>Technical Description:</strong> {f['description']}</p>
            <p style="margin-top: 10px; color: #f9a826;"><strong>Business Impact:</strong> {impact}</p>
            <p style="margin-top: 10px; color: #34c759;"><strong>Actionable Remediation:</strong> {f['recommendation']}</p>
            {"<p style='margin-top: 10px; color: #a89bb9;'><strong>CVE:</strong> " + f['cve'] + "</p>" if f.get('cve') else ""}
          </div>
        </div>"""

    summary = risks.get('summary', {})
    summary_cards = ''.join(
        f'<div class="stat-card" style="border-top:4px solid {severity_badge.get(k,"background:#aaa").split(";")[0].split(":")[1]}">'
        f'<div class="stat-number">{v}</div><div class="stat-label">{k}</div></div>'
        for k, v in summary.items()
    )

    # Technical Writer Content
    if data.get('custom_exec_summary'):
        exec_summary_text = data['custom_exec_summary']
    else:
        exec_summary_text = f"This report details the findings of a comprehensive security assessment conducted on the target system (<strong>{data.get('target', 'N/A')}</strong>). The objective of this assessment was to identify potential vulnerabilities, misconfigurations, and active services that could be leveraged by an adversary."
        if risks.get('overall_risk') in ['Critical', 'High']:
            exec_summary_text += " The assessment identified severe security exposures that pose a significant risk to the integrity, confidentiality, and availability of the system. Immediate remediation of the findings listed in this document is strongly advised to prevent potential exploitation."
        elif risks.get('overall_risk') == 'Medium':
            exec_summary_text += " The assessment identified moderate vulnerabilities. While not immediately critical, these findings represent potential attack vectors or configuration weaknesses that should be addressed in the next available maintenance window to improve the overall security posture."
        else:
            exec_summary_text += " The assessment concluded with a low risk profile. The system demonstrates a strong baseline security posture. However, adherence to the minor recommendations provided below will further harden the environment against emerging threats."

    if data.get('custom_methodology'):
        methodology_text = data['custom_methodology']
    else:
        methodology_text = "The assessment was performed utilizing non-intrusive port scanning, service enumeration, and protocol analysis algorithms. Discovered network topologies and active services were cross-referenced against proprietary threat intelligence and the Common Vulnerabilities and Exposures (CVE) database. Risk scores were algorithmically calculated based on standard CVSS metrics, weighted by the specific context of service exposure and identified configuration weaknesses."

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Assessment Report — {data.get('target','')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',sans-serif;background:#0a0510;color:#e2d8f0;line-height:1.6;}}
  .header{{background:linear-gradient(135deg,#251540,#120a1f);color:#fff;padding:40px;text-align:center;border-bottom:2px solid #c77dff}}
  .header h1{{font-size:28px;margin-bottom:6px;color:#c77dff;font-family:'Cinzel Decorative',serif}}
  .header p{{opacity:.7;font-size:14px;color:#f9a826}}
  .container{{max-width:960px;margin:30px auto;padding:0 20px}}
  .card{{background:#120a1f;border:1px solid rgba(138,43,226,0.3);border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 2px 12px rgba(199,125,255,0.08)}}
  .card h2{{font-size:18px;color:#c77dff;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid rgba(199,125,255,0.2)}}
  .card p.prose{{color:#a89bb9;font-size:14.5px;margin-bottom:16px;}}
  .meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
  .meta-item{{background:#1a0f2e;padding:12px 16px;border-radius:8px}}
  .meta-item .label{{font-size:11px;text-transform:uppercase;color:#a89bb9;letter-spacing:.5px}}
  .meta-item .value{{font-size:16px;font-weight:700;color:#fff;margin-top:2px}}
  .stats{{display:flex;gap:16px;flex-wrap:wrap}}
  .stat-card{{flex:1;min-width:100px;background:#1a0f2e;border-radius:10px;padding:16px;text-align:center;border:1px solid rgba(199,125,255,0.1)}}
  .stat-number{{font-size:32px;font-weight:800;color:#fff}}
  .stat-label{{font-size:12px;color:#a89bb9;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#251540;color:#c77dff;padding:10px 12px;text-align:left}}
  td{{padding:9px 12px;border-bottom:1px solid rgba(138,43,226,0.2)}}
  tr:nth-child(even) td{{background:#1a0f2e}}
  .finding{{border-radius:10px;overflow:hidden;margin-bottom:16px;border:1px solid rgba(199,125,255,0.2)}}
  .finding-header{{padding:12px 16px;font-weight:700;font-size:14px;display:flex;align-items:center;gap:8px;background:#1a0f2e;color:#fff}}
  .finding-body{{padding:12px 16px;font-size:13px;line-height:1.6;background:#120a1f}}
  .finding-body p{{margin-bottom:6px}}
  .footer{{text-align:center;padding:30px;color:#76668b;font-size:12px}}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Comprehensive Security Assessment Report</h1>
  <p>Prepared by: Arcane Security Matrix Automated Engine</p>
  <p style="margin-top:8px;font-size:13px;color:#a89bb9">Target: <strong>{data.get('target','')}</strong> &nbsp;|&nbsp; Date: {data.get('timestamp','')[:19].replace('T',' ')}</p>
</div>
<div class="container">
  
  <div class="card">
    <h2>Scan Overview</h2>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Target Assessed</div><div class="value">{data.get('target','')}</div></div>
      <div class="meta-item"><div class="label">Assessment Type</div><div class="value">{data.get('scan_type','').title()}</div></div>
      <div class="meta-item"><div class="label">Overall Risk Level</div><div class="value" style="color:{risks.get('overall_color','#333')}">{risks.get('overall_risk','N/A')}</div></div>
      <div class="meta-item"><div class="label">Calculated Risk Score</div><div class="value">{risks.get('risk_score',0)} <span style="font-size:14px;color:#999">/ 100</span></div></div>
    </div>
  </div>
  
  <div class="card">
    <h2>Vulnerability Breakdown</h2>
    <p class="prose">The following statistics provide a quantitative breakdown of the vulnerabilities discovered, categorized by their critical severity levels.</p>
    <div class="stats">{summary_cards}</div>
  </div>
  
  <div class="card">
    <h2>Network Attack Surface Analysis</h2>
    <p class="prose">The following network ports and services were found to be exposed and reachable from the scanning source. Unnecessary services should be disabled or firewalled to minimize the attack surface.</p>
    <table>
      <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version Info</th></tr>
      {ports_rows}
    </table>
  </div>
  
  <div class="card">
    <h2>Critical Findings & Business Impact ({len(critical_findings)})</h2>
    <p class="prose">The following security flaws represent the highest immediate risk to your infrastructure. Each critical or high severity finding is detailed below along with its projected business impact and actionable remediation advice.</p>
    {findings_html if findings_html else '<p class="prose">No critical or high severity findings were detected during this assessment.</p>'}
  </div>
  
  <div class="card">
    <h2>HTTP Security Headers Analysis</h2>
    <p class="prose">Web application security headers provide a layer of protection against common client-side attacks (e.g., Cross-Site Scripting, Clickjacking).</p>
    <p><strong>Server Identity:</strong> {curl.get('server','')}</p>
    <p style="margin:10px 0"><strong>Headers Present (Secured):</strong> {', '.join(curl.get('security_headers_present',[])) or 'None'}</p>
    <p><strong>Headers Missing (Vulnerable):</strong> {', '.join(curl.get('security_headers_missing',[])) or 'None'}</p>
  </div>
</div>
<div class="footer">Generated by Intelligent Web Security Testing Platform &copy; {datetime.datetime.now().year} | Confidential & Proprietary</div>
</body>
</html>"""

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return html_path
