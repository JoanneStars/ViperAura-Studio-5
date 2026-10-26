'''Multi-page, printable PDF with conservative findings language.'''
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,KeepTogether,Table,TableStyle
from engine import REPORTS,get_run,connection

def generate_report(run_id, db=None, outdir=REPORTS, ai_text=None):
    from engine import DB
    db=db or DB
    run,findings=get_run(run_id,db)
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    path=outdir/f'ViperAura_{run_id[:10]}.pdf'
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='VTitle',parent=styles['Title'],textColor=colors.HexColor('#6A289B'),fontSize=22,spaceAfter=18))
    styles.add(ParagraphStyle(name='VSmall',parent=styles['BodyText'],fontSize=9,leading=13,spaceAfter=7))
    doc=SimpleDocTemplate(str(path),pagesize=letter,topMargin=45,bottomMargin=48,leftMargin=45,rightMargin=45)
    para=lambda text,sty='VSmall':Paragraph(escape(str(text)),styles[sty])
    flow=[para('VIPERAURA | VULNERABILITY ASSESSMENT','VTitle'),
          para(f"Authorized lab target: {run['target']}"),para(f"Scan ID: {run['id']}"),
          para(f"Started (UTC): {run['started']}  |  Status: {run['status']}"),Spacer(1,12),
          para('Executive summary','Heading2')]
    counts=Counter(f['severity'] for f in findings)
    rows=[['Open services','High','Medium','Informational'],[str(len(findings)),str(counts['HIGH']),str(counts['MEDIUM']),str(counts['INFO'])]]
    table=Table(rows,colWidths=[125]*4)
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#EDE3F6')),
            ('GRID',(0,0),(-1,-1),0.5,colors.lightgrey),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
    flow += [table,Spacer(1,12),para('Findings are exposure review prompts, not evidence of exploitation. NVD keyword results are unverified research leads, not confirmed affected-version matches.'),
             para('Detailed findings','Heading2')]
    if not findings:flow.append(para('No open services detected within the selected TCP scan scope. This does not prove the target is secure.'))
    for f in findings:
        blocks=[para(f"{f['host']} | {f['port']}/{f['protocol']} | {f['service']} | {f['severity']}",'Heading3'),
             para(f"Product/version: {f['product'] or 'Unknown'} {f['version'] or ''}"),
             para(f"Review item: {f['issue']}"),para(f"Recommendation: {f['recommendation']}")]
        if f['cves']:
            blocks.append(para('UNVERIFIED NVD keyword candidates (CVSS refers to the published CVE, NOT the scanned host):'))
            for cv in f['cves'][:10]:blocks.append(para(f"{cv['cve_id']} | CVSS {cv['cvss'] if cv['cvss'] is not None else 'N/A'} | https://nvd.nist.gov/vuln/detail/{cv['cve_id']}"))
        blocks.append(Spacer(1,9));flow.append(KeepTogether(blocks))
    if ai_text:flow += [para('Optional AI narrative (not independently validated)','Heading2'),para(ai_text)]
    flow += [para('Method and limitations','Heading2'),para('Single private/loopback IP only. Nmap TCP connect scan, lightweight service-version detection, 100 or 1,000 common TCP ports depending on mode, no exploit attempts. False positives and false negatives are possible. Only a confirmed match of product, version, configuration and affected range can establish CVE applicability. AI text is explanatory, not diagnostic.'),
             para('Reference: https://nvd.nist.gov/developers/vulnerabilities')]
    def footer(c,d):
        c.saveState();c.setFont('Helvetica',8);c.setFillColor(colors.grey)
        c.drawString(45,30,'VIPERAURA | Authorized defensive lab');c.drawRightString(565,30,f'Page {d.page}');c.restoreState()
    doc.build(flow,onFirstPage=footer,onLaterPages=footer)
    with connection(db) as c:c.execute('UPDATE runs SET report=? WHERE id=?',(str(path),run_id))
    return path
