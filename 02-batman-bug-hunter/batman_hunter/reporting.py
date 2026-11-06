"""Generate a portable PDF evidence report."""
from io import BytesIO
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

def build_pdf(title: str, summary: dict, details: list, notes: str="") -> bytes:
    buff=BytesIO(); doc=SimpleDocTemplate(buff,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=18*mm,bottomMargin=18*mm)
    styles=getSampleStyleSheet(); styles.add(ParagraphStyle(name="SmallCell",parent=styles["BodyText"],fontSize=8,leading=10))
    story=[Paragraph("BATCOMPUTER / BATMAN BUG HUNTER X",styles["Title"]),Paragraph(escape(str(title)),styles["Heading1"]),
           Paragraph("Generated "+datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),styles["Normal"]),Spacer(1,8*mm),
           Paragraph("Executive summary",styles["Heading2"])]
    rows=[["Metric","Value"]]+[[str(k),str(v)] for k,v in summary.items()]
    t=Table(rows,colWidths=[65*mm,105*mm]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#202a38")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.grey),("PADDING",(0,0),(-1,-1),6)])); story += [t,Spacer(1,6*mm),Paragraph("Evidence and observations",styles["Heading2"])]
    for i,item in enumerate(details,1):
        text=" | ".join(f"{escape(str(k))}: {escape(str(v))}" for k,v in item.items())
        story.append(KeepTogether([Paragraph(f"{i}. {text[:2500]}",styles["SmallCell"]),Spacer(1,3*mm)]))
    if notes: story += [Spacer(1,4*mm),Paragraph("Limitations and analyst notes",styles["Heading2"]),Paragraph(escape(notes[:5000]).replace("\n","<br/>"),styles["BodyText"])]
    story += [Spacer(1,6*mm),Paragraph("This report records automated observations, not a certification of security or proof of compromise. Validate evidence and remain within written authorization.",styles["Italic"])]
    doc.build(story); return buff.getvalue()
