"""Rapport consolide en PDF — assemblage deterministe (zero token).

Prend tout ce que le consultant a VALIDE (CVE techniques, risques
organisationnels, menaces STRIDE, scenarios) + la synthese narrative de l'IA,
et produit un PDF professionnel. L'assemblage ne fait AUCUN appel IA : il rend
fidelement les donnees validees. Seule la synthese (passee en entree) vient de l'IA.
"""

import io
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, KeepTogether)

INK = colors.HexColor("#13202B")
TEAL = colors.HexColor("#0F7B68")
RED = colors.HexColor("#D14233")
AMBER = colors.HexColor("#B9740F")
MUTED = colors.HexColor("#647082")
LINE = colors.HexColor("#E1E6EC")
LSOFT = colors.HexColor("#EDF0F4")

STRIDE_LABELS = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                 "I": "Info. disclosure", "D": "Denial of service",
                 "E": "Elevation of priv."}


def _sev_color(s):
    return {"HIGH": RED, "MEDIUM": AMBER, "LOW": TEAL}.get((s or "").upper(), MUTED)


def _styles():
    ss = getSampleStyleSheet()
    st = {}
    st["title"] = ParagraphStyle("t", parent=ss["Title"], fontName="Helvetica-Bold",
                                 fontSize=22, textColor=INK, spaceAfter=4, leading=26)
    st["sub"] = ParagraphStyle("s", parent=ss["Normal"], fontName="Helvetica",
                               fontSize=10, textColor=MUTED, spaceAfter=2)
    st["h2"] = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                              fontSize=13, textColor=INK, spaceBefore=16, spaceAfter=8)
    st["body"] = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica",
                                fontSize=9.5, textColor=INK, leading=14, spaceAfter=6,
                                alignment=TA_LEFT)
    st["small"] = ParagraphStyle("sm", parent=ss["Normal"], fontName="Helvetica",
                                 fontSize=8, textColor=MUTED, leading=11)
    st["cell"] = ParagraphStyle("c", parent=ss["Normal"], fontName="Helvetica",
                                fontSize=8.5, textColor=INK, leading=11)
    st["cellb"] = ParagraphStyle("cb", parent=ss["Normal"], fontName="Helvetica-Bold",
                                 fontSize=8.5, textColor=INK, leading=11)
    return st


def _section(title, S):
    return [Spacer(1, 4), HRFlowable(width="100%", thickness=0.6, color=LINE),
            Paragraph(title, S["h2"])]


def _narrative(md, S):
    """Rend la synthese markdown de l'IA en flowables simples."""
    out = []
    for raw in (md or "").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.startswith("#"):
            txt = line.lstrip("#").strip()
            out.append(Paragraph(txt, S["h2"]))
        elif line.startswith(("- ", "* ")):
            out.append(Paragraph("&bull; " + line[2:].strip(), S["body"]))
        else:
            out.append(Paragraph(line, S["body"]))
    return out


def build_pdf(data, path):
    S = _styles()
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=20 * mm, bottomMargin=18 * mm,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            title="Rapport CySyMo - " + data.get("client", ""))
    story = []

    # --- En-tete ---
    story.append(Paragraph("Rapport d'analyse de risque cyber", S["title"]))
    story.append(Paragraph("CySyMo &nbsp;&bull;&nbsp; L'IA propose &rarr; L'humain valide &rarr; Le moteur calcule", S["sub"]))
    story.append(Spacer(1, 8))
    meta = [
        ["Client", data.get("client", "-")],
        ["Date", data.get("date", "-")],
        ["Consultant", data.get("consultant", "-")],
        ["Reference", data.get("reference", "-")],
    ]
    mt = Table(meta, colWidths=[35 * mm, 130 * mm])
    mt.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("FONT", (1, 0), (1, -1), "Helvetica", 9),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LSOFT),
    ]))
    story.append(mt)

    # --- Synthese executive ---
    if data.get("summary"):
        story += _section("Synthese executive", S)
        story += _narrative(data["summary"], S)

    # --- Analyse technique (CVE) ---
    findings = data.get("findings", [])
    story += _section("Analyse technique \u2014 vulnerabilites (CVE)", S)
    if findings:
        rows = [[Paragraph("Actif", S["cellb"]), Paragraph("CVE", S["cellb"]),
                 Paragraph("CVSS", S["cellb"]), Paragraph("EPSS", S["cellb"]),
                 Paragraph("KEV", S["cellb"]), Paragraph("Risque", S["cellb"])]]
        for f in findings:
            epss = f.get("epss")
            epss_s = ("%.0f%%" % (epss * 100)) if isinstance(epss, (int, float)) else "-"
            risk = f.get("risk")
            risk_s = ("%.2f" % risk) if isinstance(risk, (int, float)) else "-"
            rows.append([
                Paragraph(str(f.get("asset", "-")), S["cell"]),
                Paragraph(str(f.get("cve_id", "-")), S["cell"]),
                Paragraph(str(f.get("cvss", "-")), S["cell"]),
                Paragraph(epss_s, S["cell"]),
                Paragraph("OUI" if f.get("in_kev") else "-", S["cell"]),
                Paragraph(risk_s, S["cellb"]),
            ])
        t = Table(rows, colWidths=[38 * mm, 34 * mm, 16 * mm, 16 * mm, 14 * mm, 18 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LSOFT]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Aucune vulnerabilite technique validee.", S["small"]))

    # --- Risques organisationnels ---
    org = data.get("orgrisks", [])
    if org:
        story += _section("Risques organisationnels (non-techniques)", S)
        for r in org:
            sev = (r.get("severity") or "").upper()
            head = Paragraph("<b>[%s]</b> &nbsp; <font color='%s'><b>%s</b></font>" % (
                r.get("category", "-"), _sev_color(sev).hexval(), sev), S["cell"])
            desc = Paragraph(r.get("description", ""), S["body"])
            src = Paragraph("Source : " + str(r.get("source", "contexte")), S["small"])
            story.append(KeepTogether([head, desc, src, Spacer(1, 4)]))

    # --- Modele de menaces STRIDE ---
    threats = [t for t in data.get("threats", []) if t.get("verified") is not False]
    if threats:
        story += _section("Modele de menaces (STRIDE / OWASP)", S)
        by_asset = {}
        for t in threats:
            by_asset.setdefault(t.get("asset", "-"), []).append(t)
        for asset, ts in by_asset.items():
            story.append(Paragraph(asset, S["cellb"]))
            rows = [[Paragraph("STRIDE", S["cellb"]), Paragraph("Menace", S["cellb"]),
                     Paragraph("Gravite", S["cellb"])]]
            for t in ts:
                cat = t.get("category", "")
                rows.append([
                    Paragraph("<b>%s</b> %s" % (cat, STRIDE_LABELS.get(cat, "")), S["cell"]),
                    Paragraph(t.get("threat", ""), S["cell"]),
                    Paragraph("<font color='%s'><b>%s</b></font>" % (
                        _sev_color(t.get("severity")).hexval(), (t.get("severity") or "").upper()), S["cell"]),
                ])
            tb = Table(rows, colWidths=[36 * mm, 100 * mm, 18 * mm], repeatRows=1)
            tb.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), LSOFT),
                ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(tb)
            story.append(Spacer(1, 6))

    # --- Scenarios d'attaque ---
    scen = data.get("scenarios", [])
    if scen:
        story += _section("Scenarios d'attaque", S)
        for i, sc in enumerate(scen, 1):
            title = "%d. %s" % (i, sc.get("title", "Scenario"))
            block = [Paragraph(title, S["cellb"])]
            if sc.get("entry_point"):
                block.append(Paragraph("Point d'entree : " + sc["entry_point"], S["small"]))
            for j, step in enumerate(sc.get("steps", []), 1):
                txt = "%d. <b>%s</b>" % (j, step.get("asset", "-"))
                if step.get("cve"):
                    txt += " (" + step["cve"] + ")"
                txt += " &mdash; " + step.get("action", "")
                block.append(Paragraph(txt, S["body"]))
            if sc.get("rationale"):
                block.append(Paragraph("<i>" + sc["rationale"] + "</i>", S["small"]))
            block.append(Spacer(1, 6))
            story.append(KeepTogether(block))

    doc.build(story)
    return path
