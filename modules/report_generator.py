"""
Module: report_generator.py
Génération de rapports PDF ultra-professionnels style pentest cabinet
Design premium — by hawkz
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame,
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen.canvas import Canvas

W, H = A4

# ═══════════════════════════════════════════════════════════════════════════════
# PALETTE
# ═══════════════════════════════════════════════════════════════════════════════
C = {
    "bg":              HexColor("#0A0E17"),
    "surface":         HexColor("#111827"),
    "surface2":        HexColor("#1A2234"),
    "border":          HexColor("#1E2D45"),
    "accent":          HexColor("#00C2FF"),
    "accent2":         HexColor("#0066CC"),
    "green":           HexColor("#00D68F"),
    "orange":          HexColor("#FF8C00"),
    "red":             HexColor("#FF3B5C"),
    "text":            HexColor("#F0F4FF"),
    "text2":           HexColor("#7A8BA8"),
    "text3":           HexColor("#3A4A60"),
    "sev_critical":    HexColor("#FF3B5C"),
    "sev_high":        HexColor("#FF6B35"),
    "sev_medium":      HexColor("#FFB800"),
    "sev_low":         HexColor("#00D68F"),
    "sev_info":        HexColor("#00C2FF"),
    "sev_critical_bg": HexColor("#2A0A10"),
    "sev_high_bg":     HexColor("#2A1200"),
    "sev_medium_bg":   HexColor("#2A2000"),
    "sev_low_bg":      HexColor("#002A18"),
    "sev_info_bg":     HexColor("#002030"),
}

SEV_COLOR = {
    "CRITICAL": C["sev_critical"], "HIGH": C["sev_high"],
    "MEDIUM":   C["sev_medium"],   "LOW":  C["sev_low"],
    "INFO":     C["sev_info"],
}
SEV_BG = {
    "CRITICAL": C["sev_critical_bg"], "HIGH": C["sev_high_bg"],
    "MEDIUM":   C["sev_medium_bg"],   "LOW":  C["sev_low_bg"],
    "INFO":     C["sev_info_bg"],
}
SEV_LABEL = {
    "CRITICAL": "CRITIQUE", "HIGH": "ÉLEVÉ",
    "MEDIUM":   "MOYEN",    "LOW":  "FAIBLE",
    "INFO":     "INFO",
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def risk_color_for_score(score):
    if score >= 75: return C["sev_critical"]
    if score >= 50: return C["sev_high"]
    if score >= 25: return C["sev_medium"]
    if score >= 10: return C["sev_low"]
    return C["sev_info"]


def S(name, **kw):
    d = dict(fontName="Helvetica", fontSize=9, textColor=C["text2"], leading=13, spaceAfter=3)
    d.update(kw)
    return ParagraphStyle(name, **d)


STYLES = {
    "section":    S("section",    fontSize=17, fontName="Helvetica-Bold", textColor=C["accent"],
                    spaceBefore=18, spaceAfter=10, leading=22),
    "subsection": S("subsection", fontSize=12, fontName="Helvetica-Bold", textColor=C["text"],
                    spaceBefore=12, spaceAfter=7, leading=16),
    "body":       S("body",       fontSize=9,  textColor=C["text2"], leading=14,
                    spaceAfter=6, alignment=TA_JUSTIFY),
    "body_bold":  S("body_bold",  fontSize=9,  fontName="Helvetica-Bold", textColor=C["text"], leading=14),
    "code":       S("code",       fontSize=8,  fontName="Courier", textColor=C["green"],
                    leading=12, leftIndent=6, spaceAfter=4),
    "th":         S("th",         fontSize=8,  fontName="Helvetica-Bold", textColor=C["bg"],
                    alignment=TA_CENTER, leading=11),
    "td":         S("td",         fontSize=8,  textColor=C["text2"], leading=11),
    "td_c":       S("td_c",       fontSize=8,  textColor=C["text2"], alignment=TA_CENTER, leading=11),
    "td_bold":    S("td_bold",    fontSize=8,  fontName="Helvetica-Bold", textColor=C["text"], leading=11),
    "small":      S("small",      fontSize=7,  textColor=C["text3"], leading=10),
    "finding_t":  S("finding_t",  fontSize=10, fontName="Helvetica-Bold", textColor=C["text"],
                    leading=14, spaceAfter=3),
    "finding_d":  S("finding_d",  fontSize=8.5, textColor=C["text2"], leading=13,
                    spaceAfter=3, alignment=TA_JUSTIFY),
    "finding_r":  S("finding_r",  fontSize=8.5, textColor=C["green"], leading=13, spaceAfter=2),
    "toc_main":   S("toc_main",   fontSize=10, fontName="Helvetica-Bold", textColor=C["text"], leading=18),
    "toc_sub":    S("toc_sub",    fontSize=9,  textColor=C["text2"], leading=16, leftIndent=8),
    "label":      S("label",      fontSize=7,  fontName="Helvetica-Bold", textColor=C["text3"], leading=10),
    "value":      S("value",      fontSize=10, fontName="Helvetica-Bold", textColor=C["text"], leading=14),
    "disclaimer": S("disclaimer", fontSize=7.5, textColor=C["text3"], leading=11,
                    alignment=TA_JUSTIFY),
}


def tbl_style(hdr_color=None):
    hc = hdr_color or C["accent"]
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  hc),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C["surface"], C["surface2"]]),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("GRID",  (0, 0), (-1, -1), 0.3, C["border"]),
        ("BOX",   (0, 0), (-1, -1), 1,   C["border"]),
        ("VALIGN",(0, 0), (-1, -1), "MIDDLE"),
    ])


def section_header(title, subtitle=None):
    e = [Spacer(1, 4*mm), Paragraph(title, STYLES["section"])]
    accent_row = Table([["", ""]], colWidths=[22*mm, W - 52*mm])
    accent_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), C["accent"]),
        ("BACKGROUND",    (1, 0), (1, 0), C["border"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("ROWHEIGHT",     (0, 0), (-1, -1), 2),
    ]))
    e.append(accent_row)
    if subtitle:
        e += [Spacer(1, 2*mm), Paragraph(subtitle, STYLES["body"])]
    e.append(Spacer(1, 4*mm))
    return e


def kv_block(items, cols=2):
    col_w = (W - 30*mm) / cols
    rows, row = [], []
    for i, (key, val) in enumerate(items):
        cell = Table(
            [[Paragraph(key, STYLES["label"])],
             [Paragraph(str(val)[:60], STYLES["value"])]],
            colWidths=[col_w - 6*mm]
        )
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["surface2"]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
        ]))
        row.append(cell)
        if len(row) == cols or i == len(items) - 1:
            while len(row) < cols:
                row.append(Spacer(1, 1))
            rows.append(row)
            row = []
    if not rows:
        return []
    t = Table(rows, colWidths=[col_w] * cols, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
    ]))
    return [t, Spacer(1, 4*mm)]


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM FLOWABLES
# ═══════════════════════════════════════════════════════════════════════════════

class SeverityPill(Flowable):
    def __init__(self, severity, w=68, h=20):
        super().__init__()
        self.severity = severity
        self.width = w
        self.height = h

    def draw(self):
        c = self.canv
        col = SEV_COLOR.get(self.severity, C["text2"])
        bg  = SEV_BG.get(self.severity, C["surface"])
        lbl = SEV_LABEL.get(self.severity, self.severity)
        c.setFillColor(bg)
        c.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=0)
        c.setStrokeColor(col)
        c.setLineWidth(0.8)
        c.roundRect(0, 0, self.width, self.height, 4, fill=0, stroke=1)
        c.setFillColor(col)
        c.circle(10, self.height / 2, 3, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(18, (self.height - 7.5) / 2 + 1, lbl)


class CoverPage(Flowable):
    def __init__(self, data):
        super().__init__()
        self.data = data
        self.width = W
        self.height = H

    def draw(self):
        c = self.canv
        d = self.data
        target  = d.get("target", "")
        company = d.get("company", "Confidentiel")
        auditor = d.get("auditor", "hawkz")
        risk    = d.get("risk", {})
        score   = risk.get("score", 0)
        level   = risk.get("level", "N/A")
        sc      = d.get("_sev_counts", {})
        dur     = d.get("scan_duration_seconds", 0)
        mods    = d.get("modules", {})
        active_mods = len([m for m in mods.values() if not m.get("skipped") and not m.get("error")])

        try:
            dt = datetime.fromisoformat(d.get("scan_date", ""))
            date_str = dt.strftime("%d %B %Y")
            time_str = dt.strftime("%H:%M UTC")
        except Exception:
            date_str = datetime.now().strftime("%d %B %Y")
            time_str = datetime.now().strftime("%H:%M UTC")

        rcol = risk_color_for_score(score)

        # ── Fond ──────────────────────────────────────────────────────────────
        c.setFillColor(C["bg"])
        c.rect(0, 0, W, H, fill=1, stroke=0)

        # ── Bande latérale gauche ─────────────────────────────────────────────
        c.setFillColor(C["surface"])
        c.rect(0, 0, 8*mm, H, fill=1, stroke=0)
        c.setFillColor(C["accent"])
        c.rect(0, 0, 2.5*mm, H, fill=1, stroke=0)

        # ── Header band ───────────────────────────────────────────────────────
        c.setFillColor(C["surface"])
        c.rect(8*mm, H - 50*mm, W - 8*mm, 50*mm, fill=1, stroke=0)
        c.setFillColor(C["accent"])
        c.rect(8*mm, H - 50*mm, W - 8*mm, 1.2, fill=1, stroke=0)

        # Logo
        c.setFillColor(C["accent"])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(18*mm, H - 16*mm, "VULNSCAN")
        c.setFillColor(C["text2"])
        c.setFont("Helvetica", 12)
        logo_x = 18*mm + c.stringWidth("VULNSCAN", "Helvetica-Bold", 12) + 2
        c.drawString(logo_x, H - 16*mm, "PRO")
        c.setFillColor(C["text3"])
        c.setFont("Helvetica", 7.5)
        c.drawString(18*mm, H - 22*mm, "by hawkz")

        # Séparateur vertical header
        c.setFillColor(C["border"])
        c.rect(W - 58*mm, H - 44*mm, 0.5, 32*mm, fill=1, stroke=0)

        # Date / heure
        c.setFillColor(C["text2"])
        c.setFont("Helvetica", 8)
        c.drawRightString(W - 12*mm, H - 18*mm, date_str)
        c.drawRightString(W - 12*mm, H - 26*mm, time_str)
        c.setFillColor(C["text3"])
        c.setFont("Helvetica-Bold", 7.5)
        c.drawRightString(W - 12*mm, H - 34*mm, "CONFIDENTIEL")

        # ── Titre ─────────────────────────────────────────────────────────────
        c.setFillColor(C["text"])
        c.setFont("Helvetica-Bold", 36)
        c.drawString(18*mm, H - 82*mm, "RAPPORT")
        c.drawString(18*mm, H - 98*mm, "D'AUDIT DE")
        c.setFillColor(C["accent"])
        c.drawString(18*mm, H - 114*mm, "SÉCURITÉ")

        # Déco titre
        c.setFillColor(C["accent"])
        c.rect(18*mm, H - 119*mm, 26*mm, 2.5, fill=1, stroke=0)
        c.setFillColor(C["border"])
        c.rect(46*mm, H - 119*mm - 0.5, W - 58*mm, 0.5, fill=1, stroke=0)

        # ── Cible ─────────────────────────────────────────────────────────────
        c.setFillColor(C["surface2"])
        c.roundRect(18*mm, H - 139*mm, W - 28*mm, 16*mm, 4, fill=1, stroke=0)
        c.setStrokeColor(C["border"])
        c.setLineWidth(0.5)
        c.roundRect(18*mm, H - 139*mm, W - 28*mm, 16*mm, 4, fill=0, stroke=1)
        c.setFillColor(C["text3"])
        c.setFont("Helvetica-Bold", 6.5)
        c.drawString(22*mm, H - 126*mm, "CIBLE AUDITÉE")
        c.setFillColor(C["accent"])
        c.setFont("Helvetica-Bold", 11)
        c.drawString(22*mm, H - 134*mm, target)

        # ── Bloc score ────────────────────────────────────────────────────────
        bx, by, bw, bh = 18*mm, H - 198*mm, 52*mm, 52*mm
        c.setFillColor(C["surface"])
        c.roundRect(bx, by, bw, bh, 5, fill=1, stroke=0)
        c.setStrokeColor(rcol)
        c.setLineWidth(1.2)
        c.roundRect(bx, by, bw, bh, 5, fill=0, stroke=1)
        # Label
        c.setFillColor(C["text3"])
        c.setFont("Helvetica-Bold", 6.5)
        lbl_txt = "SCORE DE RISQUE"
        c.drawString(bx + (bw - c.stringWidth(lbl_txt, "Helvetica-Bold", 6.5)) / 2,
                     by + bh - 9, lbl_txt)
        # Chiffre
        c.setFillColor(rcol)
        c.setFont("Helvetica-Bold", 36)
        sw = c.stringWidth(str(score), "Helvetica-Bold", 36)
        c.drawString(bx + (bw - sw) / 2, by + 22, str(score))
        # /100
        c.setFillColor(C["text3"])
        c.setFont("Helvetica", 8)
        sw2 = c.stringWidth("/ 100", "Helvetica", 8)
        c.drawString(bx + (bw - sw2) / 2, by + 13, "/ 100")
        # Level
        c.setFillColor(rcol)
        c.setFont("Helvetica-Bold", 9)
        sw3 = c.stringWidth(level, "Helvetica-Bold", 9)
        c.drawString(bx + (bw - sw3) / 2, by + 4, level)

        # ── Blocs sévérité ────────────────────────────────────────────────────
        sev_items = [
            ("CRITIQUE", sc.get("CRITICAL", 0), C["sev_critical"]),
            ("ÉLEVÉ",    sc.get("HIGH", 0),     C["sev_high"]),
            ("MOYEN",    sc.get("MEDIUM", 0),   C["sev_medium"]),
            ("FAIBLE",   sc.get("LOW", 0),      C["sev_low"]),
            ("INFO",     sc.get("INFO", 0),      C["sev_info"]),
        ]
        avail_w = W - 28*mm - 58*mm
        box_w   = avail_w / 5
        sx = 18*mm + 58*mm
        for lbl, cnt, col in sev_items:
            c.setFillColor(C["surface"])
            c.roundRect(sx, by, box_w - 2, bh, 4, fill=1, stroke=0)
            c.setStrokeColor(col)
            c.setLineWidth(0.5)
            c.roundRect(sx, by, box_w - 2, bh, 4, fill=0, stroke=1)
            # Barre top couleur
            c.setFillColor(col)
            c.rect(sx, by + bh - 3, box_w - 2, 3, fill=1, stroke=0)
            # Nombre
            c.setFillColor(col if cnt > 0 else C["text3"])
            c.setFont("Helvetica-Bold", 24)
            sw = c.stringWidth(str(cnt), "Helvetica-Bold", 24)
            c.drawString(sx + (box_w - 2 - sw) / 2, by + 20, str(cnt))
            # Label
            c.setFillColor(C["text3"])
            c.setFont("Helvetica-Bold", 6)
            sw2 = c.stringWidth(lbl, "Helvetica-Bold", 6)
            c.drawString(sx + (box_w - 2 - sw2) / 2, by + 10, lbl)
            sx += box_w

        # ── Infos mission ─────────────────────────────────────────────────────
        info_items = [
            ("ENTREPRISE",  company),
            ("AUDITEUR",    auditor),
            ("DURÉE",       f"{dur:.0f}s"),
            ("MODULES",     f"{active_mods} actifs"),
        ]
        info_y  = H - 218*mm
        info_cw = (W - 28*mm) / 4
        ix = 18*mm
        for lbl, val in info_items:
            c.setFillColor(C["surface2"])
            c.roundRect(ix, info_y, info_cw - 3, 15*mm, 3, fill=1, stroke=0)
            c.setFillColor(C["text3"])
            c.setFont("Helvetica-Bold", 6.5)
            c.drawString(ix + 4*mm, info_y + 12*mm, lbl)
            c.setFillColor(C["text"])
            c.setFont("Helvetica-Bold", 9)
            c.drawString(ix + 4*mm, info_y + 5*mm, str(val)[:26])
            ix += info_cw

        # ── Footer confidentiel ────────────────────────────────────────────────
        c.setFillColor(C["surface"])
        c.rect(8*mm, 0, W - 8*mm, 20*mm, fill=1, stroke=0)
        c.setFillColor(C["accent"])
        c.rect(8*mm, 20*mm, W - 8*mm, 0.5, fill=1, stroke=0)
        c.setFillColor(C["text3"])
        c.setFont("Helvetica", 7)
        c.drawCentredString(W / 2 + 4*mm, 13*mm,
            "DOCUMENT STRICTEMENT CONFIDENTIEL — Usage légal uniquement sur systèmes autorisés")
        c.setFillColor(C["accent"])
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(18*mm, 7*mm, "VulnScan Pro v1.0")
        c.setFillColor(C["text3"])
        c.setFont("Helvetica", 7.5)
        c.drawRightString(W - 12*mm, 7*mm, "by hawkz")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CANVAS — header/footer automatiques
# ═══════════════════════════════════════════════════════════════════════════════

class ReportCanvas(Canvas):
    def __init__(self, filename, doc_data=None, **kwargs):
        super().__init__(filename, **kwargs)
        self.doc_data = doc_data or {}
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_chrome(self._pageNumber, num_pages)
            super().showPage()
        super().save()

    def _draw_chrome(self, page_num, total):
        if page_num == 1:
            return  # Cover gérée par CoverPage flowable

        target  = self.doc_data.get("target", "")
        company = self.doc_data.get("company", "")
        try:
            dt = datetime.fromisoformat(self.doc_data.get("scan_date", ""))
            date_str = dt.strftime("%d/%m/%Y")
        except Exception:
            date_str = ""

        # Header
        self.setFillColor(C["surface"])
        self.rect(0, H - 15*mm, W, 15*mm, fill=1, stroke=0)
        self.setFillColor(C["accent"])
        self.rect(0, H - 15*mm, 3*mm, 15*mm, fill=1, stroke=0)
        self.setFillColor(C["border"])
        self.rect(0, H - 15*mm, W, 0.5, fill=1, stroke=0)

        self.setFillColor(C["accent"])
        self.setFont("Helvetica-Bold", 8.5)
        self.drawString(8*mm, H - 8*mm, "VULNSCAN PRO")
        self.setFillColor(C["text3"])
        self.setFont("Helvetica", 7)
        self.drawString(8*mm, H - 12.5*mm, "by hawkz")

        self.setFillColor(C["border"])
        self.rect(46*mm, H - 13*mm, 0.5, 9*mm, fill=1, stroke=0)

        self.setFillColor(C["text2"])
        self.setFont("Helvetica", 7.5)
        self.drawString(50*mm, H - 8*mm, f"Audit de sécurité — {target}")
        self.setFillColor(C["text3"])
        self.setFont("Helvetica", 7)
        self.drawString(50*mm, H - 12.5*mm, "CONFIDENTIEL")

        self.setFillColor(C["text2"])
        self.setFont("Helvetica", 7.5)
        self.drawRightString(W - 8*mm, H - 8*mm, company)
        self.setFillColor(C["text3"])
        self.setFont("Helvetica", 7)
        self.drawRightString(W - 8*mm, H - 12.5*mm, date_str)

        # Footer
        self.setFillColor(C["surface"])
        self.rect(0, 0, W, 10*mm, fill=1, stroke=0)
        self.setFillColor(C["border"])
        self.rect(0, 10*mm, W, 0.5, fill=1, stroke=0)
        self.setFillColor(C["accent"])
        self.rect(0, 0, 3*mm, 10*mm, fill=1, stroke=0)

        self.setFillColor(C["text3"])
        self.setFont("Helvetica", 7)
        self.drawString(8*mm, 3.5*mm, "DOCUMENT CONFIDENTIEL — Usage interne uniquement")

        self.setFillColor(C["accent"])
        self.setFont("Helvetica-Bold", 7.5)
        self.drawCentredString(W / 2, 3.5*mm, f"Page {page_num} / {total}")

        self.setFillColor(C["text3"])
        self.setFont("Helvetica", 7)
        self.drawRightString(W - 8*mm, 3.5*mm, "VulnScan Pro v1.0")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    def __init__(self, results: dict, output_dir: str = "./output"):
        self.r = results
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.all_findings = self._collect_findings()
        self.sev_counts   = self._count_sev()
        self.r["_sev_counts"] = self.sev_counts

    def _collect_findings(self):
        out = []
        for mod, data in self.r.get("modules", {}).items():
            if isinstance(data, dict):
                for f in data.get("findings", []):
                    f = dict(f)
                    f.setdefault("_module", mod)
                    out.append(f)
        out.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 9))
        return out

    def _count_sev(self):
        c = {k: 0 for k in SEV_ORDER}
        for f in self.all_findings:
            s = f.get("severity", "INFO")
            if s in c: c[s] += 1
        return c

    def generate(self) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        tgt = self.r.get("target", "target").replace(".", "_").replace("/", "_")[:30]
        filepath = os.path.join(self.output_dir, f"vulnscan_{tgt}_{ts}.pdf")

        # Cover page : frame pleine page sans marges
        frame_cover = Frame(
            0, 0, W, H,
            leftPadding=0, rightPadding=0,
            topPadding=0, bottomPadding=0,
            id="cover"
        )
        # Pages intérieures : marges header/footer
        frame_inner = Frame(
            8*mm, 12*mm,
            W - 18*mm, H - 29*mm,
            leftPadding=0, rightPadding=0,
            topPadding=0, bottomPadding=0,
            id="main"
        )

        def make_canvas(filename, **kwargs):
            return ReportCanvas(filename, doc_data=self.r, **kwargs)

        doc = BaseDocTemplate(
            filepath,
            pagesize=A4,
            pageTemplates=[
                PageTemplate(id="cover", frames=[frame_cover]),
                PageTemplate(id="main",  frames=[frame_inner]),
            ],
            initialtemplate="cover",
            title=f"Rapport VulnScan — {self.r.get('target', '')}",
            author=self.r.get("auditor", "hawkz"),
            subject="Rapport d'audit de sécurité — VulnScan Pro by hawkz",
            creator="VulnScan Pro v1.0 by hawkz",
        )

        from reportlab.platypus import NextPageTemplate
        story = []
        story += self._cover()
        story.append(NextPageTemplate("main"))
        story.append(PageBreak())
        story += self._toc()
        story.append(PageBreak())
        story += self._executive_summary()
        story.append(PageBreak())
        story += self._findings_detail()
        story.append(PageBreak())
        story += self._network_section()
        story.append(PageBreak())
        story += self._http_section()
        story.append(PageBreak())
        story += self._ssl_section()
        story.append(PageBreak())
        story += self._dns_section()
        story.append(PageBreak())
        story += self._cve_section()
        story.append(PageBreak())
        story += self._recommendations()
        story.append(PageBreak())
        story += self._methodology()

        doc.build(story, canvasmaker=make_canvas)
        return filepath

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGES
    # ═══════════════════════════════════════════════════════════════════════════

    def _cover(self):
        return [CoverPage(self.r)]

    # ── TOC ──────────────────────────────────────────────────────────────────

    def _toc(self):
        e = []
        e += section_header("Table des matières")
        sections = [
            ("01", "Résumé Exécutif"),
            ("02", "Détail des Vulnérabilités"),
            ("03", "Analyse Réseau & Ports"),
            ("04", "Analyse HTTP / HTTPS"),
            ("05", "Analyse SSL / TLS"),
            ("06", "Analyse DNS & WHOIS"),
            ("07", "CVEs Identifiées"),
            ("08", "Recommandations Prioritaires"),
            ("09", "Méthodologie"),
        ]
        for num, title in sections:
            row = Table(
                [[
                    Paragraph(f'<font color="{C["accent"].hexval()}"><b>{num}</b></font>',
                              STYLES["toc_main"]),
                    Paragraph(title, STYLES["toc_main"]),
                    Paragraph("· · · · · ·", STYLES["small"]),
                ]],
                colWidths=[14*mm, W - 50*mm, 16*mm]
            )
            row.setStyle(TableStyle([
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.4, C["border"]),
                ("ALIGN",         (2, 0), (2, 0), "RIGHT"),
            ]))
            e.append(row)
        return e

    # ── Résumé exécutif ───────────────────────────────────────────────────────

    def _executive_summary(self):
        e = []
        e += section_header("01 — Résumé Exécutif",
                             "Synthèse des résultats de l'audit de sécurité.")

        risk    = self.r.get("risk", {})
        score   = risk.get("score", 0)
        level   = risk.get("level", "N/A")
        target  = self.r.get("target", "")
        company = self.r.get("company", "")
        auditor = self.r.get("auditor", "")
        total   = len(self.all_findings)
        dur     = self.r.get("scan_duration_seconds", 0)

        try:
            dt = datetime.fromisoformat(self.r.get("scan_date", ""))
            date_fmt = dt.strftime("%d %B %Y à %H:%M")
        except Exception:
            date_fmt = "N/A"

        e.append(Paragraph("Contexte de l'audit", STYLES["subsection"]))
        e.append(Paragraph(
            f"Un audit de sécurité automatisé a été conduit le <b>{date_fmt}</b> "
            f"sur la cible <b>{target}</b> pour le compte de <b>{company}</b> "
            f"par l'auditeur <b>{auditor}</b>. "
            f"La durée totale du scan a été de <b>{dur:.0f} secondes</b>. "
            f"Tous les tests ont été réalisés depuis l'extérieur du périmètre (approche black-box).",
            STYLES["body"]
        ))
        e.append(Spacer(1, 5*mm))

        rcol = risk_color_for_score(score)

        # Score block
        score_tbl = Table(
            [
                [Paragraph("SCORE GLOBAL", STYLES["label"])],
                [Paragraph(
                    f'<font size="34" color="{rcol.hexval()}"><b>{score}</b></font>'
                    f'<font size="11" color="{C["text3"].hexval()}"> /100</font>',
                    S("sc", alignment=TA_CENTER, leading=40)
                )],
                [Paragraph(
                    f'<font color="{rcol.hexval()}"><b>{level}</b></font>',
                    S("lv", alignment=TA_CENTER, fontSize=11, fontName="Helvetica-Bold", leading=16)
                )],
            ],
            colWidths=[45*mm], rowHeights=[10, 44, 18]
        )
        score_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["surface"]),
            ("BOX",           (0, 0), (-1, -1), 1.5, rcol),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ]))

        # Barres sévérité
        sev_items = [
            ("CRITICAL", "CRITIQUE", C["sev_critical"]),
            ("HIGH",     "ÉLEVÉ",    C["sev_high"]),
            ("MEDIUM",   "MOYEN",    C["sev_medium"]),
            ("LOW",      "FAIBLE",   C["sev_low"]),
            ("INFO",     "INFO",     C["sev_info"]),
        ]
        bar_rows = []
        for k, lbl, col in sev_items:
            cnt = self.sev_counts.get(k, 0)
            pct = min(cnt / max(total, 1), 1.0)
            bw_max = 88*mm
            bw = max(pct * bw_max, 1)
            bar = Table([["", ""]], colWidths=[bw, bw_max - bw], rowHeights=[6])
            bar.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, 0), col),
                ("BACKGROUND",    (1, 0), (1, 0), C["surface2"]),
                ("TOPPADDING",    (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ]))
            bar_rows.append([
                Paragraph(lbl, S("bl", fontSize=7.5, fontName="Helvetica-Bold",
                                 textColor=col, leading=10)),
                bar,
                Paragraph(
                    f'<font color="{col.hexval()}"><b>{cnt}</b></font>',
                    S("bc", fontSize=11, fontName="Helvetica-Bold",
                      alignment=TA_RIGHT, leading=13)
                ),
            ])

        bar_tbl = Table(bar_rows, colWidths=[22*mm, 88*mm, 12*mm])
        bar_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["surface"]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C["border"]),
            ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))

        combo = Table([[score_tbl, bar_tbl]], colWidths=[52*mm, W - 82*mm])
        combo.setStyle(TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        e.append(combo)
        e.append(Spacer(1, 6*mm))

        # Tableau modules
        e.append(Paragraph("Résultats par module", STYLES["subsection"]))
        hdr = [Paragraph(t, STYLES["th"]) for t in
               ["Module", "Statut", "Critique", "Élevé", "Moyen", "Faible", "Total"]]
        rows = [hdr]
        mod_display = {
            "network": "Réseau / Nmap", "ports": "Scan de ports",
            "http": "HTTP / HTTPS",     "ssl":   "SSL / TLS",
            "dns":  "DNS",              "cve":   "CVE Lookup",
            "vulns":"Scripts NSE",      "whois": "WHOIS",
        }
        for key, label in mod_display.items():
            data = self.r.get("modules", {}).get(key, {})
            if data.get("skipped"):
                rows.append([Paragraph(label, STYLES["td"])] +
                            [Paragraph("Ignoré", S("ig", fontSize=8, textColor=C["text3"],
                                                   alignment=TA_CENTER))] +
                            [Paragraph("—", STYLES["td_c"]) for _ in range(5)])
                continue
            st_p = (Paragraph("✗ Erreur", S("er", fontSize=8, textColor=C["sev_high"],
                                            alignment=TA_CENTER))
                    if data.get("error") else
                    Paragraph("✓ OK", S("ok", fontSize=8, textColor=C["green"],
                                        alignment=TA_CENTER)))
            ff = data.get("findings", [])
            cc = sum(1 for f in ff if f.get("severity") == "CRITICAL")
            hh = sum(1 for f in ff if f.get("severity") == "HIGH")
            med_count = sum(1 for f in ff if f.get("severity") == "MEDIUM")
            ll = sum(1 for f in ff if f.get("severity") == "LOW")
            tt = len(ff)

            def cp(n, col):
                hex_c = col.hexval()
                hex_m = C["text3"].hexval()
                txt = (f'<font color="{hex_c}"><b>{n}</b></font>'
                       if n else f'<font color="{hex_m}">{n}</font>')
                return Paragraph(txt, STYLES["td_c"])

            rows.append([
                Paragraph(label, STYLES["td_bold"]), st_p,
                cp(cc, C["sev_critical"]), cp(hh, C["sev_high"]),
                cp(med_count, C["sev_medium"]),   cp(ll, C["sev_low"]),
                Paragraph(f"<b>{tt}</b>", STYLES["td_c"]),
            ])

        t = Table(rows, colWidths=[48*mm, 22*mm, 18*mm, 18*mm, 18*mm, 18*mm, 18*mm])
        t.setStyle(tbl_style())
        e.append(t)
        return e

    # ── Findings ─────────────────────────────────────────────────────────────

    def _findings_detail(self):
        e = []
        e += section_header("02 — Détail des Vulnérabilités",
                             f"{len(self.all_findings)} problème(s) identifié(s) et classifié(s).")

        if not self.all_findings:
            e.append(Paragraph("Aucune vulnérabilité détectée.", STYLES["body"]))
            return e

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            group = [f for f in self.all_findings if f.get("severity") == sev]
            if not group:
                continue
            col = SEV_COLOR[sev]
            bg  = SEV_BG[sev]
            lbl = SEV_LABEL[sev]

            gh = Table(
                [[
                    SeverityPill(sev, w=74, h=22),
                    Paragraph(
                        f'<font color="{col.hexval()}"><b>{lbl}</b></font>'
                        f'<font color="{C["text3"].hexval()}"> — {len(group)} finding(s)</font>',
                        S("gh", fontSize=11, fontName="Helvetica-Bold", leading=16)
                    ),
                ]],
                colWidths=[84*mm, W - 114*mm]
            )
            gh.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("BOX",           (0, 0), (-1, -1), 1.2, col),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            e += [Spacer(1, 4*mm), gh, Spacer(1, 3*mm)]

            for i, f in enumerate(group):
                e.append(KeepTogether(self._finding_card(f, i + 1, col, bg)))
                e.append(Spacer(1, 2.5*mm))

        return e

    def _finding_card(self, f, num, col, bg):
        title  = f.get("title", "Vulnérabilité")
        desc   = f.get("description", "")
        reco   = f.get("recommendation", "")
        port   = f.get("port", "")
        cves   = f.get("cves", [])
        score  = f.get("score", "")
        module = f.get("_module", "").upper()

        meta = " · ".join(filter(None, [
            f"Port: {port}" if port else "",
            f"Module: {module}" if module else "",
        ]))

        hdr = Table(
            [[
                Paragraph(
                    f'<font color="{col.hexval()}">#{num:02d}</font>  {title}',
                    STYLES["finding_t"]
                ),
                Paragraph(meta, S("hr", fontSize=7.5, textColor=C["text3"],
                                  alignment=TA_RIGHT, leading=12)),
            ]],
            colWidths=[W - 80*mm, 42*mm]
        )
        hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.8, col),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))

        body_rows = []
        if desc:
            body_rows.append([
                Paragraph("Description", S("lk", fontSize=7.5, fontName="Helvetica-Bold",
                           textColor=C["text3"])),
                Paragraph(desc[:700], STYLES["finding_d"]),
            ])
        if reco:
            body_rows.append([
                Paragraph("Recommandation", S("lk2", fontSize=7.5, fontName="Helvetica-Bold",
                           textColor=C["green"])),
                Paragraph(reco, STYLES["finding_r"]),
            ])
        if cves:
            body_rows.append([
                Paragraph("CVE(s)", S("lk3", fontSize=7.5, fontName="Helvetica-Bold",
                           textColor=C["orange"])),
                Paragraph(", ".join(cves[:6]),
                          S("cv", fontSize=8, fontName="Courier",
                            textColor=C["orange"], leading=12)),
            ])
        if score:
            body_rows.append([
                Paragraph("Score CVSS", S("lk4", fontSize=7.5, fontName="Helvetica-Bold",
                           textColor=C["text3"])),
                Paragraph(f'<font color="{col.hexval()}"><b>{score}</b></font> / 10',
                          S("sv", fontSize=9, fontName="Helvetica-Bold", leading=12)),
            ])

        elems = [hdr]
        if body_rows:
            bt = Table(body_rows, colWidths=[32*mm, W - 62*mm])
            bt.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), C["surface"]),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C["border"]),
                ("BOX",           (0, 0), (-1, -1), 0.5, bg),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(bt)
        return elems

    # ── Réseau ────────────────────────────────────────────────────────────────

    def _network_section(self):
        e = []
        e += section_header("03 — Analyse Réseau & Ports")

        ports_data   = self.r.get("modules", {}).get("ports", {})
        network_data = self.r.get("modules", {}).get("network", {})
        open_ports   = network_data.get("open_ports", []) or ports_data.get("open_ports", [])
        os_info      = network_data.get("os_info", {})

        if os_info:
            e.append(Paragraph("Système d'exploitation", STYLES["subsection"]))
            e += kv_block([
                ("OS DÉTECTÉ", os_info.get("name", "Inconnu")),
                ("PRÉCISION",  f"{os_info.get('accuracy', '?')}%"),
            ], cols=2)

        e.append(Paragraph(f"Ports ouverts — {len(open_ports)} détecté(s)", STYLES["subsection"]))

        if not open_ports:
            e.append(Paragraph("Aucun port ouvert détecté.", STYLES["body"]))
            return e

        RISKY = {21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 4444, 5432, 5900, 6379, 9200, 27017, 2375}
        hdr = [Paragraph(t, STYLES["th"]) for t in
               ["Port", "Proto", "Service", "Version / Banner", "Risque"]]
        rows = [hdr]
        for p in open_ports[:60]:
            pn    = p.get("port", 0)
            risky = pn in RISKY
            rc    = C["sev_high"] if risky else C["sev_low"]
            rt    = "⚠ Élevé" if risky else "✓ Normal"
            ver   = str(p.get("full_version", p.get("banner", "")))[:55]
            rows.append([
                Paragraph(f'<font color="{C["accent"].hexval()}"><b>{pn}</b></font>', STYLES["td_c"]),
                Paragraph(str(p.get("protocol", "tcp")), STYLES["td_c"]),
                Paragraph(str(p.get("service", "?")), STYLES["td_bold"]),
                Paragraph(ver or "—", STYLES["td"]),
                Paragraph(f'<font color="{rc.hexval()}"><b>{rt}</b></font>', STYLES["td_c"]),
            ])
        t = Table(rows, colWidths=[16*mm, 16*mm, 28*mm, 85*mm, 20*mm])
        t.setStyle(tbl_style())
        e.append(t)
        return e

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _http_section(self):
        e = []
        e += section_header("04 — Analyse HTTP / HTTPS")

        http = self.r.get("modules", {}).get("http", {})
        if http.get("error"):
            e.append(Paragraph(f"Module HTTP indisponible : {http['error']}", STYLES["body"]))
            return e

        techs = http.get("technologies", [])
        if techs:
            e.append(Paragraph("Technologies détectées", STYLES["subsection"]))
            hdr = [Paragraph(t, STYLES["th"]) for t in ["Technologie", "Source", "Valeur"]]
            rows = [hdr]
            for t in techs:
                rows.append([
                    Paragraph(t.get("name", ""), STYLES["td_bold"]),
                    Paragraph(t.get("source", ""), STYLES["td"]),
                    Paragraph(str(t.get("value", ""))[:80], STYLES["td"]),
                ])
            tbl = Table(rows, colWidths=[50*mm, 50*mm, 65*mm])
            tbl.setStyle(tbl_style(C["accent2"]))
            e.append(tbl)
            e.append(Spacer(1, 5*mm))

        headers = http.get("headers_analysis", [])
        if headers:
            e.append(Paragraph("En-têtes de sécurité HTTP", STYLES["subsection"]))
            hdr = [Paragraph(t, STYLES["th"]) for t in ["En-tête", "Statut", "Valeur"]]
            rows = [hdr]
            for h in headers:
                present = h.get("status") == "présent"
                sc  = C["sev_low"] if present else C["sev_high"]
                st  = "✓ Présent" if present else "✗ Absent"
                rows.append([
                    Paragraph(h.get("header", ""), STYLES["td_bold"]),
                    Paragraph(f'<font color="{sc.hexval()}"><b>{st}</b></font>', STYLES["td_c"]),
                    Paragraph(str(h.get("value", "N/A"))[:75], STYLES["td"]),
                ])
            tbl = Table(rows, colWidths=[60*mm, 28*mm, 77*mm])
            tbl.setStyle(tbl_style(C["accent2"]))
            e.append(tbl)

        srv = http.get("server_info", {})
        if srv:
            e.append(Spacer(1, 4*mm))
            e.append(Paragraph("Informations serveur", STYLES["subsection"]))
            items = []
            if srv.get("server"):       items.append(("SERVER",       srv["server"]))
            if srv.get("x_powered_by"): items.append(("X-POWERED-BY", srv["x_powered_by"]))
            if items:
                e += kv_block(items, cols=2)
        return e

    # ── SSL ───────────────────────────────────────────────────────────────────

    def _ssl_section(self):
        e = []
        e += section_header("05 — Analyse SSL / TLS")

        ssl_data  = self.r.get("modules", {}).get("ssl", {})
        cert_info = ssl_data.get("cert_info", {})
        tls_info  = ssl_data.get("tls_info", {})

        if cert_info:
            e.append(Paragraph("Certificat SSL", STYLES["subsection"]))
            e += kv_block([
                ("COMMON NAME (CN)", cert_info.get("common_name", "N/A")),
                ("ÉMETTEUR",         cert_info.get("issuer_name", "N/A")),
                ("VALIDE DEPUIS",    cert_info.get("valid_from", "N/A")),
                ("EXPIRATION",       cert_info.get("expiry_date", "N/A")),
                ("JOURS RESTANTS",   str(cert_info.get("days_until_expiry", "N/A"))),
                ("SANs",             ", ".join(cert_info.get("san", [])[:4])),
            ], cols=3)

        if tls_info:
            e.append(Paragraph("Configuration TLS", STYLES["subsection"]))
            proto = tls_info.get("protocol", "N/A")
            pc    = C["sev_low"] if proto in ["TLSv1.2", "TLSv1.3"] else C["sev_high"]
            e += kv_block([
                ("PROTOCOLE",    proto),
                ("CIPHER SUITE", tls_info.get("cipher_suite", "N/A")),
                ("FORCE (BITS)", str(tls_info.get("cipher_bits", 0))),
            ], cols=3)
        return e

    # ── DNS ───────────────────────────────────────────────────────────────────

    def _dns_section(self):
        e = []
        e += section_header("06 — Analyse DNS & WHOIS")

        dns_data   = self.r.get("modules", {}).get("dns", {})
        whois_data = self.r.get("modules", {}).get("whois", {}).get("whois_info", {})
        records    = dns_data.get("records", {})
        subdomains = dns_data.get("subdomains_found", [])

        if whois_data:
            e.append(Paragraph("Informations WHOIS", STYLES["subsection"]))
            e += kv_block([
                ("DOMAINE",      whois_data.get("domain", "N/A")),
                ("IP RÉSOLUE",   whois_data.get("resolved_ip", "N/A")),
                ("REGISTRAR",    whois_data.get("registrar", "N/A")),
                ("ORGANISATION", whois_data.get("org", "N/A")),
                ("CRÉATION",     whois_data.get("creation_date", "N/A")),
                ("EXPIRATION",   whois_data.get("expiration_date", "N/A")),
            ], cols=3)

        if records:
            e.append(Paragraph("Enregistrements DNS", STYLES["subsection"]))
            for rtype, vals in records.items():
                if not vals: continue
                e.append(Paragraph(
                    f'<font color="{C["accent"].hexval()}"><b>{rtype}</b></font>',
                    S("rt", fontSize=9, fontName="Helvetica-Bold", leading=14, spaceAfter=2)
                ))
                for v in vals[:6]:
                    e.append(Paragraph(f"  {v}", STYLES["code"]))
            e.append(Spacer(1, 3*mm))

        if subdomains:
            e.append(Paragraph(f"Sous-domaines découverts ({len(subdomains)})", STYLES["subsection"]))
            hdr = [Paragraph(t, STYLES["th"]) for t in ["Sous-domaine", "IP(s)"]]
            rows = [hdr]
            for s in subdomains[:30]:
                rows.append([
                    Paragraph(s.get("subdomain", ""),
                              S("sd", fontSize=8, fontName="Courier",
                                textColor=C["accent"], leading=11)),
                    Paragraph(", ".join(s.get("ips", [])), STYLES["td"]),
                ])
            t = Table(rows, colWidths=[100*mm, 65*mm])
            t.setStyle(tbl_style(C["accent2"]))
            e.append(t)
        return e

    # ── CVE ───────────────────────────────────────────────────────────────────

    def _cve_section(self):
        e = []
        e += section_header("07 — CVEs Identifiées")

        cve_data = self.r.get("modules", {}).get("cve", {})
        if cve_data.get("skipped"):
            e.append(Paragraph("Lookup CVE désactivé pour ce scan.", STYLES["body"]))
            return e

        cves = cve_data.get("cves", [])
        e.append(Paragraph(
            f"<b>{len(cves)}</b> CVE(s) trouvée(s) pour "
            f"<b>{cve_data.get('services_analyzed', 0)}</b> service(s) analysé(s).",
            STYLES["body"]
        ))
        e.append(Spacer(1, 4*mm))

        if not cves:
            e.append(Paragraph("Aucune CVE connue pour les services détectés.", STYLES["body"]))
            return e

        hdr = [Paragraph(t, STYLES["th"]) for t in
               ["CVE ID", "Score", "Sévérité", "Description", "Source"]]
        rows = [hdr]
        for cv in sorted(cves, key=lambda x: x.get("score", 0), reverse=True)[:40]:
            sev = cv.get("severity", "MEDIUM")
            col = SEV_COLOR.get(sev, C["text2"])
            sc  = cv.get("score", 0)
            rows.append([
                Paragraph(cv.get("id", ""),
                          S("ci", fontSize=7.5, fontName="Courier",
                            textColor=C["orange"], leading=11)),
                Paragraph(f'<font color="{col.hexval()}"><b>{sc}</b></font>', STYLES["td_c"]),
                Paragraph(f'<font color="{col.hexval()}"><b>{SEV_LABEL.get(sev, sev)}</b></font>',
                          STYLES["td_c"]),
                Paragraph(cv.get("description", "")[:150], STYLES["td"]),
                Paragraph(cv.get("source", ""), STYLES["td"]),
            ])

        t = Table(rows, colWidths=[28*mm, 14*mm, 20*mm, 90*mm, 13*mm])
        t.setStyle(tbl_style(C["orange"]))
        e.append(t)
        return e

    # ── Recommandations ───────────────────────────────────────────────────────

    def _recommendations(self):
        e = []
        e += section_header("08 — Recommandations Prioritaires",
                             "Actions correctives classées par ordre de priorité immédiate.")

        critical_high = [f for f in self.all_findings
                         if f.get("severity") in ["CRITICAL", "HIGH"]]

        if not critical_high:
            e.append(Paragraph(
                "Aucune vulnérabilité critique ou élevée détectée. "
                "Maintenir la surveillance et planifier des audits réguliers.",
                STYLES["body"]
            ))
        else:
            e.append(Paragraph(
                f"Les <b>{len(critical_high)}</b> actions suivantes doivent être "
                f"traitées en <b>priorité immédiate</b> :",
                STYLES["body"]
            ))
            e.append(Spacer(1, 4*mm))

            seen, n = set(), 1
            for f in critical_high[:20]:
                reco = f.get("recommendation", "")
                if not reco or reco in seen: continue
                seen.add(reco)
                sev = f.get("severity", "HIGH")
                col = SEV_COLOR.get(sev, C["text2"])
                bg  = SEV_BG.get(sev, C["surface"])

                inner = Table(
                    [[Paragraph(f.get("title", ""), STYLES["finding_t"])],
                     [Paragraph(reco, STYLES["finding_r"])]],
                    colWidths=[W - 68*mm]
                )
                inner.setStyle(TableStyle([
                    ("TOPPADDING",    (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]))
                card = Table(
                    [[
                        Paragraph(f'<font color="{col.hexval()}"><b>{n:02d}</b></font>',
                                  S("rn", fontSize=18, fontName="Helvetica-Bold",
                                    alignment=TA_CENTER, leading=22)),
                        inner,
                    ]],
                    colWidths=[18*mm, W - 48*mm]
                )
                card.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (0, -1), bg),
                    ("BACKGROUND",    (1, 0), (1, -1), C["surface"]),
                    ("TOPPADDING",    (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                    ("BOX",           (0, 0), (-1, -1), 0.8, bg),
                    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ]))
                e.append(card)
                e.append(Spacer(1, 2.5*mm))
                n += 1

        e.append(Spacer(1, 6*mm))
        e.append(Paragraph("Bonnes pratiques générales", STYLES["subsection"]))
        for icon, text in [
            ("🔄", "Patch management mensuel — maintenir tous les composants à jour"),
            ("🔐", "MFA sur tous les accès distants (VPN, RDP, SSH, panneaux admin)"),
            ("📊", "SIEM pour la détection d'incidents en temps réel"),
            ("🔍", "Tests d'intrusion réguliers (minimum trimestriels)"),
            ("📋", "Inventaire des actifs et services exposés à jour en permanence"),
            ("🛡", "WAF devant toutes les applications web exposées"),
            ("📦", "Sauvegardes 3-2-1 chiffrées et testées régulièrement"),
            ("👥", "Formation sécurité des équipes (phishing, mots de passe forts)"),
        ]:
            e.append(Paragraph(f"{icon}  {text}",
                               S("bp", fontSize=9, textColor=C["text2"],
                                 leading=16, leftIndent=5, spaceAfter=1)))
        return e

    # ── Méthodologie ──────────────────────────────────────────────────────────

    def _methodology(self):
        e = []
        e += section_header("09 — Méthodologie")
        e.append(Paragraph(
            "L'audit a été conduit via <b>VulnScan Pro v1.0</b> (by hawkz) selon une approche "
            "black-box structurée en quatre phases. Tous les tests ont été réalisés depuis "
            "l'extérieur du périmètre sans accès privilégié préalable.",
            STYLES["body"]
        ))
        e.append(Spacer(1, 4*mm))

        phases = [
            ("01", "Reconnaissance", C["sev_info"], [
                "Collecte WHOIS — registrar, contacts, dates d'expiration",
                "Analyse DNS complète — A, AAAA, MX, NS, TXT, CNAME, SOA",
                "Vérification SPF / DKIM / DMARC",
                "Test de transfert de zone (AXFR) sur chaque serveur NS",
                "Brute-force de 60+ sous-domaines courants",
            ]),
            ("02", "Scan Réseau", C["sev_medium"], [
                "Scan TCP 1-10000 parallèle (200 threads) + banner grabbing",
                "Nmap -sV : détection précise des versions de services",
                "Nmap -O : fingerprinting du système d'exploitation",
                "Nmap -sC : exécution des scripts NSE par défaut",
            ]),
            ("03", "Analyse des Vulnérabilités", C["sev_high"], [
                "Scripts NSE : vuln, ssl-heartbleed, smb-vuln-ms17-010, http-shellshock...",
                "Analyse des 9 headers de sécurité HTTP (CSP, HSTS, X-Frame-Options...)",
                "Audit SSL/TLS — protocoles obsolètes, cipher suites faibles, certificat",
                "Lookup CVE via NVD API v2 + base locale intégrée",
                "Détection de configurations dangereuses et données exposées dans le HTML",
            ]),
            ("04", "Rapport", C["sev_low"], [
                "Agrégation et déduplication des findings toutes sources",
                "Calcul du score de risque global (pondération CVSS)",
                "Rédaction des recommandations priorisées par sévérité",
                "Génération du rapport PDF professionnel",
            ]),
        ]

        for num, title, col, steps in phases:
            ph = Table(
                [[
                    Paragraph(f'<font color="{col.hexval()}"><b>{num}</b></font>',
                              S("pn", fontSize=14, fontName="Helvetica-Bold",
                                alignment=TA_CENTER, leading=18)),
                    Paragraph(title, S("pt", fontSize=11, fontName="Helvetica-Bold",
                               textColor=C["text"], leading=16)),
                ]],
                colWidths=[14*mm, W - 44*mm]
            )
            ph.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, -1), C["surface2"]),
                ("BACKGROUND",    (1, 0), (1, -1), C["surface"]),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
                ("LINEAFTER",     (0, 0), (0, -1), 1.5, col),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            e.append(ph)
            for step in steps:
                e.append(Paragraph(
                    f'  <font color="{col.hexval()}">▸</font>  {step}',
                    S("st", fontSize=8.5, textColor=C["text2"],
                      leading=14, leftIndent=10, spaceAfter=1)
                ))
            e.append(Spacer(1, 4*mm))

        e.append(Paragraph("Outils & Librairies", STYLES["subsection"]))
        tools = [
            ("Nmap",         "Scanner réseau — ports, services, OS, vulnérabilités NSE"),
            ("python-nmap",  "Interface Python pour Nmap"),
            ("dnspython",    "Requêtes DNS (records, zone transfer, DMARC...)"),
            ("requests",     "Client HTTP — analyse des applications web"),
            ("ssl",          "Analyse SSL/TLS et certificats (stdlib Python)"),
            ("python-whois", "Lookups WHOIS"),
            ("NVD API v2",   "Base nationale des vulnérabilités — NIST"),
            ("ReportLab",    "Génération des rapports PDF"),
        ]
        hdr  = [Paragraph(t, STYLES["th"]) for t in ["Outil", "Rôle"]]
        rows = [hdr]
        for tool, role in tools:
            rows.append([
                Paragraph(tool, S("tn", fontSize=8, fontName="Courier",
                           textColor=C["accent"], leading=11)),
                Paragraph(role, STYLES["td"]),
            ])
        t = Table(rows, colWidths=[40*mm, 125*mm])
        t.setStyle(tbl_style(C["accent2"]))
        e.append(t)

        e += [Spacer(1, 10*mm),
              HRFlowable(width="100%", thickness=0.5, color=C["border"]),
              Spacer(1, 4*mm)]
        e.append(Paragraph(
            "Ce rapport a été généré automatiquement par VulnScan Pro v1.0 (by hawkz). "
            "Il ne remplace pas un audit manuel complet conduit par des experts certifiés. "
            "Les résultats doivent être validés et interprétés en contexte avant toute action corrective.",
            STYLES["disclaimer"]
        ))
        return e
