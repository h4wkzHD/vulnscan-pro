"""
Module: report_generator.py
Génération de rapports PDF professionnels style pentest
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, ListFlowable, ListItem
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.lib.colors import HexColor, Color


# ─── PALETTE DE COULEURS ──────────────────────────────────────────────────────
DARK_BG = HexColor("#0D1117")
DARK_SURFACE = HexColor("#161B22")
ACCENT_CYAN = HexColor("#00D4FF")
ACCENT_BLUE = HexColor("#1F6FEB")
ACCENT_GREEN = HexColor("#3FB950")
ACCENT_ORANGE = HexColor("#D29922")
ACCENT_RED = HexColor("#F85149")
ACCENT_PURPLE = HexColor("#BC8CFF")

TEXT_PRIMARY = HexColor("#E6EDF3")
TEXT_SECONDARY = HexColor("#8B949E")
TEXT_MUTED = HexColor("#484F58")

SEVERITY_COLORS = {
    "CRITICAL": HexColor("#FF0000"),
    "HIGH": HexColor("#FF4500"),
    "MEDIUM": HexColor("#FFA500"),
    "LOW": HexColor("#32CD32"),
    "INFO": HexColor("#1E90FF"),
}

SEVERITY_BG_COLORS = {
    "CRITICAL": HexColor("#2D0000"),
    "HIGH": HexColor("#2D1000"),
    "MEDIUM": HexColor("#2D2000"),
    "LOW": HexColor("#002D00"),
    "INFO": HexColor("#00002D"),
}

W, H = A4


class ColoredBox(Flowable):
    """Boîte colorée personnalisée."""
    def __init__(self, width, height, fill_color, stroke_color=None, radius=3):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.fill_color = fill_color
        self.stroke_color = stroke_color
        self.radius = radius

    def draw(self):
        self.canv.setFillColor(self.fill_color)
        if self.stroke_color:
            self.canv.setStrokeColor(self.stroke_color)
            self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=1)
        else:
            self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=0)


class SeverityBadge(Flowable):
    """Badge de sévérité coloré."""
    def __init__(self, severity: str, width=60, height=16):
        Flowable.__init__(self)
        self.severity = severity
        self.width = width
        self.height = height

    def draw(self):
        color = SEVERITY_COLORS.get(self.severity, HexColor("#888888"))
        bg_color = SEVERITY_BG_COLORS.get(self.severity, HexColor("#111111"))
        self.canv.setFillColor(bg_color)
        self.canv.roundRect(0, 0, self.width, self.height, 3, fill=1, stroke=0)
        self.canv.setStrokeColor(color)
        self.canv.setLineWidth(1)
        self.canv.roundRect(0, 0, self.width, self.height, 3, fill=0, stroke=1)
        self.canv.setFillColor(color)
        self.canv.setFont("Helvetica-Bold", 7)
        text_width = self.canv.stringWidth(self.severity, "Helvetica-Bold", 7)
        self.canv.drawString((self.width - text_width) / 2, 4, self.severity)


class HeaderCanvas:
    """Canvas personnalisé pour header/footer sur chaque page."""

    def __init__(self, doc_data: dict):
        self.doc_data = doc_data
        self.target = doc_data.get("target", "")
        self.company = doc_data.get("company", "")
        self.scan_date = doc_data.get("scan_date", "")

    def __call__(self, canv, doc):
        self._draw_header(canv, doc)
        self._draw_footer(canv, doc)

    def _draw_header(self, canv, doc):
        if doc.page == 1:
            return  # Pas de header sur la page de garde

        canv.saveState()

        # Fond du header
        canv.setFillColor(DARK_SURFACE)
        canv.rect(0, H - 25*mm, W, 25*mm, fill=1, stroke=0)

        # Ligne accent
        canv.setFillColor(ACCENT_CYAN)
        canv.rect(0, H - 25*mm, W, 1.5, fill=1, stroke=0)

        # Logo/Titre
        canv.setFillColor(ACCENT_CYAN)
        canv.setFont("Helvetica-Bold", 10)
        canv.drawString(15*mm, H - 14*mm, "VULNSCAN PRO")

        canv.setFillColor(TEXT_SECONDARY)
        canv.setFont("Helvetica", 8)
        canv.drawString(15*mm, H - 20*mm, f"Rapport d'audit de sécurité — {self.target}")

        # Info droite
        canv.setFillColor(TEXT_SECONDARY)
        canv.setFont("Helvetica", 8)
        date_str = datetime.fromisoformat(self.scan_date).strftime("%d/%m/%Y") if self.scan_date else ""
        canv.drawRightString(W - 15*mm, H - 14*mm, self.company)
        canv.drawRightString(W - 15*mm, H - 20*mm, date_str)

        canv.restoreState()

    def _draw_footer(self, canv, doc):
        canv.saveState()

        # Fond footer
        canv.setFillColor(DARK_SURFACE)
        canv.rect(0, 0, W, 15*mm, fill=1, stroke=0)

        # Ligne accent
        canv.setFillColor(TEXT_MUTED)
        canv.rect(0, 15*mm, W, 0.5, fill=1, stroke=0)

        # Page number
        canv.setFillColor(TEXT_SECONDARY)
        canv.setFont("Helvetica", 7)
        canv.drawCentredString(W / 2, 6*mm, f"Page {doc.page}")
        canv.drawString(15*mm, 6*mm, "CONFIDENTIEL — Usage interne uniquement")
        canv.drawRightString(W - 15*mm, 6*mm, "VulnScan Pro v1.0")

        canv.restoreState()


class ReportGenerator:
    def __init__(self, results: dict, output_dir: str = "./output"):
        self.results = results
        self.output_dir = output_dir
        self.styles = self._build_styles()
        os.makedirs(output_dir, exist_ok=True)

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()

        styles = {
            "cover_title": ParagraphStyle(
                "cover_title",
                fontSize=36,
                fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY,
                alignment=TA_LEFT,
                spaceAfter=8,
                leading=42,
            ),
            "cover_subtitle": ParagraphStyle(
                "cover_subtitle",
                fontSize=14,
                fontName="Helvetica",
                textColor=ACCENT_CYAN,
                alignment=TA_LEFT,
                spaceAfter=6,
                leading=20,
            ),
            "cover_meta": ParagraphStyle(
                "cover_meta",
                fontSize=10,
                fontName="Helvetica",
                textColor=TEXT_SECONDARY,
                alignment=TA_LEFT,
                spaceAfter=4,
            ),
            "section_title": ParagraphStyle(
                "section_title",
                fontSize=18,
                fontName="Helvetica-Bold",
                textColor=ACCENT_CYAN,
                spaceBefore=20,
                spaceAfter=12,
                leading=24,
            ),
            "subsection_title": ParagraphStyle(
                "subsection_title",
                fontSize=13,
                fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY,
                spaceBefore=14,
                spaceAfter=8,
                leading=18,
            ),
            "body": ParagraphStyle(
                "body",
                fontSize=9,
                fontName="Helvetica",
                textColor=TEXT_SECONDARY,
                leading=14,
                spaceAfter=6,
                alignment=TA_JUSTIFY,
            ),
            "body_bold": ParagraphStyle(
                "body_bold",
                fontSize=9,
                fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY,
                leading=14,
                spaceAfter=4,
            ),
            "code": ParagraphStyle(
                "code",
                fontSize=8,
                fontName="Courier",
                textColor=ACCENT_GREEN,
                leading=12,
                spaceAfter=4,
                backColor=HexColor("#0D1117"),
                leftIndent=8,
                rightIndent=8,
                borderPadding=6,
            ),
            "finding_title": ParagraphStyle(
                "finding_title",
                fontSize=11,
                fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY,
                spaceBefore=6,
                spaceAfter=4,
                leading=15,
            ),
            "finding_desc": ParagraphStyle(
                "finding_desc",
                fontSize=9,
                fontName="Helvetica",
                textColor=TEXT_SECONDARY,
                leading=13,
                spaceAfter=4,
                alignment=TA_JUSTIFY,
            ),
            "finding_reco": ParagraphStyle(
                "finding_reco",
                fontSize=9,
                fontName="Helvetica",
                textColor=ACCENT_GREEN,
                leading=13,
                spaceAfter=4,
            ),
            "table_header": ParagraphStyle(
                "table_header",
                fontSize=8,
                fontName="Helvetica-Bold",
                textColor=DARK_BG,
                alignment=TA_CENTER,
            ),
            "table_cell": ParagraphStyle(
                "table_cell",
                fontSize=8,
                fontName="Helvetica",
                textColor=TEXT_SECONDARY,
                leading=11,
            ),
            "table_cell_center": ParagraphStyle(
                "table_cell_center",
                fontSize=8,
                fontName="Helvetica",
                textColor=TEXT_SECONDARY,
                alignment=TA_CENTER,
            ),
            "exec_title": ParagraphStyle(
                "exec_title",
                fontSize=22,
                fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY,
                spaceAfter=8,
            ),
            "risk_score": ParagraphStyle(
                "risk_score",
                fontSize=48,
                fontName="Helvetica-Bold",
                textColor=ACCENT_CYAN,
                alignment=TA_CENTER,
            ),
            "risk_label": ParagraphStyle(
                "risk_label",
                fontSize=12,
                fontName="Helvetica-Bold",
                textColor=TEXT_SECONDARY,
                alignment=TA_CENTER,
            ),
            "toc_entry": ParagraphStyle(
                "toc_entry",
                fontSize=9,
                fontName="Helvetica",
                textColor=TEXT_SECONDARY,
                leading=16,
                leftIndent=5,
            ),
            "toc_section": ParagraphStyle(
                "toc_section",
                fontSize=10,
                fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY,
                leading=16,
            ),
            "disclaimer": ParagraphStyle(
                "disclaimer",
                fontSize=8,
                fontName="Helvetica",
                textColor=TEXT_MUTED,
                leading=12,
                alignment=TA_JUSTIFY,
            ),
            "caption": ParagraphStyle(
                "caption",
                fontSize=8,
                fontName="Helvetica",
                textColor=TEXT_MUTED,
                alignment=TA_CENTER,
            ),
        }
        return styles

    def generate(self) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = self.results.get("target", "target").replace(".", "_").replace("/", "_")
        filename = f"vulnscan_{target_clean}_{ts}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=15*mm,
            leftMargin=15*mm,
            topMargin=30*mm,
            bottomMargin=20*mm,
            title=f"Rapport VulnScan — {self.results.get('target', '')}",
            author=self.results.get("auditor", "VulnScan Pro"),
            subject="Rapport d'audit de sécurité",
            creator="VulnScan Pro v1.0",
        )

        header_canvas = HeaderCanvas(self.results)
        story = []

        # ── Pages ─────────────────────────────────────────────
        story += self._build_cover_page()
        story.append(PageBreak())

        story += self._build_toc()
        story.append(PageBreak())

        story += self._build_executive_summary()
        story.append(PageBreak())

        story += self._build_findings_detail()
        story.append(PageBreak())

        story += self._build_network_section()
        story.append(PageBreak())

        story += self._build_http_section()
        story.append(PageBreak())

        story += self._build_ssl_section()
        story.append(PageBreak())

        story += self._build_dns_section()
        story.append(PageBreak())

        story += self._build_cve_section()
        story.append(PageBreak())

        story += self._build_recommendations()
        story.append(PageBreak())

        story += self._build_methodology()

        doc.build(story, onFirstPage=header_canvas, onLaterPages=header_canvas)
        return filepath

    def _build_cover_page(self) -> list:
        elements = []
        target = self.results.get("target", "")
        company = self.results.get("company", "Confidentiel")
        auditor = self.results.get("auditor", "VulnScan Pro")
        scan_date = self.results.get("scan_date", "")
        risk = self.results.get("risk", {})

        try:
            date_fmt = datetime.fromisoformat(scan_date).strftime("%d %B %Y")
        except Exception:
            date_fmt = datetime.now().strftime("%d %B %Y")

        # Grand fond sombre simulé via table
        cover_data = [[""]]
        cover_table = Table(cover_data, colWidths=[W - 30*mm], rowHeights=[240])
        cover_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_SURFACE),
            ("ROUNDEDCORNERS", [8]),
            ("TOPPADDING", (0, 0), (-1, -1), 30),
            ("LEFTPADDING", (0, 0), (-1, -1), 30),
        ]))

        # Accent bar
        accent_data = [[""]]
        accent_table = Table(accent_data, colWidths=[6], rowHeights=[90])
        accent_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ACCENT_CYAN),
        ]))

        # Score badge
        level = risk.get("level", "N/A")
        score = risk.get("score", 0)
        level_color = risk.get("color", "grey")

        risk_color_map = {
            "red": SEVERITY_COLORS["CRITICAL"],
            "orange3": SEVERITY_COLORS["HIGH"],
            "yellow": SEVERITY_COLORS["MEDIUM"],
            "green": SEVERITY_COLORS["LOW"],
            "bright_green": ACCENT_GREEN,
        }
        risk_color = risk_color_map.get(level_color, ACCENT_CYAN)

        # En-tête du rapport
        elements.append(Spacer(1, 15*mm))

        # Bande de titre
        title_block = [
            [
                Paragraph("RAPPORT D'AUDIT", ParagraphStyle("ct", fontSize=11, fontName="Helvetica",
                           textColor=ACCENT_CYAN, spaceAfter=2)),
            ],
            [
                Paragraph("DE SÉCURITÉ", ParagraphStyle("ct2", fontSize=11, fontName="Helvetica",
                           textColor=ACCENT_CYAN, spaceAfter=2)),
            ],
        ]
        label_table = Table([[Paragraph("RAPPORT D'AUDIT DE SÉCURITÉ",
                             ParagraphStyle("lbl", fontSize=10, fontName="Helvetica-Bold",
                                          textColor=ACCENT_CYAN))]],
                           colWidths=[W - 30*mm])
        label_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#0A2040")),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(label_table)
        elements.append(Spacer(1, 8*mm))

        # Titre principal
        elements.append(Paragraph(f"Audit de Sécurité", self.styles["cover_title"]))
        elements.append(Paragraph(target, ParagraphStyle("tgt", fontSize=22, fontName="Helvetica-Bold",
                                                         textColor=ACCENT_CYAN, spaceAfter=10)))
        elements.append(HRFlowable(width="100%", thickness=1, color=TEXT_MUTED, spaceAfter=15))

        # Métadonnées dans une grille
        meta_data = [
            [
                Paragraph("ENTREPRISE", ParagraphStyle("ml", fontSize=7, fontName="Helvetica",
                           textColor=TEXT_MUTED, spaceAfter=2)),
                Paragraph("AUDITEUR", ParagraphStyle("ml2", fontSize=7, fontName="Helvetica",
                           textColor=TEXT_MUTED, spaceAfter=2)),
                Paragraph("DATE DU SCAN", ParagraphStyle("ml3", fontSize=7, fontName="Helvetica",
                           textColor=TEXT_MUTED, spaceAfter=2)),
                Paragraph("DURÉE", ParagraphStyle("ml4", fontSize=7, fontName="Helvetica",
                           textColor=TEXT_MUTED, spaceAfter=2)),
            ],
            [
                Paragraph(company, ParagraphStyle("mv", fontSize=11, fontName="Helvetica-Bold",
                           textColor=TEXT_PRIMARY)),
                Paragraph(auditor, ParagraphStyle("mv2", fontSize=11, fontName="Helvetica-Bold",
                           textColor=TEXT_PRIMARY)),
                Paragraph(date_fmt, ParagraphStyle("mv3", fontSize=11, fontName="Helvetica-Bold",
                           textColor=TEXT_PRIMARY)),
                Paragraph(f"{self.results.get('scan_duration_seconds', 0):.0f}s",
                          ParagraphStyle("mv4", fontSize=11, fontName="Helvetica-Bold",
                           textColor=TEXT_PRIMARY)),
            ],
        ]
        meta_table = Table(meta_data, colWidths=[(W - 30*mm) / 4] * 4)
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_SURFACE),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, TEXT_MUTED),
            ("LINEAFTER", (0, 0), (-2, -1), 0.5, TEXT_MUTED),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 12*mm))

        # Score de risque global
        score_color = risk_color

        score_data = [
            [
                Paragraph("SCORE DE RISQUE GLOBAL", ParagraphStyle("sl", fontSize=8, fontName="Helvetica",
                           textColor=TEXT_MUTED, alignment=TA_CENTER)),
                Paragraph("VULNÉRABILITÉS TOTALES", ParagraphStyle("sl2", fontSize=8, fontName="Helvetica",
                           textColor=TEXT_MUTED, alignment=TA_CENTER)),
                Paragraph("NIVEAU DE RISQUE", ParagraphStyle("sl3", fontSize=8, fontName="Helvetica",
                           textColor=TEXT_MUTED, alignment=TA_CENTER)),
            ],
            [
                Paragraph(f"{score}/100", ParagraphStyle("sv", fontSize=28, fontName="Helvetica-Bold",
                           textColor=score_color, alignment=TA_CENTER)),
                Paragraph(str(self._count_total_findings()), ParagraphStyle("sv2", fontSize=28,
                           fontName="Helvetica-Bold", textColor=TEXT_PRIMARY, alignment=TA_CENTER)),
                Paragraph(level, ParagraphStyle("sv3", fontSize=20, fontName="Helvetica-Bold",
                           textColor=score_color, alignment=TA_CENTER)),
            ],
        ]
        score_table = Table(score_data, colWidths=[(W - 30*mm) / 3] * 3)
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_SURFACE),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, TEXT_MUTED),
            ("LINEAFTER", (0, 0), (-2, -1), 0.5, TEXT_MUTED),
            ("BOX", (0, 0), (-1, -1), 1, score_color),
        ]))
        elements.append(score_table)
        elements.append(Spacer(1, 12*mm))

        # Répartition par sévérité
        sev_counts = self._count_by_severity()
        sev_data = [[
            Paragraph(f"CRITICAL\n{sev_counts.get('CRITICAL', 0)}",
                      ParagraphStyle("sc", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=SEVERITY_COLORS["CRITICAL"], alignment=TA_CENTER)),
            Paragraph(f"HIGH\n{sev_counts.get('HIGH', 0)}",
                      ParagraphStyle("sh", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=SEVERITY_COLORS["HIGH"], alignment=TA_CENTER)),
            Paragraph(f"MEDIUM\n{sev_counts.get('MEDIUM', 0)}",
                      ParagraphStyle("sm", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=SEVERITY_COLORS["MEDIUM"], alignment=TA_CENTER)),
            Paragraph(f"LOW\n{sev_counts.get('LOW', 0)}",
                      ParagraphStyle("sl_", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=SEVERITY_COLORS["LOW"], alignment=TA_CENTER)),
            Paragraph(f"INFO\n{sev_counts.get('INFO', 0)}",
                      ParagraphStyle("si", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=SEVERITY_COLORS["INFO"], alignment=TA_CENTER)),
        ]]
        sev_table = Table(sev_data, colWidths=[(W - 30*mm) / 5] * 5, rowHeights=[40])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), SEVERITY_BG_COLORS["CRITICAL"]),
            ("BACKGROUND", (1, 0), (1, -1), SEVERITY_BG_COLORS["HIGH"]),
            ("BACKGROUND", (2, 0), (2, -1), SEVERITY_BG_COLORS["MEDIUM"]),
            ("BACKGROUND", (3, 0), (3, -1), SEVERITY_BG_COLORS["LOW"]),
            ("BACKGROUND", (4, 0), (4, -1), SEVERITY_BG_COLORS["INFO"]),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEAFTER", (0, 0), (-2, -1), 0.5, TEXT_MUTED),
        ]))
        elements.append(sev_table)

        elements.append(Spacer(1, 20*mm))

        # Avertissement confidentialité
        disclaimer_text = (
            "DOCUMENT CONFIDENTIEL — Ce rapport contient des informations sensibles sur la "
            "sécurité du système audité. Il est destiné exclusivement aux personnes autorisées. "
            "Toute reproduction ou diffusion non autorisée est interdite."
        )
        disc_table = Table([[Paragraph(disclaimer_text, self.styles["disclaimer"])]],
                           colWidths=[W - 30*mm])
        disc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#1A1A1A")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("BOX", (0, 0), (-1, -1), 0.5, TEXT_MUTED),
        ]))
        elements.append(disc_table)

        return elements

    def _build_toc(self) -> list:
        elements = []
        elements.append(Paragraph("Table des matières", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=12))

        sections = [
            ("1.", "Résumé Exécutif", ""),
            ("2.", "Détail des Vulnérabilités", ""),
            ("   2.1", "Vulnérabilités Critiques", ""),
            ("   2.2", "Vulnérabilités Élevées", ""),
            ("   2.3", "Vulnérabilités Moyennes", ""),
            ("   2.4", "Vulnérabilités Faibles", ""),
            ("3.", "Analyse Réseau & Ports", ""),
            ("4.", "Analyse HTTP/HTTPS", ""),
            ("5.", "Analyse SSL/TLS", ""),
            ("6.", "Analyse DNS", ""),
            ("7.", "CVEs Identifiées", ""),
            ("8.", "Recommandations Prioritaires", ""),
            ("9.", "Méthodologie", ""),
        ]

        for num, title, page in sections:
            is_main = not num.startswith("  ")
            style = self.styles["toc_section"] if is_main else self.styles["toc_entry"]
            row = Table(
                [[Paragraph(num, style), Paragraph(title, style), Paragraph("•••", self.styles["toc_entry"])]],
                colWidths=[20*mm, W - 70*mm, 20*mm]
            )
            row.setStyle(TableStyle([
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
                ("ALIGN", (2, 0), (2, -1), "RIGHT"),
                ("TEXTCOLOR", (2, 0), (2, -1), TEXT_MUTED),
            ]))
            elements.append(row)

        return elements

    def _build_executive_summary(self) -> list:
        elements = []
        elements.append(Paragraph("1. Résumé Exécutif", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        target = self.results.get("target", "")
        company = self.results.get("company", "")
        auditor = self.results.get("auditor", "")
        risk = self.results.get("risk", {})
        level = risk.get("level", "N/A")
        score = risk.get("score", 0)

        try:
            scan_date = datetime.fromisoformat(self.results.get("scan_date", "")).strftime("%d %B %Y à %H:%M")
        except Exception:
            scan_date = "N/A"

        duration = self.results.get("scan_duration_seconds", 0)

        # Contexte
        elements.append(Paragraph("Contexte de l'audit", self.styles["subsection_title"]))
        context_text = (
            f"Un audit de sécurité automatisé a été réalisé le <b>{scan_date}</b> sur la cible "
            f"<b>{target}</b> pour le compte de <b>{company}</b>. "
            f"L'audit a été conduit par <b>{auditor}</b> à l'aide de l'outil VulnScan Pro v1.0. "
            f"La durée totale du scan a été de <b>{duration:.0f} secondes</b>."
        )
        elements.append(Paragraph(context_text, self.styles["body"]))
        elements.append(Spacer(1, 4*mm))

        # Périmètre
        elements.append(Paragraph("Périmètre analysé", self.styles["subsection_title"]))
        modules_ran = []
        module_names = {
            "whois": "Informations WHOIS & DNS Passif",
            "dns": "Scan DNS actif (enregistrements, zone transfer, SPF/DKIM/DMARC)",
            "ports": "Scan de ports TCP (plage complète)",
            "network": "Analyse réseau Nmap (services, versions, OS fingerprinting)",
            "vulns": "Scripts NSE de vulnérabilités Nmap",
            "http": "Analyse HTTP (headers de sécurité, technologies, CORS, cookies)",
            "ssl": "Analyse SSL/TLS (certificat, protocoles, cipher suites)",
            "cve": "Recherche de CVEs (NVD + base locale)",
        }
        for mod_key, mod_name in module_names.items():
            data = self.results.get("modules", {}).get(mod_key, {})
            if not data.get("skipped") and not data.get("error"):
                modules_ran.append(f"✓ {mod_name}")

        for item in modules_ran:
            elements.append(Paragraph(item, ParagraphStyle("mi", fontSize=8, fontName="Helvetica",
                                                            textColor=ACCENT_GREEN, leading=14,
                                                            leftIndent=8)))
        elements.append(Spacer(1, 4*mm))

        # Résultat global
        elements.append(Paragraph("Résultat global", self.styles["subsection_title"]))
        sev_counts = self._count_by_severity()
        total = self._count_total_findings()

        result_text = (
            f"L'audit a permis d'identifier <b>{total} problèmes de sécurité</b> répartis comme suit: "
            f"<font color='red'><b>{sev_counts.get('CRITICAL', 0)} CRITIQUES</b></font>, "
            f"<b>{sev_counts.get('HIGH', 0)} ÉLEVÉS</b>, "
            f"<b>{sev_counts.get('MEDIUM', 0)} MOYENS</b>, "
            f"<b>{sev_counts.get('LOW', 0)} FAIBLES</b>, "
            f"et <b>{sev_counts.get('INFO', 0)} INFORMATIFS</b>. "
            f"Le score de risque global est de <b>{score}/100</b>, correspondant à un niveau <b>{level}</b>."
        )
        elements.append(Paragraph(result_text, self.styles["body"]))
        elements.append(Spacer(1, 6*mm))

        # Tableau de synthèse des modules
        elements.append(Paragraph("Synthèse par domaine", self.styles["subsection_title"]))

        header_row = [
            Paragraph("Domaine analysé", self.styles["table_header"]),
            Paragraph("Statut", self.styles["table_header"]),
            Paragraph("Critiques", self.styles["table_header"]),
            Paragraph("Élevés", self.styles["table_header"]),
            Paragraph("Moyens", self.styles["table_header"]),
            Paragraph("Total", self.styles["table_header"]),
        ]
        rows = [header_row]

        module_display = {
            "network": "Réseau & Services",
            "ports": "Ports ouverts",
            "http": "HTTP/HTTPS",
            "ssl": "SSL/TLS",
            "dns": "DNS",
            "cve": "CVEs",
            "vulns": "Vulnérabilités NSE",
            "whois": "WHOIS",
        }

        for mod_key, display_name in module_display.items():
            data = self.results.get("modules", {}).get(mod_key, {})
            if data.get("skipped"):
                status = Paragraph("Ignoré", ParagraphStyle("s", fontSize=8, textColor=TEXT_MUTED, alignment=TA_CENTER))
                rows.append([
                    Paragraph(display_name, self.styles["table_cell"]),
                    status,
                    Paragraph("-", self.styles["table_cell_center"]),
                    Paragraph("-", self.styles["table_cell_center"]),
                    Paragraph("-", self.styles["table_cell_center"]),
                    Paragraph("-", self.styles["table_cell_center"]),
                ])
                continue
            if data.get("error"):
                status = Paragraph("Erreur", ParagraphStyle("s", fontSize=8, textColor=SEVERITY_COLORS["HIGH"], alignment=TA_CENTER))
            else:
                status = Paragraph("OK", ParagraphStyle("s", fontSize=8, textColor=ACCENT_GREEN, alignment=TA_CENTER))

            findings = data.get("findings", [])
            c = sum(1 for f in findings if f.get("severity") == "CRITICAL")
            h = sum(1 for f in findings if f.get("severity") == "HIGH")
            m = sum(1 for f in findings if f.get("severity") == "MEDIUM")

            rows.append([
                Paragraph(display_name, self.styles["table_cell"]),
                status,
                Paragraph(str(c), ParagraphStyle("sc", fontSize=8, textColor=SEVERITY_COLORS["CRITICAL"] if c else TEXT_MUTED, alignment=TA_CENTER, fontName="Helvetica-Bold" if c else "Helvetica")),
                Paragraph(str(h), ParagraphStyle("sh", fontSize=8, textColor=SEVERITY_COLORS["HIGH"] if h else TEXT_MUTED, alignment=TA_CENTER, fontName="Helvetica-Bold" if h else "Helvetica")),
                Paragraph(str(m), ParagraphStyle("sm", fontSize=8, textColor=SEVERITY_COLORS["MEDIUM"] if m else TEXT_MUTED, alignment=TA_CENTER, fontName="Helvetica-Bold" if m else "Helvetica")),
                Paragraph(str(len(findings)), ParagraphStyle("st", fontSize=8, textColor=TEXT_PRIMARY, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            ])

        col_widths = [55*mm, 25*mm, 25*mm, 25*mm, 25*mm, 25*mm]
        summary_table = Table(rows, colWidths=col_widths)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_CYAN),
            ("BACKGROUND", (0, 1), (-1, -1), DARK_SURFACE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
            ("BOX", (0, 0), (-1, -1), 1, ACCENT_CYAN),
        ]))
        elements.append(summary_table)

        return elements

    def _build_findings_detail(self) -> list:
        elements = []
        elements.append(Paragraph("2. Détail des Vulnérabilités", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        all_findings = self._get_all_findings()

        if not all_findings:
            elements.append(Paragraph("Aucune vulnérabilité significative détectée.", self.styles["body"]))
            return elements

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in all_findings if f.get("severity") == severity]
            if not sev_findings:
                continue

            color = SEVERITY_COLORS[severity]
            bg_color = SEVERITY_BG_COLORS[severity]

            # En-tête de section sévérité
            sev_header = Table(
                [[Paragraph(f"  {severity} — {len(sev_findings)} finding(s)",
                           ParagraphStyle("sh", fontSize=11, fontName="Helvetica-Bold",
                                         textColor=color))]],
                colWidths=[W - 30*mm]
            )
            sev_header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 1.5, color),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]))
            elements.append(Spacer(1, 5*mm))
            elements.append(sev_header)
            elements.append(Spacer(1, 4*mm))

            for i, finding in enumerate(sev_findings):
                finding_block = self._build_finding_card(finding, i + 1, color, bg_color)
                elements.append(KeepTogether(finding_block))
                elements.append(Spacer(1, 3*mm))

        return elements

    def _build_finding_card(self, finding: dict, num: int, color, bg_color) -> list:
        elements = []
        title = finding.get("title", "Vulnérabilité")
        description = finding.get("description", "")
        recommendation = finding.get("recommendation", "")
        port = finding.get("port", "")
        cves = finding.get("cves", [])
        score = finding.get("score", "")

        # En-tête du finding
        header_content = [
            [
                Paragraph(f"#{num:02d}", ParagraphStyle("fn", fontSize=9, fontName="Helvetica-Bold",
                           textColor=color)),
                Paragraph(title, ParagraphStyle("ft", fontSize=10, fontName="Helvetica-Bold",
                           textColor=TEXT_PRIMARY, leading=14)),
                Paragraph(f"Port: {port}" if port else "",
                          ParagraphStyle("fp", fontSize=8, fontName="Helvetica",
                           textColor=TEXT_MUTED, alignment=TA_RIGHT)),
            ]
        ]
        header_table = Table(header_content, colWidths=[12*mm, W - 60*mm, 25*mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, color),
        ]))
        elements.append(header_table)

        # Corps du finding
        body_rows = []

        if description:
            body_rows.append([
                Paragraph("Description:", ParagraphStyle("lbl", fontSize=8, fontName="Helvetica-Bold",
                           textColor=TEXT_SECONDARY)),
                Paragraph(description[:600], self.styles["finding_desc"]),
            ])

        if recommendation:
            body_rows.append([
                Paragraph("Recommandation:", ParagraphStyle("lbl2", fontSize=8, fontName="Helvetica-Bold",
                           textColor=ACCENT_GREEN)),
                Paragraph(recommendation, self.styles["finding_reco"]),
            ])

        if cves:
            cve_str = ", ".join(cves[:5])
            body_rows.append([
                Paragraph("CVE(s):", ParagraphStyle("lbl3", fontSize=8, fontName="Helvetica-Bold",
                           textColor=ACCENT_ORANGE)),
                Paragraph(cve_str, ParagraphStyle("cv", fontSize=8, fontName="Courier",
                           textColor=ACCENT_ORANGE, leading=12)),
            ])

        if score:
            body_rows.append([
                Paragraph("Score CVSS:", ParagraphStyle("lbl4", fontSize=8, fontName="Helvetica-Bold",
                           textColor=TEXT_MUTED)),
                Paragraph(str(score), ParagraphStyle("sc", fontSize=8, fontName="Helvetica-Bold",
                           textColor=color)),
            ])

        if body_rows:
            body_table = Table(body_rows, colWidths=[30*mm, W - 60*mm])
            body_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), DARK_SURFACE),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 0.5, bg_color),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(body_table)

        return elements

    def _build_network_section(self) -> list:
        elements = []
        elements.append(Paragraph("3. Analyse Réseau & Ports", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        # Ports ouverts
        ports_data = self.results.get("modules", {}).get("ports", {})
        network_data = self.results.get("modules", {}).get("network", {})

        open_ports = ports_data.get("open_ports", []) or network_data.get("open_ports", [])
        os_info = network_data.get("os_info", {})

        if os_info:
            elements.append(Paragraph("Détection du système d'exploitation", self.styles["subsection_title"]))
            os_text = f"OS détecté: <b>{os_info.get('name', 'Inconnu')}</b> (précision: {os_info.get('accuracy', '?')}%)"
            elements.append(Paragraph(os_text, self.styles["body"]))
            elements.append(Spacer(1, 4*mm))

        elements.append(Paragraph(f"Ports ouverts ({len(open_ports)} détectés)", self.styles["subsection_title"]))

        if open_ports:
            header = [
                Paragraph("Port", self.styles["table_header"]),
                Paragraph("Protocole", self.styles["table_header"]),
                Paragraph("Service", self.styles["table_header"]),
                Paragraph("Version/Produit", self.styles["table_header"]),
                Paragraph("Risque", self.styles["table_header"]),
            ]
            rows = [header]

            high_risk_ports = {21, 23, 25, 135, 139, 445, 3389, 4444, 5900, 6379, 9200, 27017, 2375}

            for p in open_ports[:50]:
                port_num = p.get("port", 0)
                is_risky = port_num in high_risk_ports
                risk_text = "⚠ Élevé" if is_risky else "Normal"
                risk_color = SEVERITY_COLORS["HIGH"] if is_risky else ACCENT_GREEN

                rows.append([
                    Paragraph(str(port_num), ParagraphStyle("pc", fontSize=8, fontName="Helvetica-Bold",
                               textColor=ACCENT_CYAN, alignment=TA_CENTER)),
                    Paragraph(str(p.get("protocol", "tcp")), self.styles["table_cell_center"]),
                    Paragraph(str(p.get("service", "?")), self.styles["table_cell"]),
                    Paragraph(str(p.get("full_version", p.get("banner", "")))[:60], self.styles["table_cell"]),
                    Paragraph(risk_text, ParagraphStyle("pr", fontSize=8, textColor=risk_color, alignment=TA_CENTER)),
                ])

            port_table = Table(rows, colWidths=[18*mm, 22*mm, 28*mm, 85*mm, 22*mm])
            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_CYAN),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_BLUE),
            ]))
            elements.append(port_table)
        else:
            elements.append(Paragraph("Aucun port ouvert détecté ou scan non disponible.", self.styles["body"]))

        return elements

    def _build_http_section(self) -> list:
        elements = []
        elements.append(Paragraph("4. Analyse HTTP/HTTPS", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        http_data = self.results.get("modules", {}).get("http", {})
        if http_data.get("error"):
            elements.append(Paragraph(f"Erreur: {http_data['error']}", self.styles["body"]))
            return elements

        # Technologies détectées
        techs = http_data.get("technologies", [])
        if techs:
            elements.append(Paragraph("Technologies détectées", self.styles["subsection_title"]))
            tech_rows = [[
                Paragraph("Technologie", self.styles["table_header"]),
                Paragraph("Source", self.styles["table_header"]),
                Paragraph("Valeur", self.styles["table_header"]),
            ]]
            for t in techs:
                tech_rows.append([
                    Paragraph(t.get("name", ""), self.styles["table_cell"]),
                    Paragraph(t.get("source", ""), self.styles["table_cell"]),
                    Paragraph(str(t.get("value", ""))[:80], self.styles["table_cell"]),
                ])
            tech_table = Table(tech_rows, colWidths=[50*mm, 50*mm, 75*mm])
            tech_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_BLUE),
            ]))
            elements.append(tech_table)
            elements.append(Spacer(1, 5*mm))

        # Headers de sécurité
        headers_analysis = http_data.get("headers_analysis", [])
        if headers_analysis:
            elements.append(Paragraph("Analyse des en-têtes de sécurité", self.styles["subsection_title"]))
            h_rows = [[
                Paragraph("En-tête HTTP", self.styles["table_header"]),
                Paragraph("Statut", self.styles["table_header"]),
                Paragraph("Valeur", self.styles["table_header"]),
            ]]
            for h in headers_analysis:
                status = h.get("status", "")
                status_color = ACCENT_GREEN if status == "présent" else SEVERITY_COLORS["HIGH"]
                h_rows.append([
                    Paragraph(h.get("header", ""), self.styles["table_cell"]),
                    Paragraph(status.upper(), ParagraphStyle("hs", fontSize=8, textColor=status_color,
                               alignment=TA_CENTER, fontName="Helvetica-Bold")),
                    Paragraph(str(h.get("value", "N/A"))[:80], self.styles["table_cell"]),
                ])
            h_table = Table(h_rows, colWidths=[60*mm, 25*mm, 90*mm])
            h_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_BLUE),
            ]))
            elements.append(h_table)

        return elements

    def _build_ssl_section(self) -> list:
        elements = []
        elements.append(Paragraph("5. Analyse SSL/TLS", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        ssl_data = self.results.get("modules", {}).get("ssl", {})
        cert_info = ssl_data.get("cert_info", {})
        tls_info = ssl_data.get("tls_info", {})

        if cert_info:
            elements.append(Paragraph("Informations du certificat", self.styles["subsection_title"]))
            cert_rows = [
                ["Champ", "Valeur"],
                ["Common Name (CN)", cert_info.get("common_name", "N/A")],
                ["Émetteur", cert_info.get("issuer_name", "N/A")],
                ["Valide depuis", cert_info.get("valid_from", "N/A")],
                ["Expiration", cert_info.get("expiry_date", "N/A")],
                ["Jours restants", str(cert_info.get("days_until_expiry", "N/A"))],
                ["SANs", ", ".join(cert_info.get("san", [])[:5])],
                ["Numéro de série", cert_info.get("serial_number", "N/A")],
            ]
            formatted_rows = []
            for i, row in enumerate(cert_rows):
                if i == 0:
                    formatted_rows.append([
                        Paragraph(row[0], self.styles["table_header"]),
                        Paragraph(row[1], self.styles["table_header"]),
                    ])
                else:
                    formatted_rows.append([
                        Paragraph(row[0], ParagraphStyle("cl", fontSize=8, fontName="Helvetica-Bold",
                                   textColor=TEXT_SECONDARY)),
                        Paragraph(str(row[1])[:120], self.styles["table_cell"]),
                    ])

            cert_table = Table(formatted_rows, colWidths=[55*mm, 120*mm])
            cert_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_CYAN),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_CYAN),
            ]))
            elements.append(cert_table)
            elements.append(Spacer(1, 5*mm))

        if tls_info:
            elements.append(Paragraph("Configuration TLS", self.styles["subsection_title"]))
            proto = tls_info.get("protocol", "N/A")
            cipher = tls_info.get("cipher_suite", "N/A")
            bits = tls_info.get("cipher_bits", 0)

            proto_color = ACCENT_GREEN if proto in ["TLSv1.2", "TLSv1.3"] else SEVERITY_COLORS["HIGH"]
            tls_rows = [
                [Paragraph("Protocole TLS", ParagraphStyle("tl", fontSize=8, fontName="Helvetica-Bold", textColor=TEXT_SECONDARY)),
                 Paragraph(proto, ParagraphStyle("tv", fontSize=9, fontName="Helvetica-Bold", textColor=proto_color))],
                [Paragraph("Cipher Suite", ParagraphStyle("tl2", fontSize=8, fontName="Helvetica-Bold", textColor=TEXT_SECONDARY)),
                 Paragraph(str(cipher), self.styles["table_cell"])],
                [Paragraph("Force du chiffrement", ParagraphStyle("tl3", fontSize=8, fontName="Helvetica-Bold", textColor=TEXT_SECONDARY)),
                 Paragraph(f"{bits} bits", self.styles["table_cell"])],
            ]
            tls_table = Table(tls_rows, colWidths=[55*mm, 120*mm])
            tls_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), DARK_SURFACE),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_CYAN),
            ]))
            elements.append(tls_table)

        return elements

    def _build_dns_section(self) -> list:
        elements = []
        elements.append(Paragraph("6. Analyse DNS", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        dns_data = self.results.get("modules", {}).get("dns", {})
        records = dns_data.get("records", {})
        subdomains = dns_data.get("subdomains_found", [])
        whois_data = self.results.get("modules", {}).get("whois", {}).get("whois_info", {})

        # Infos WHOIS
        if whois_data:
            elements.append(Paragraph("Informations WHOIS", self.styles["subsection_title"]))
            whois_items = [
                ("Domaine", whois_data.get("domain", "N/A")),
                ("IP résolue", whois_data.get("resolved_ip", "N/A")),
                ("Reverse DNS", whois_data.get("reverse_dns", "N/A")),
                ("Registrar", whois_data.get("registrar", "N/A")),
                ("Organisation", whois_data.get("org", "N/A")),
                ("Pays", whois_data.get("country", "N/A")),
                ("Création", whois_data.get("creation_date", "N/A")),
                ("Expiration domaine", whois_data.get("expiration_date", "N/A")),
            ]
            whois_rows = [[
                Paragraph(k, ParagraphStyle("wk", fontSize=8, fontName="Helvetica-Bold", textColor=TEXT_SECONDARY)),
                Paragraph(str(v)[:100], self.styles["table_cell"])
            ] for k, v in whois_items]
            whois_table = Table(whois_rows, colWidths=[45*mm, 130*mm])
            whois_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), DARK_SURFACE),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_BLUE),
            ]))
            elements.append(whois_table)
            elements.append(Spacer(1, 5*mm))

        # Enregistrements DNS
        if records:
            elements.append(Paragraph("Enregistrements DNS", self.styles["subsection_title"]))
            for rtype, rvals in records.items():
                if not rvals:
                    continue
                elements.append(Paragraph(f"▸ {rtype}", ParagraphStyle("rt", fontSize=9, fontName="Helvetica-Bold",
                                          textColor=ACCENT_CYAN, spaceAfter=2)))
                for val in rvals[:5]:
                    elements.append(Paragraph(f"  {val}", self.styles["code"]))
            elements.append(Spacer(1, 4*mm))

        # Sous-domaines découverts
        if subdomains:
            elements.append(Paragraph(f"Sous-domaines découverts ({len(subdomains)})", self.styles["subsection_title"]))
            sub_rows = [[
                Paragraph("Sous-domaine", self.styles["table_header"]),
                Paragraph("IP(s)", self.styles["table_header"]),
            ]]
            for s in subdomains[:30]:
                sub_rows.append([
                    Paragraph(s.get("subdomain", ""), ParagraphStyle("sd", fontSize=8, fontName="Courier",
                               textColor=ACCENT_CYAN)),
                    Paragraph(", ".join(s.get("ips", [])), self.styles["table_cell"]),
                ])
            sub_table = Table(sub_rows, colWidths=[100*mm, 75*mm])
            sub_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT_BLUE),
            ]))
            elements.append(sub_table)

        return elements

    def _build_cve_section(self) -> list:
        elements = []
        elements.append(Paragraph("7. CVEs Identifiées", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        cve_data = self.results.get("modules", {}).get("cve", {})

        if cve_data.get("skipped"):
            elements.append(Paragraph("Lookup CVE désactivé pour ce scan.", self.styles["body"]))
            return elements

        cves = cve_data.get("cves", [])
        lookup_results = cve_data.get("lookup_results", [])

        elements.append(Paragraph(
            f"Total CVEs trouvées: <b>{len(cves)}</b> pour {cve_data.get('services_analyzed', 0)} service(s) analysé(s).",
            self.styles["body"]
        ))
        elements.append(Spacer(1, 4*mm))

        if not cves:
            elements.append(Paragraph("Aucune CVE connue trouvée pour les services détectés.", self.styles["body"]))
            return elements

        # Tableau des CVEs
        cve_rows = [[
            Paragraph("CVE ID", self.styles["table_header"]),
            Paragraph("Score", self.styles["table_header"]),
            Paragraph("Sévérité", self.styles["table_header"]),
            Paragraph("Description", self.styles["table_header"]),
            Paragraph("Source", self.styles["table_header"]),
        ]]

        for cve in sorted(cves, key=lambda x: x.get("score", 0), reverse=True)[:40]:
            sev = cve.get("severity", "MEDIUM")
            sev_color = SEVERITY_COLORS.get(sev, TEXT_SECONDARY)
            score = cve.get("score", 0)

            cve_rows.append([
                Paragraph(cve.get("id", ""), ParagraphStyle("ci", fontSize=7, fontName="Courier",
                           textColor=ACCENT_ORANGE)),
                Paragraph(str(score), ParagraphStyle("cs", fontSize=8, fontName="Helvetica-Bold",
                           textColor=sev_color, alignment=TA_CENTER)),
                Paragraph(sev, ParagraphStyle("csev", fontSize=7, fontName="Helvetica-Bold",
                           textColor=sev_color, alignment=TA_CENTER)),
                Paragraph(cve.get("description", "")[:150], self.styles["table_cell"]),
                Paragraph(cve.get("source", ""), ParagraphStyle("csrc", fontSize=7, textColor=TEXT_MUTED)),
            ])

        cve_table = Table(cve_rows, colWidths=[28*mm, 14*mm, 18*mm, 95*mm, 20*mm])
        cve_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_ORANGE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
            ("BOX", (0, 0), (-1, -1), 1, ACCENT_ORANGE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(cve_table)
        return elements

    def _build_recommendations(self) -> list:
        elements = []
        elements.append(Paragraph("8. Recommandations Prioritaires", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        all_findings = self._get_all_findings()
        critical_high = [f for f in all_findings if f.get("severity") in ["CRITICAL", "HIGH"]]

        if not critical_high:
            elements.append(Paragraph(
                "Aucune vulnérabilité critique ou élevée détectée. Maintenir la vigilance et effectuer des audits réguliers.",
                self.styles["body"]
            ))
        else:
            elements.append(Paragraph(
                f"Les {len(critical_high)} recommandations suivantes doivent être traitées en priorité immédiate:",
                self.styles["body"]
            ))
            elements.append(Spacer(1, 5*mm))

            seen_recos = set()
            counter = 1
            for finding in critical_high[:20]:
                reco = finding.get("recommendation", "")
                if not reco or reco in seen_recos:
                    continue
                seen_recos.add(reco)

                sev = finding.get("severity", "HIGH")
                color = SEVERITY_COLORS.get(sev, TEXT_SECONDARY)
                bg = SEVERITY_BG_COLORS.get(sev, DARK_SURFACE)

                reco_block = Table(
                    [[
                        Paragraph(f"{counter:02d}", ParagraphStyle("rn", fontSize=14, fontName="Helvetica-Bold",
                                   textColor=color, alignment=TA_CENTER)),
                        Paragraph(
                            f"<b>{finding.get('title', '')}</b><br/>"
                            f"<font color='#8B949E'>{reco}</font>",
                            ParagraphStyle("rb", fontSize=9, fontName="Helvetica", textColor=ACCENT_GREEN,
                                          leading=14)
                        )
                    ]],
                    colWidths=[15*mm, W - 50*mm]
                )
                reco_block.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), bg),
                    ("BACKGROUND", (1, 0), (-1, -1), DARK_SURFACE),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 1, bg),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]))
                elements.append(reco_block)
                elements.append(Spacer(1, 3*mm))
                counter += 1

        # Bonnes pratiques générales
        elements.append(Spacer(1, 8*mm))
        elements.append(Paragraph("Bonnes pratiques générales", self.styles["subsection_title"]))

        best_practices = [
            ("🔄", "Mettre en place un programme de gestion des correctifs (patch management) mensuel"),
            ("🔐", "Implémenter une authentification multi-facteurs (MFA) sur tous les accès distants"),
            ("📊", "Déployer un SIEM pour la détection d'incidents en temps réel"),
            ("🔍", "Réaliser des tests d'intrusion réguliers (trimestriels minimum)"),
            ("📋", "Maintenir un inventaire exhaustif des actifs et des services exposés"),
            ("🛡", "Configurer un WAF (Web Application Firewall) devant les applications web"),
            ("📦", "Mettre en place une politique de sauvegarde 3-2-1 testée régulièrement"),
            ("👥", "Former les équipes aux bonnes pratiques de sécurité (phishing, mots de passe)"),
        ]

        for icon, practice in best_practices:
            elements.append(Paragraph(
                f"{icon}  {practice}",
                ParagraphStyle("bp", fontSize=9, fontName="Helvetica", textColor=TEXT_SECONDARY,
                               leading=16, leftIndent=5, spaceAfter=2)
            ))

        return elements

    def _build_methodology(self) -> list:
        elements = []
        elements.append(Paragraph("9. Méthodologie", self.styles["section_title"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_CYAN, spaceAfter=10))

        methodology_text = (
            "L'audit a été réalisé à l'aide de l'outil VulnScan Pro v1.0, suivant une approche "
            "systématique en plusieurs phases. L'ensemble des tests a été effectué depuis l'extérieur "
            "(approche boîte noire / black-box) sauf indication contraire."
        )
        elements.append(Paragraph(methodology_text, self.styles["body"]))
        elements.append(Spacer(1, 5*mm))

        phases = [
            ("Phase 1 — Reconnaissance", [
                "Collecte d'informations WHOIS (registrar, dates, contacts)",
                "Résolution DNS et analyse des enregistrements (A, MX, TXT, NS, SOA)",
                "Vérification SPF, DKIM, DMARC",
                "Test de transfert de zone DNS",
                "Découverte de sous-domaines par dictionnaire",
            ]),
            ("Phase 2 — Scan réseau", [
                "Scan de ports TCP 1-10000 avec détection d'état",
                "Identification des services et versions via Nmap (-sV)",
                "Fingerprinting du système d'exploitation (-O)",
                "Exécution des scripts NSE par défaut (-sC)",
                "Capture de banners de services",
            ]),
            ("Phase 3 — Analyse des vulnérabilités", [
                "Exécution des scripts NSE de vulnérabilités (vuln, ssl-heartbleed, smb-vuln-ms17-010...)",
                "Analyse des headers HTTP de sécurité",
                "Audit de la configuration SSL/TLS",
                "Recherche de CVEs dans la base NVD et base locale",
                "Détection de configurations dangereuses",
            ]),
            ("Phase 4 — Rapport", [
                "Agrégation et déduplication des findings",
                "Calcul du score de risque global (pondération par sévérité CVSS)",
                "Rédaction des recommandations priorisées",
                "Génération du rapport PDF",
            ]),
        ]

        for phase_title, steps in phases:
            elements.append(Paragraph(phase_title, self.styles["subsection_title"]))
            for step in steps:
                elements.append(Paragraph(
                    f"  ▸  {step}",
                    ParagraphStyle("step", fontSize=9, fontName="Helvetica", textColor=TEXT_SECONDARY,
                                   leading=14, leftIndent=10, spaceAfter=1)
                ))
            elements.append(Spacer(1, 4*mm))

        # Outils utilisés
        elements.append(Paragraph("Outils et technologies utilisés", self.styles["subsection_title"]))
        tools = [
            ("Nmap", "Scanner réseau — détection de ports, services, OS, vulnérabilités"),
            ("python-nmap", "Interface Python pour Nmap"),
            ("dnspython", "Bibliothèque Python pour les requêtes DNS"),
            ("requests", "Client HTTP pour l'analyse des applications web"),
            ("ssl (Python stdlib)", "Analyse SSL/TLS et certificats"),
            ("python-whois", "Récupération des informations WHOIS"),
            ("NVD API v2", "Base de données nationale des vulnérabilités (NIST)"),
            ("ReportLab", "Génération des rapports PDF"),
        ]
        tools_rows = [[
            Paragraph("Outil", self.styles["table_header"]),
            Paragraph("Rôle", self.styles["table_header"]),
        ]]
        for tool, role in tools:
            tools_rows.append([
                Paragraph(tool, ParagraphStyle("tn", fontSize=8, fontName="Courier", textColor=ACCENT_CYAN)),
                Paragraph(role, self.styles["table_cell"]),
            ])
        tools_table = Table(tools_rows, colWidths=[55*mm, 120*mm])
        tools_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK_SURFACE, HexColor("#1A2030")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, TEXT_MUTED),
            ("BOX", (0, 0), (-1, -1), 1, ACCENT_BLUE),
        ]))
        elements.append(tools_table)

        elements.append(Spacer(1, 10*mm))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=TEXT_MUTED, spaceAfter=8))
        elements.append(Paragraph(
            "Ce rapport a été généré automatiquement par VulnScan Pro v1.0. "
            "Il ne remplace pas un audit de sécurité manuel complet réalisé par des experts certifiés. "
            "Les résultats doivent être validés et interprétés en contexte avant toute action corrective.",
            self.styles["disclaimer"]
        ))

        return elements

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def _get_all_findings(self) -> list:
        all_findings = []
        for module_name, module_data in self.results.get("modules", {}).items():
            if isinstance(module_data, dict):
                for finding in module_data.get("findings", []):
                    finding["_module"] = module_name
                    all_findings.append(finding)
        # Trier par sévérité
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda x: order.get(x.get("severity", "INFO"), 5))
        return all_findings

    def _count_total_findings(self) -> int:
        return len(self._get_all_findings())

    def _count_by_severity(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self._get_all_findings():
            sev = finding.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1
        return counts
