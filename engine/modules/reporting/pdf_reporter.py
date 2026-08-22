"""
reporting/pdf_reporter.py
-------------------------
Professional PDF Security Assessment Report Generator
Hybrid AI Red Team Framework

Visual identity:
- Dark charcoal + red Red Team palette matching the web dashboard
- Programmatically drawn shield logo (no external image dependency)
- Branded cover page
- Header and footer on internal pages
- Curated executive summary, vulnerability, MITRE, attack-chain,
  threat-intelligence, AI-analysis, and recommendations sections
- Safe text wrapping for long tokens and URLs
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Iterable

from fpdf import FPDF

from engine.config.settings import (
    REPORT_PDF_DIR,
    FRAMEWORK_NAME,
    FRAMEWORK_VERSION,
    REPORT_DATE_FORMAT,
    FRAMEWORK_SUBTITLE,
    UNIVERSITY,
    DEPARTMENT,
    ACADEMIC_YEAR,
    REPORT_CLASSIFICATION,
)


FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MAX_UNBROKEN_TOKEN = 55

# ---------------------------------------------------------------------
# Brand palette - aligned with the dashboard theme
# ---------------------------------------------------------------------
INK = (15, 23, 42)
CHARCOAL = (7, 9, 13)
CARD = (14, 19, 25)
CARD_ALT = (22, 28, 36)
RED = (239, 35, 60)
RED_DARK = (153, 27, 27)
RED_SOFT = (253, 232, 235)
PURPLE = (124, 58, 237)
PURPLE_SOFT = (245, 243, 255)
GREEN = (34, 197, 94)
AMBER = (245, 158, 11)
ORANGE = (255, 101, 60)
SLATE = (100, 116, 139)
SLATE_DARK = (71, 85, 105)
LIGHT_GRID = (226, 232, 240)
PANEL_BG = (248, 250, 252)
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)

SEVERITY_COLORS = {
    "critical": RED,
    "high": ORANGE,
    "medium": AMBER,
    "low": GREEN,
    "unknown": SLATE,
    "informational": SLATE,
}

RISK_BANNER_COLORS = {
    "CRITICAL": RED_DARK,
    "HIGH": (194, 65, 12),
    "MEDIUM": (161, 98, 7),
    "LOW": (21, 128, 61),
    "UNKNOWN": SLATE_DARK,
}


class BrandedPDF(FPDF):
    """FPDF subclass providing branded internal-page headers and footers."""

    def __init__(self, report_id: str = "N/A", session_id: str = "N/A"):
        super().__init__()
        self.report_id = report_id
        self.session_id = session_id
        self.cover_page_number = 1

    def header(self) -> None:
        if self.page_no() <= self.cover_page_number:
            return

        self.set_fill_color(*CHARCOAL)
        self.rect(0, 0, self.w, 21, "F")

        self._draw_mini_shield(12, 5.1, 8.2, 10.4)

        self.set_xy(23, 4.8)
        self.set_text_color(*WHITE)
        self.set_font("DejaVu", "B", 9.2)
        self.cell(0, 5, FRAMEWORK_NAME)

        self.set_xy(23, 10.4)
        self.set_text_color(190, 197, 208)
        self.set_font("DejaVu", "", 7.2)
        self.cell(0, 4, FRAMEWORK_SUBTITLE)

        label = "SECURITY ASSESSMENT REPORT"
        self.set_font("DejaVu", "B", 7.1)
        label_width = self.get_string_width(label) + 8
        self.set_xy(self.w - self.r_margin - label_width, 7.1)
        self.set_fill_color(*RED_DARK)
        self.set_text_color(*WHITE)
        self.cell(label_width, 7, label, fill=True, align="C")

        self.set_draw_color(*RED)
        self.set_line_width(0.6)
        self.line(0, 21, self.w, 21)
        self.set_y(27)

    def footer(self) -> None:
        if self.page_no() <= self.cover_page_number:
            return

        y = self.h - 15
        self.set_draw_color(*LIGHT_GRID)
        self.set_line_width(0.2)
        self.line(self.l_margin, y, self.w - self.r_margin, y)

        self.set_y(y + 3)
        self.set_text_color(*SLATE)
        self.set_font("DejaVu", "", 7)
        left = f"{UNIVERSITY} | {DEPARTMENT}"
        self.cell(95, 5, left)

        middle = f"Session: {self.session_id}"
        self.cell(55, 5, middle, align="C")

        page_label = f"Page {self.page_no() - 1}"
        self.cell(0, 5, page_label, align="R")

        self.set_y(self.h - 7.5)
        self.set_text_color(*RED_DARK)
        self.set_font("DejaVu", "B", 6.4)
        self.cell(0, 4, REPORT_CLASSIFICATION.upper(), align="C")

    def _draw_mini_shield(self, x: float, y: float, w: float, h: float) -> None:
        points = [
            (x + w / 2, y),
            (x + w, y + h * 0.18),
            (x + w * 0.88, y + h * 0.68),
            (x + w / 2, y + h),
            (x + w * 0.12, y + h * 0.68),
            (x, y + h * 0.18),
        ]
        self.set_fill_color(*RED)
        self.set_draw_color(*RED)
        self.polygon(points, style="DF")
        self.set_draw_color(*WHITE)
        self.set_line_width(0.8)
        self.line(x + w / 2, y + h * 0.25, x + w / 2, y + h * 0.62)
        self.line(x + w / 2, y + h * 0.76, x + w / 2, y + h * 0.78)


class PdfReporter:
    """Generate the branded project PDF report."""

    def save(
        self,
        report_data: dict,
        filename: str | None = None,
        output_dir: str | None = None,
    ) -> str:
        save_dir = output_dir or REPORT_PDF_DIR
        os.makedirs(save_dir, exist_ok=True)

        timestamp = datetime.now().strftime(REPORT_DATE_FORMAT)
        filename = filename or f"attack_report_{timestamp}.pdf"
        path = os.path.join(save_dir, filename)

        self._build_pdf(report_data or {}, path)
        print(f"[PDF] Report generated -> {path}")
        return path

    # -----------------------------------------------------------------
    # Build
    # -----------------------------------------------------------------

    def _build_pdf(self, data: dict, path: str) -> None:
        report_id = str(data.get("report_id") or "N/A")
        session_id = str(
            data.get("session_id")
            or data.get("scan_session_id")
            or report_id
            or "N/A"
        )

        pdf = BrandedPDF(report_id=report_id, session_id=session_id)
        pdf.set_auto_page_break(auto=True, margin=21)
        pdf.set_margins(15, 27, 15)
        pdf.add_font("DejaVu", "", FONT_PATH)
        pdf.add_font("DejaVu", "B", FONT_BOLD_PATH)
        pdf.set_title(f"{FRAMEWORK_NAME} - Security Assessment Report")
        pdf.set_author(UNIVERSITY)
        pdf.set_subject("Authorized Offensive Security Assessment")
        pdf.set_creator(FRAMEWORK_NAME)

        exec_summary = self._as_dict(data.get("executive_summary"))
        ai_analysis = self._as_dict(data.get("ai_analysis"))
        threat_intel = self._as_dict(data.get("threat_intelligence"))
        risk_summary = self._as_dict(data.get("risk_summary"))
        vulnerabilities = self._as_list(data.get("vulnerabilities"))
        mitre_analysis = self._as_dict(data.get("mitre_analysis"))
        attack_chain = data.get("attack_chain") or []

        overall_risk = str(
            exec_summary.get("overall_risk")
            or risk_summary.get("overall_risk")
            or risk_summary.get("risk_level")
            or "UNKNOWN"
        ).upper()
        risk_score = self._to_number(
            risk_summary.get("risk_score", exec_summary.get("risk_score", 0))
        )

# ============================================================
# COVER PAGE
# Disable automatic page breaking because the cover uses
# absolute positioning near the bottom edge of the page.
# ============================================================

        pdf.set_auto_page_break(auto=False)

        pdf.add_page()

        self._cover_page(
            pdf,
            data,
            report_id,
            session_id,
            overall_risk,
            risk_score,
         )

        # Restore normal pagination for report content
        pdf.set_auto_page_break(auto=True, margin=21)
        pdf.set_margins(15, 27, 15)

        pdf.add_page()
        self._section_title(pdf, "1", "Executive Summary", "Assessment posture and high-level findings")
        self._risk_banner(pdf, overall_risk, risk_score)
        self._stat_cards(pdf, exec_summary, vulnerabilities)
        self._ai_callout(
            pdf,
            title="Executive Narrative",
            text=ai_analysis.get("executive_summary", ""),
        )

        self._vulnerability_table(pdf, vulnerabilities)
        self._mitre_table(pdf, mitre_analysis)
        self._attack_chain(pdf, attack_chain)

        self._section_title(pdf, "5", "AI Technical Analysis", "AI-assisted explanation of confirmed findings")
        self._ai_callout(
            pdf,
            title="Technical Analysis",
            text=ai_analysis.get("technical_analysis", ""),
        )

        self._threat_intelligence(pdf, threat_intel)

        self._section_title(pdf, "7", "Security Recommendations", "Prioritized remediation actions")
        self._recommendations_block(pdf, ai_analysis.get("recommendations", ""))

        pdf.output(path)

    # -----------------------------------------------------------------
    # Cover
    # -----------------------------------------------------------------

    def _cover_page(
        self,
        pdf: BrandedPDF,
        data: dict,
        report_id: str,
        session_id: str,
        overall_risk: str,
        risk_score: float,
    ) -> None:
        pdf.set_margins(15, 15, 15)
        pdf.set_fill_color(*CHARCOAL)
        pdf.rect(0, 0, pdf.w, pdf.h, "F")

        # Red ambient circles
        pdf.set_fill_color(45, 10, 18)
        pdf.ellipse(pdf.w - 88, -30, 120, 120, "F")
        pdf.set_fill_color(28, 8, 13)
        pdf.ellipse(-55, pdf.h - 90, 125, 125, "F")

        # Top brand block
        self._draw_logo(pdf, 21, 21, 27, 33)
        pdf.set_xy(56, 22)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 19)
        pdf.cell(0, 9, self._clean_text(FRAMEWORK_NAME), new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(56)
        pdf.set_text_color(196, 202, 212)
        pdf.set_font("DejaVu", "", 10)
        pdf.cell(0, 7, self._clean_text(FRAMEWORK_SUBTITLE), new_x="LMARGIN", new_y="NEXT")

        pdf.set_draw_color(*RED)
        pdf.set_line_width(1)
        pdf.line(21, 62, pdf.w - 21, 62)

        # Main title
        pdf.set_y(83)
        pdf.set_text_color(*RED)
        pdf.set_font("DejaVu", "B", 10)
        pdf.cell(0, 6, "AUTHORIZED OFFENSIVE SECURITY ASSESSMENT", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(5)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 27)
        pdf.multi_cell(0, 13, "SECURITY\nASSESSMENT REPORT", align="C")

        pdf.ln(4)
        pdf.set_text_color(190, 197, 208)
        pdf.set_font("DejaVu", "", 10)
        pdf.cell(0, 7, "Graduation Project - Cyber Security Engineering", align="C", new_x="LMARGIN", new_y="NEXT")

        # Risk pill
        risk_color = RISK_BANNER_COLORS.get(overall_risk, RISK_BANNER_COLORS["UNKNOWN"])
        pill_w = 72
        pill_x = (pdf.w - pill_w) / 2
        pill_y = pdf.get_y() + 7
        pdf.set_fill_color(*risk_color)
        pdf.rect(pill_x, pill_y, pill_w, 16, "F")
        pdf.set_xy(pill_x, pill_y + 2.5)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 10)
        pdf.cell(pill_w, 6, f"{overall_risk} RISK", align="C")
        pdf.set_xy(pill_x, pill_y + 8.3)
        pdf.set_font("DejaVu", "", 7.6)
        pdf.cell(pill_w, 5, f"Risk Score: {self._format_number(risk_score)}/100", align="C")

        # Information card
        card_x = 26
        card_y = 166
        card_w = pdf.w - 52
        card_h = 61
        pdf.set_fill_color(*CARD)
        pdf.set_draw_color(48, 56, 68)
        pdf.rect(card_x, card_y, card_w, card_h, "DF")
        pdf.set_fill_color(*RED)
        pdf.rect(card_x, card_y, 4, card_h, "F")

        target = self._extract_target(data)
        generated = self._fmt_date(data.get("generated_at", datetime.now().isoformat()))
        rows = [
            ("Target / Scope", target),
            ("Report ID", report_id),
            ("Session ID", session_id),
            ("Generated", generated),
            ("Framework Version", FRAMEWORK_VERSION),
        ]

        y = card_y + 8
        for label, value in rows:
            pdf.set_xy(card_x + 12, y)
            pdf.set_text_color(149, 158, 171)
            pdf.set_font("DejaVu", "", 8.2)
            pdf.cell(42, 6, label.upper())
            pdf.set_text_color(*WHITE)
            pdf.set_font("DejaVu", "B", 8.8)
            pdf.cell(card_w - 58, 6, self._truncate(value, card_w - 58))
            y += 10

        # Academic footer area
        pdf.set_y(243)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 10)
        pdf.cell(0, 6, UNIVERSITY, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(180, 187, 198)
        pdf.set_font("DejaVu", "", 8.6)
        pdf.cell(0, 5, f"{DEPARTMENT} | Academic Year {ACADEMIC_YEAR}", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(271)
        pdf.set_text_color(*RED)
        pdf.set_font("DejaVu", "B", 7.4)
        pdf.cell(0, 5, REPORT_CLASSIFICATION.upper(), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(145, 153, 165)
        pdf.set_font("DejaVu", "", 6.9)
        pdf.cell(
            0,
            5,
            "This report documents an authorized academic security assessment. Use is limited to the approved scope.",
            align="C",
        )

        pdf.set_margins(15, 27, 15)

    def _draw_logo(self, pdf: FPDF, x: float, y: float, w: float, h: float) -> None:
        # Outer shield
        points = [
            (x + w / 2, y),
            (x + w, y + h * 0.16),
            (x + w * 0.9, y + h * 0.66),
            (x + w / 2, y + h),
            (x + w * 0.1, y + h * 0.66),
            (x, y + h * 0.16),
        ]
        pdf.set_fill_color(*RED)
        pdf.set_draw_color(*RED)
        pdf.polygon(points, style="DF")

        # Inner shield
        inset = 3.4
        inner = [
            (x + w / 2, y + inset),
            (x + w - inset, y + h * 0.2),
            (x + w * 0.83, y + h * 0.62),
            (x + w / 2, y + h - inset),
            (x + w * 0.17, y + h * 0.62),
            (x + inset, y + h * 0.2),
        ]
        pdf.set_fill_color(*CHARCOAL)
        pdf.polygon(inner, style="F")

        # Alert mark
        pdf.set_draw_color(*RED)
        pdf.set_line_width(2)
        pdf.line(x + w / 2, y + h * 0.28, x + w / 2, y + h * 0.62)
        pdf.set_fill_color(*RED)
        pdf.ellipse(x + w / 2 - 1.2, y + h * 0.72, 2.4, 2.4, "F")

    # -----------------------------------------------------------------
    # Section title
    # -----------------------------------------------------------------

    def _section_title(self, pdf: FPDF, number: str, title: str, subtitle: str = "") -> None:
        self._ensure_space(pdf, 26)
        pdf.ln(2)
        x = pdf.l_margin
        y = pdf.get_y()

        pdf.set_fill_color(*RED)
        pdf.rect(x, y, 12, 12, "F")
        pdf.set_xy(x, y + 1.3)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 9)
        pdf.cell(12, 9, number, align="C")

        pdf.set_xy(x + 17, y)
        pdf.set_text_color(*INK)
        pdf.set_font("DejaVu", "B", 14)
        pdf.cell(0, 7, self._clean_text(title), new_x="LMARGIN", new_y="NEXT")

        if subtitle:
            pdf.set_x(x + 17)
            pdf.set_text_color(*SLATE)
            pdf.set_font("DejaVu", "", 7.8)
            pdf.cell(0, 5, self._clean_text(subtitle), new_x="LMARGIN", new_y="NEXT")

        pdf.set_draw_color(*LIGHT_GRID)
        pdf.set_line_width(0.3)
        line_y = y + 15
        pdf.line(x, line_y, pdf.w - pdf.r_margin, line_y)
        pdf.set_y(line_y + 5)

    # -----------------------------------------------------------------
    # Executive summary
    # -----------------------------------------------------------------

    def _risk_banner(self, pdf: FPDF, overall_risk: str, risk_score: float) -> None:
        color = RISK_BANNER_COLORS.get(overall_risk, RISK_BANNER_COLORS["UNKNOWN"])
        x = pdf.l_margin
        y = pdf.get_y()
        w = pdf.w - pdf.l_margin - pdf.r_margin
        h = 24

        pdf.set_fill_color(*color)
        pdf.rect(x, y, w, h, "F")
        pdf.set_fill_color(*WHITE)
        pdf.rect(x + 5, y + 5, 3, 14, "F")

        pdf.set_xy(x + 13, y + 4.2)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 14)
        pdf.cell(88, 7, f"OVERALL RISK: {overall_risk}")

        pdf.set_xy(x + 13, y + 12.3)
        pdf.set_font("DejaVu", "", 7.8)
        pdf.cell(88, 5, "Rule-based security posture derived from confirmed findings")

        pdf.set_xy(x + w - 45, y + 4)
        pdf.set_font("DejaVu", "B", 18)
        pdf.cell(35, 8, self._format_number(risk_score), align="R")
        pdf.set_xy(x + w - 45, y + 13)
        pdf.set_font("DejaVu", "", 7.6)
        pdf.cell(35, 5, "OUT OF 100", align="R")

        pdf.set_text_color(*INK)
        pdf.set_y(y + h + 7)

    def _stat_cards(self, pdf: FPDF, exec_summary: dict, vulnerabilities: list) -> None:
        breakdown = self._as_dict(exec_summary.get("severity_breakdown"))
        if not breakdown and vulnerabilities:
            breakdown = self._severity_breakdown(vulnerabilities)

        total = self._to_int(exec_summary.get("total_findings"), default=len(vulnerabilities))
        cards = [
            ("TOTAL", total, INK),
            ("CRITICAL", breakdown.get("critical", 0), RED),
            ("HIGH", breakdown.get("high", 0), ORANGE),
            ("MEDIUM", breakdown.get("medium", 0), AMBER),
            ("LOW", breakdown.get("low", 0), GREEN),
        ]

        total_w = pdf.w - pdf.l_margin - pdf.r_margin
        gap = 3.2
        card_w = (total_w - gap * 4) / 5
        y = pdf.get_y()
        h = 25

        for index, (label, value, color) in enumerate(cards):
            x = pdf.l_margin + index * (card_w + gap)
            pdf.set_fill_color(*PANEL_BG)
            pdf.set_draw_color(*LIGHT_GRID)
            pdf.rect(x, y, card_w, h, "DF")
            pdf.set_fill_color(*color)
            pdf.rect(x, y, card_w, 2.2, "F")

            pdf.set_xy(x, y + 4.4)
            pdf.set_text_color(*color)
            pdf.set_font("DejaVu", "B", 15)
            pdf.cell(card_w, 8, str(value), align="C")

            pdf.set_xy(x, y + 14.5)
            pdf.set_text_color(*SLATE)
            pdf.set_font("DejaVu", "B", 7)
            pdf.cell(card_w, 5, label, align="C")

        pdf.set_text_color(*INK)
        pdf.set_y(y + h + 8)

    # -----------------------------------------------------------------
    # AI blocks / recommendations
    # -----------------------------------------------------------------

    def _ai_callout(self, pdf: FPDF, title: str, text: Any) -> None:
        text = self._normalize_narrative(text)
        unavailable = not text or "unavailable" in text.lower()
        display = (
            "AI narrative was not available for this run. The rule-based findings and scores in this report remain valid."
            if unavailable
            else text
        )

        estimated = self._estimate_multicell_height(pdf, display, 6, pdf.w - pdf.l_margin - pdf.r_margin - 20)
        block_h = max(32, estimated + 19)
        self._ensure_space(pdf, min(block_h, 75))

        x = pdf.l_margin
        y = pdf.get_y()
        w = pdf.w - pdf.l_margin - pdf.r_margin

        bg = PANEL_BG if unavailable else PURPLE_SOFT
        accent = SLATE if unavailable else PURPLE
        pdf.set_fill_color(*bg)
        pdf.set_draw_color(*LIGHT_GRID)
        pdf.rect(x, y, w, block_h, "DF")
        pdf.set_fill_color(*accent)
        pdf.rect(x, y, 4, block_h, "F")

        pdf.set_xy(x + 9, y + 5)
        pdf.set_text_color(*accent)
        pdf.set_font("DejaVu", "B", 9.3)
        pdf.cell(0, 6, self._clean_text(title), new_x="LMARGIN", new_y="NEXT")

        pdf.set_xy(x + 9, y + 13)
        pdf.set_text_color(*SLATE_DARK)
        pdf.set_font("DejaVu", "", 9)
        self._safe_multicell(pdf, display, height=5.6, width=w - 18, left=x + 9)
        pdf.set_y(y + block_h + 6)
        pdf.set_text_color(*INK)

    def _recommendations_block(self, pdf: FPDF, value: Any) -> None:
        recommendations = self._normalize_recommendations(value)
        if not recommendations:
            self._empty_note(
                pdf,
                "AI recommendations were not available for this run. Review the confirmed findings and apply vendor remediation guidance.",
            )
            return

        for index, recommendation in enumerate(recommendations, start=1):
            estimated = self._estimate_multicell_height(pdf, recommendation, 5.4, 155)
            row_h = max(16, estimated + 7)
            self._ensure_space(pdf, row_h + 3)

            x = pdf.l_margin
            y = pdf.get_y()
            w = pdf.w - pdf.l_margin - pdf.r_margin

            pdf.set_fill_color(*PANEL_BG)
            pdf.set_draw_color(*LIGHT_GRID)
            pdf.rect(x, y, w, row_h, "DF")

            pdf.set_fill_color(*RED)
            pdf.rect(x + 5, y + 4, 9, 9, "F")
            pdf.set_xy(x + 5, y + 4.6)
            pdf.set_text_color(*WHITE)
            pdf.set_font("DejaVu", "B", 7.6)
            pdf.cell(9, 7, str(index), align="C")

            pdf.set_text_color(*INK)
            pdf.set_font("DejaVu", "", 8.8)
            pdf.set_xy(x + 19, y + 4)
            self._safe_multicell(pdf, recommendation, height=5.4, width=w - 24, left=x + 19)
            pdf.set_y(y + row_h + 3)

    # -----------------------------------------------------------------
    # Vulnerabilities
    # -----------------------------------------------------------------

    def _vulnerability_table(self, pdf: FPDF, findings: list) -> None:
        self._section_title(pdf, "2", "Key Vulnerability Findings", "Highest-priority confirmed security weaknesses")

        if not findings:
            self._empty_note(pdf, "No vulnerabilities were detected in the current assessment.")
            return

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranked = sorted(
            findings,
            key=lambda item: (
                order.get(str(item.get("severity", "unknown")).lower(), 9),
                -self._to_number(item.get("risk_score", item.get("threat_score", 0))),
            ),
        )[:12]

        headers = ["Severity", "CVE / CWE", "Asset", "CVSS", "Finding"]
        widths = [24, 31, 38, 16, 81]
        self._table_header(pdf, headers, widths)

        for index, item in enumerate(ranked):
            self._ensure_space(pdf, 9)
            row_h = 9
            x = pdf.l_margin
            y = pdf.get_y()
            fill = PANEL_BG if index % 2 == 0 else WHITE
            pdf.set_fill_color(*fill)
            pdf.rect(x, y, sum(widths), row_h, "F")

            severity = str(item.get("severity", "unknown"))
            self._severity_badge(pdf, x, y, widths[0], row_h, severity)

            pdf.set_xy(x + widths[0], y)
            pdf.set_text_color(*INK)
            pdf.set_font("DejaVu", "", 7.9)
            pdf.set_draw_color(*LIGHT_GRID)
            identifier = item.get("cve") or item.get("cwe_id") or item.get("vulnerability_id") or "-"
            asset = f"{item.get('host', '-') }:{item.get('port', '-') }"
            cvss = item.get("cvss_live", item.get("cvss", "-"))
            title = item.get("vulnerability") or item.get("edb_title") or item.get("title") or "-"

            pdf.cell(widths[1], row_h, self._truncate(identifier, widths[1]), border="B")
            pdf.cell(widths[2], row_h, self._truncate(asset, widths[2]), border="B")
            pdf.cell(widths[3], row_h, self._truncate(cvss, widths[3]), border="B", align="C")
            pdf.cell(widths[4], row_h, self._truncate(title, widths[4]), border="B")
            pdf.ln(row_h)

        if len(findings) > len(ranked):
            pdf.set_text_color(*SLATE)
            pdf.set_font("DejaVu", "", 7.8)
            pdf.cell(
                0,
                7,
                f"+ {len(findings) - len(ranked)} additional finding(s) are available in the JSON report.",
                new_x="LMARGIN",
                new_y="NEXT",
            )

        pdf.set_text_color(*INK)
        pdf.ln(4)

    # -----------------------------------------------------------------
    # MITRE
    # -----------------------------------------------------------------

    def _mitre_table(self, pdf: FPDF, mitre_analysis: dict) -> None:
        self._section_title(pdf, "3", "MITRE ATT&CK Mapping", "Adversary techniques mapped from confirmed evidence")

        raw = self._as_list(mitre_analysis.get("techniques"))
        techniques = self._deduplicate_techniques(raw)
        if not techniques:
            self._empty_note(pdf, "No MITRE ATT&CK techniques were mapped.")
            return

        coverage = mitre_analysis.get("coverage_percentage", 0)
        summary = (
            f"{len(techniques)} unique technique(s) | "
            f"{mitre_analysis.get('total_tactics', mitre_analysis.get('tactics_covered', '-'))} tactic(s) | "
            f"{coverage}% ATT&CK coverage"
        )
        self._small_summary_strip(pdf, summary)

        headers = ["Technique", "Tactic", "Confidence", "Source"]
        widths = [79, 47, 29, 35]
        self._table_header(pdf, headers, widths)

        for index, tech in enumerate(techniques[:20]):
            self._ensure_space(pdf, 9)
            row_h = 9
            x = pdf.l_margin
            y = pdf.get_y()
            pdf.set_fill_color(*(PANEL_BG if index % 2 == 0 else WHITE))
            pdf.rect(x, y, sum(widths), row_h, "F")

            tid = tech.get("technique_id") or tech.get("techniqueID") or "-"
            name = tech.get("technique_name") or tech.get("name") or ""
            label = f"{tid} - {name}" if name else str(tid)
            tactic = str(tech.get("tactic", "-")).replace("-", " ").replace("_", " ").title()
            confidence = self._format_confidence(tech.get("confidence", "-"))
            source = tech.get("source", "-")

            pdf.set_xy(x, y)
            pdf.set_text_color(*INK)
            pdf.set_font("DejaVu", "", 7.9)
            pdf.cell(widths[0], row_h, self._truncate(label, widths[0]), border="B")
            pdf.cell(widths[1], row_h, self._truncate(tactic, widths[1]), border="B")
            pdf.cell(widths[2], row_h, self._truncate(confidence, widths[2]), border="B", align="C")
            pdf.cell(widths[3], row_h, self._truncate(source, widths[3]), border="B")
            pdf.ln(row_h)

        pdf.ln(4)

    # -----------------------------------------------------------------
    # Attack chain
    # -----------------------------------------------------------------

    def _attack_chain(self, pdf: FPDF, attack_chain: Any) -> None:
        self._section_title(pdf, "4", "Attack Chain", "Ordered adversary phases and mapped techniques")
        phases = self._normalize_chain(attack_chain)

        if not phases:
            self._empty_note(pdf,     "No successful attack-chain phases were established during this assessment. "
    "MITRE ATT&CK mappings may still represent observed or attempted techniques.")
            return

        for index, phase in enumerate(phases, start=1):
            detail = phase.get("detail", "")
            estimated = self._estimate_multicell_height(pdf, detail, 5.1, 160) if detail else 0
            block_h = max(19, estimated + 15)
            self._ensure_space(pdf, block_h + 4)

            x = pdf.l_margin
            y = pdf.get_y()
            w = pdf.w - pdf.l_margin - pdf.r_margin

            pdf.set_fill_color(*PANEL_BG)
            pdf.set_draw_color(*LIGHT_GRID)
            pdf.rect(x + 14, y, w - 14, block_h, "DF")
            pdf.set_fill_color(*RED)
            pdf.ellipse(x, y + 2, 10, 10, "F")
            pdf.set_xy(x, y + 3)
            pdf.set_text_color(*WHITE)
            pdf.set_font("DejaVu", "B", 7.5)
            pdf.cell(10, 7, str(index), align="C")

            if index < len(phases):
                pdf.set_draw_color(*RED)
                pdf.set_line_width(0.7)
                pdf.line(x + 5, y + 12, x + 5, y + block_h + 4)

            pdf.set_xy(x + 20, y + 4)
            pdf.set_text_color(*INK)
            pdf.set_font("DejaVu", "B", 9.5)
            pdf.cell(0, 6, self._clean_text(phase.get("title", "Phase")), new_x="LMARGIN", new_y="NEXT")

            if detail:
                pdf.set_text_color(*SLATE_DARK)
                pdf.set_font("DejaVu", "", 8.3)
                pdf.set_xy(x + 20, y + 11)
                self._safe_multicell(pdf, detail, height=5.1, width=w - 27, left=x + 20)

            pdf.set_y(y + block_h + 4)

        pdf.ln(2)

    # -----------------------------------------------------------------
    # Threat intelligence
    # -----------------------------------------------------------------

    def _threat_intelligence(self, pdf: FPDF, threat_intel: dict) -> None:
        self._section_title(pdf, "6", "Threat Intelligence", "External exploitation and exposure context")

        actors = self._as_list(threat_intel.get("threat_actors"))
        stats = [
            ("Known Exploited", "KEV", threat_intel.get("kev_count", 0), RED),
            ("High Exploit Probability", "EPSS >= 0.4", threat_intel.get("high_epss_count", 0), ORANGE),
            ("End-of-Life Components", "EOL", threat_intel.get("eol_count", 0), AMBER),
            ("Threat Actors Matched", "Actors", len(actors), PURPLE),
        ]
        self._mini_metric_cards(pdf, stats)

        if actors:
            self._small_summary_strip(pdf, "Matched threat actors: " + ", ".join(str(actor) for actor in actors))

        top = self._as_list(threat_intel.get("top_ti_findings"))
        if not top:
            return

        pdf.set_font("DejaVu", "B", 9.5)
        pdf.set_text_color(*INK)
        pdf.cell(0, 7, "Top Findings by Exploit Probability (EPSS)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

        headers = ["Asset", "Severity", "CVSS", "EPSS", "KEV"]
        widths = [57, 35, 28, 32, 38]
        self._table_header(pdf, headers, widths)

        for index, finding in enumerate(top[:8]):
            if not isinstance(finding, dict):
                continue
            self._ensure_space(pdf, 9)
            row_h = 9
            x = pdf.l_margin
            y = pdf.get_y()
            pdf.set_fill_color(*(PANEL_BG if index % 2 == 0 else WHITE))
            pdf.rect(x, y, sum(widths), row_h, "F")

            asset = f"{finding.get('host', '-')}:{finding.get('port', '-')}"
            severity = str(finding.get("severity", "unknown"))
            cvss = finding.get("cvss_live", finding.get("cvss", "-"))
            epss = self._format_epss(finding.get("epss", "-"))

            pdf.set_xy(x, y)
            pdf.set_text_color(*INK)
            pdf.set_font("DejaVu", "", 7.9)
            pdf.cell(widths[0], row_h, self._truncate(asset, widths[0]), border="B")
            self._severity_badge(pdf, x + widths[0], y, widths[1], row_h, severity)
            pdf.set_xy(x + widths[0] + widths[1], y)
            pdf.cell(widths[2], row_h, self._truncate(cvss, widths[2]), border="B", align="C")
            pdf.cell(widths[3], row_h, epss, border="B", align="C")
            pdf.cell(widths[4], row_h, "YES" if finding.get("in_kev") else "NO", border="B", align="C")
            pdf.ln(row_h)

        pdf.ln(4)

    # -----------------------------------------------------------------
    # Shared visual helpers
    # -----------------------------------------------------------------

    def _table_header(self, pdf: FPDF, headers: list[str], widths: list[float]) -> None:
        self._ensure_space(pdf, 10)
        pdf.set_x(pdf.l_margin)
        pdf.set_fill_color(*CHARCOAL)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 7.7)
        for header, width in zip(headers, widths):
            pdf.cell(width, 9, self._clean_text(header), fill=True)
        pdf.ln(9)
        pdf.set_text_color(*INK)

    def _severity_badge(self, pdf: FPDF, x: float, y: float, w: float, h: float, severity: str) -> None:
        severity = (severity or "unknown").lower()
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])
        pdf.set_fill_color(*color)
        pdf.rect(x + 2, y + 1.5, w - 4, h - 3, "F")
        pdf.set_xy(x, y)
        pdf.set_text_color(*WHITE)
        pdf.set_font("DejaVu", "B", 6.9)
        pdf.cell(w, h, severity.upper(), align="C")
        pdf.set_text_color(*INK)

    def _mini_metric_cards(self, pdf: FPDF, items: list[tuple]) -> None:
        total_w = pdf.w - pdf.l_margin - pdf.r_margin
        gap = 4
        card_w = (total_w - gap * (len(items) - 1)) / len(items)
        y = pdf.get_y()
        h = 31

        for index, (title, label, value, color) in enumerate(items):
            x = pdf.l_margin + index * (card_w + gap)
            pdf.set_fill_color(*PANEL_BG)
            pdf.set_draw_color(*LIGHT_GRID)
            pdf.rect(x, y, card_w, h, "DF")
            pdf.set_fill_color(*color)
            pdf.rect(x, y, card_w, 2.2, "F")

            pdf.set_xy(x, y + 4.5)
            pdf.set_text_color(*color)
            pdf.set_font("DejaVu", "B", 15)
            pdf.cell(card_w, 7, str(value), align="C")
            pdf.set_xy(x, y + 13)
            pdf.set_text_color(*INK)
            pdf.set_font("DejaVu", "B", 6.7)
            pdf.cell(card_w, 5, self._truncate(title, card_w), align="C")
            pdf.set_xy(x, y + 20)
            pdf.set_text_color(*SLATE)
            pdf.set_font("DejaVu", "", 6.3)
            pdf.cell(card_w, 4, str(label), align="C")

        pdf.set_text_color(*INK)
        pdf.set_y(y + h + 7)

    def _small_summary_strip(self, pdf: FPDF, text: str) -> None:
        self._ensure_space(pdf, 14)
        x = pdf.l_margin
        y = pdf.get_y()
        w = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_fill_color(*RED_SOFT)
        pdf.set_draw_color(252, 190, 198)
        pdf.rect(x, y, w, 12, "DF")
        pdf.set_fill_color(*RED)
        pdf.rect(x, y, 3, 12, "F")
        pdf.set_xy(x + 8, y + 2.4)
        pdf.set_text_color(*RED_DARK)
        pdf.set_font("DejaVu", "B", 7.8)
        pdf.cell(w - 12, 7, self._truncate(text, w - 12))
        pdf.set_y(y + 16)
        pdf.set_text_color(*INK)

    def _empty_note(self, pdf: FPDF, text: str) -> None:
        self._ensure_space(pdf, 22)
        x = pdf.l_margin
        y = pdf.get_y()
        w = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_fill_color(*PANEL_BG)
        pdf.set_draw_color(*LIGHT_GRID)
        pdf.rect(x, y, w, 18, "DF")
        pdf.set_fill_color(*SLATE)
        pdf.ellipse(x + 7, y + 6, 5, 5, "F")
        pdf.set_xy(x + 17, y + 4.5)
        pdf.set_text_color(*SLATE_DARK)
        pdf.set_font("DejaVu", "", 8.5)
        pdf.cell(w - 22, 8, self._clean_text(text))
        pdf.set_y(y + 23)
        pdf.set_text_color(*INK)

    # -----------------------------------------------------------------
    # Safe text output
    # -----------------------------------------------------------------

    def _safe_multicell(
        self,
        pdf: FPDF,
        text: Any,
        height: float = 6,
        width: float | None = None,
        left: float | None = None,
        font_size: float | None = None,
        bold: bool = False,
    ) -> None:
        if font_size is not None:
            pdf.set_font("DejaVu", "B" if bold else "", font_size)

        cleaned = self._clean_text(text)
        if not cleaned.strip():
            return

        usable_width = width or (pdf.w - pdf.l_margin - pdf.r_margin)
        start_x = left if left is not None else pdf.l_margin

        for line in cleaned.split("\n"):
            if not line.strip():
                pdf.ln(height / 2)
                continue
            pdf.set_x(start_x)
            try:
                pdf.multi_cell(usable_width, height, line)
            except Exception:
                for chunk in self._hard_wrap(line, 38):
                    pdf.set_x(start_x)
                    pdf.multi_cell(usable_width, height, chunk)

    def _estimate_multicell_height(self, pdf: FPDF, text: Any, line_h: float, width: float) -> float:
        cleaned = self._clean_text(text)
        if not cleaned:
            return line_h
        try:
            lines = pdf.multi_cell(width, line_h, cleaned, dry_run=True, output="LINES")
            return max(line_h, len(lines) * line_h)
        except Exception:
            approximate_chars = max(int(width / 1.8), 20)
            line_count = 0
            for paragraph in cleaned.split("\n"):
                line_count += max(1, (len(paragraph) // approximate_chars) + 1)
            return line_count * line_h

    def _ensure_space(self, pdf: FPDF, required_height: float) -> None:
        bottom_limit = pdf.h - pdf.b_margin
        if pdf.get_y() + required_height > bottom_limit:
            pdf.add_page()

    # -----------------------------------------------------------------
    # Normalization helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _as_dict(value: Any) -> dict:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_list(value: Any) -> list:
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        return []

    @staticmethod
    def _to_number(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _to_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _format_number(value: Any) -> str:
        try:
            number = float(value)
            return str(int(number)) if number.is_integer() else f"{number:.1f}"
        except (TypeError, ValueError):
            return "0"

    @staticmethod
    def _severity_breakdown(findings: list) -> dict:
        result = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "")).lower()
            if severity in result:
                result[severity] += 1
        return result

    @staticmethod
    def _normalize_narrative(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, dict):
            return str(value.get("text") or value.get("content") or value.get("summary") or "").strip()
        return str(value).strip()

    @staticmethod
    def _normalize_recommendations(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            output = []
            for item in value:
                if isinstance(item, str):
                    text = item.strip()
                elif isinstance(item, dict):
                    text = str(item.get("recommendation") or item.get("text") or "").strip()
                else:
                    text = str(item).strip()
                if text:
                    output.append(text)
            return output
        if isinstance(value, str):
            lines = re.split(r"\n+", value)
            output = []
            for line in lines:
                cleaned = re.sub(r"^\s*(?:\d+[.)]|[-*•])\s*", "", line).strip()
                if cleaned:
                    output.append(cleaned)
            return output
        return []

    @staticmethod
    def _hard_wrap(text: str, chunk_size: int) -> list[str]:
        return [text[index:index + chunk_size] for index in range(0, len(text), chunk_size)] or [""]

    def _deduplicate_techniques(self, techniques: list) -> list:
        seen: set[tuple[str, str]] = set()
        output = []
        for technique in techniques:
            if not isinstance(technique, dict):
                continue
            tid = str(technique.get("technique_id") or technique.get("techniqueID") or "").strip()
            tactic = str(technique.get("tactic") or "").strip().lower()
            key = (tid, tactic)
            if not tid or key in seen:
                continue
            seen.add(key)
            output.append(technique)
        return output

    def _normalize_chain(self, attack_chain: Any) -> list[dict]:
        if isinstance(attack_chain, dict):
            raw = attack_chain.get("phases")
            if isinstance(raw, dict):
                items = list(raw.values())
            elif isinstance(raw, list):
                items = raw
            else:
                items = [value for value in attack_chain.values() if isinstance(value, (dict, str))]
        elif isinstance(attack_chain, list):
            items = attack_chain
        else:
            return []

        phases = []
        for item in items:
            if not isinstance(item, dict):
                phases.append({"title": str(item), "detail": ""})
                continue

            title = item.get("phase_name") or item.get("phase") or item.get("name") or "Phase"
            detail_parts = []
            tactic = item.get("tactic") or item.get("mitre_tactic")
            if tactic:
                detail_parts.append(f"Tactic: {str(tactic).replace('_', ' ').replace('-', ' ').title()}")

            techniques = item.get("techniques")
            if isinstance(techniques, dict):
                techniques = list(techniques.values())
            if isinstance(techniques, list):
                for technique in techniques:
                    if isinstance(technique, str):
                        detail_parts.append(technique)
                    elif isinstance(technique, dict):
                        tid = technique.get("technique_id") or technique.get("techniqueID") or technique.get("id") or ""
                        name = technique.get("technique_name") or technique.get("name") or ""
                        label = f"{tid} {name}".strip()
                        if label:
                            detail_parts.append(label)
            elif item.get("technique_id"):
                detail_parts.append(
                    f"{item.get('technique_id')} {item.get('action', '')}".strip()
                )

            phases.append({"title": str(title), "detail": " | ".join(detail_parts)})
        return phases

    def _extract_target(self, data: dict) -> str:
        candidates = [
            data.get("target"),
            data.get("scope"),
            self._as_dict(data.get("executive_summary")).get("scope"),
            self._as_dict(data.get("risk_summary")).get("scope"),
        ]
        for value in candidates:
            if isinstance(value, list):
                return ", ".join(str(item) for item in value) or "N/A"
            if value:
                return str(value)
        vulnerabilities = self._as_list(data.get("vulnerabilities"))
        hosts = []
        for item in vulnerabilities:
            if isinstance(item, dict) and item.get("host"):
                host = str(item.get("host"))
                if host not in hosts:
                    hosts.append(host)
        return ", ".join(hosts) if hosts else "N/A"

    @staticmethod
    def _format_confidence(value: Any) -> str:
        if value in (None, "", "-"):
            return "-"
        try:
            number = float(str(value).replace("%", ""))
            if number <= 1:
                number *= 100
            return f"{round(number)}%"
        except (TypeError, ValueError):
            return str(value)

    @staticmethod
    def _format_epss(value: Any) -> str:
        if value in (None, "", "-"):
            return "-"
        try:
            number = float(value)
            if number <= 1:
                return f"{number * 100:.1f}%"
            return f"{number:.1f}%"
        except (TypeError, ValueError):
            return str(value)

    def _truncate(self, value: Any, width_mm: float) -> str:
        text = self._clean_text(value)
        max_chars = max(int(width_mm / 1.85), 3)
        if len(text) > max_chars:
            return text[: max_chars - 1] + "..."
        return text

    @staticmethod
    def _fmt_date(value: Any) -> str:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return dt.strftime("%d %B %Y - %H:%M")
        except Exception:
            return str(value)

    def _clean_text(self, text: Any) -> str:
        value = "" if text is None else str(text)
        replacements = {
            "\u2014": "-",
            "\u2013": "-",
            "\u201c": '"',
            "\u201d": '"',
            "\u2018": "'",
            "\u2019": "'",
            "\u2192": "->",
            "\u2022": "-",
            "\u2026": "...",
        }
        for old, new in replacements.items():
            value = value.replace(old, new)

        value = "".join(
            character
            for character in value
            if character in "\n\t" or ord(character) >= 32
        )

        def break_long_word(match: re.Match) -> str:
            word = match.group(0)
            return " ".join(
                word[index:index + MAX_UNBROKEN_TOKEN]
                for index in range(0, len(word), MAX_UNBROKEN_TOKEN)
            )

        return re.sub(
            rf"\S{{{MAX_UNBROKEN_TOKEN + 1},}}",
            break_long_word,
            value,
        )
