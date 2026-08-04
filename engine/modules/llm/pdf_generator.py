"""
reporting/report_generator.py
-------------------------------
Orchestrates all report sections into a single unified report.
"""

import os
from datetime import datetime

from engine.modules.reporting.executive_report import ExecutiveReport
from engine.modules.reporting.mitre_report import MitreReport
from engine.modules.reporting.threat_report import ThreatReport
from engine.modules.reporting.json_reporter import JsonReporter
from engine.modules.reporting.pdf_reporter import PdfReporter

from engine.modules.llm.report_writer import ReportWriter

from engine.config.settings import REPORT_DATE_FORMAT


class ReportGenerator:

    def __init__(self):

        self._exec = ExecutiveReport()
        self._mitre = MitreReport()
        self._threat = ThreatReport()

        self._json = JsonReporter()
        self._pdf = PdfReporter()

        # LLM Report Assistant
        self._llm = ReportWriter()


    def generate(
        self,
        scan_results: dict,
        findings: list[dict],
        mapped_results: list[dict],
        attack_chain: dict,
        risk_summary: dict,
        coverage: dict,
        formats: list[str] | None = None,
        output_dir: str = "reports"
    ) -> dict:


        formats = formats or ["json"]

        ts = datetime.now().strftime(REPORT_DATE_FORMAT)

        os.makedirs(output_dir, exist_ok=True)



        # =========================
        # LLM ANALYSIS
        # (rule-based engine already decided everything below;
        #  the LLM only phrases it — see report_writer.py)
        # =========================

        ai_report = self._llm.generate_full_report(
            findings=findings,
            mapped_results=mapped_results,
            attack_chain=attack_chain,
            risk_summary=risk_summary
        )



        # =========================
        # BUILD REPORT
        # =========================

        report = {

            "report_id":
                f"REPORT_{ts}",


            "generated_at":
                datetime.now().isoformat(),



            "executive_summary":
                self._exec.build(
                    scan_results,
                    findings,
                    attack_chain,
                    risk_summary
                ),



            "ai_analysis": {

                "executive_summary":
                    ai_report.get("executive_summary", ""),

                "technical_analysis":
                    ai_report.get("technical_analysis", ""),

                "recommendations":
                    ai_report.get("recommendations", "")
            },



            "threat_intelligence":
                self._threat.build(findings),



            "mitre_analysis":
                self._mitre.build(
                    mapped_results,
                    attack_chain,
                    coverage
                ),



            "attack_chain":
                attack_chain,



            "vulnerabilities":
                findings,



            "risk_summary":
                risk_summary,

        }



        # =========================
        # SAVE REPORTS
        # =========================

        saved = {}



        if "json" in formats:

            saved["json"] = self._json.save(
                report,
                f"attack_report_{ts}.json",
                output_dir
            )



        if "pdf" in formats:

            saved["pdf"] = self._pdf.save(
                report,
                f"attack_report_{ts}.pdf",
                output_dir
            )



        report["saved_files"] = saved



        print(
            f"\n  [Report] Generated: {list(saved.values())}"
        )



        return report
