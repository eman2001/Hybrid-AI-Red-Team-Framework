"""
report_writer.py
------------------
The "brain" of AI report writing.

Pipeline:
    JSON findings (rule-based engine, already decided)
        -> summary_builder   (condenses + selects what matters)
        -> prompts           (structures it into an instruction)
        -> llm_engine         (Qwen2.5 via Ollama — phrasing only)
        -> executive_summary / technical_analysis / recommendations

IMPORTANT: this module NEVER decides severity, priority, or which
techniques matter — that was already decided by the rule-based engine
upstream (risk_engine, mitre engine, threat_intelligence). The LLM here
only explains and phrases what it's handed.
"""

import logging

from engine.modules.llm.llm_engine import LLMEngine
from engine.modules.llm.prompts import (
    SYSTEM_PROMPT,
    EXECUTIVE_PROMPT,
    TECHNICAL_PROMPT,
    RECOMMENDATION_PROMPT,
)
from engine.modules.llm.summary_builder import (
    build_findings_summary,
    build_mitre_summary,
    build_risk_summary,
    build_attack_chain_summary,
)

logger = logging.getLogger(__name__)


class ReportWriter:

    def __init__(self, llm: LLMEngine = None):
        self.llm = llm or LLMEngine()

    # ------------------------------------------------------------------
    # Main entry point — used by ReportGenerator
    # ------------------------------------------------------------------
    def generate_full_report(
        self,
        findings: list[dict],
        mapped_results: list[dict],
        attack_chain,
        risk_summary: dict,
    ) -> dict:
        """
        Returns:
            {
                "executive_summary":  str,
                "technical_analysis": str,
                "recommendations":    str,
            }
        """
        findings_summary = build_findings_summary(findings)
        mitre_summary     = build_mitre_summary(mapped_results)
        risk              = build_risk_summary(risk_summary)
        chain_summary     = build_attack_chain_summary(attack_chain)

        print("  [LLM] Generating executive summary...")
        executive_summary = self._executive_summary(
            risk, findings_summary, mitre_summary, chain_summary
        )
        print("  [LLM] Executive summary done.")

        print(f"  [LLM] Generating technical analysis for {min(len(mitre_summary), 5)} technique(s)...")
        technical_analysis = self._technical_analysis(mitre_summary)
        print("  [LLM] Technical analysis done.")

        print("  [LLM] Generating recommendations...")
        recommendations = self._recommendations(findings_summary, risk)
        print("  [LLM] Recommendations done.")

        return {
            "executive_summary": executive_summary,
            "technical_analysis": technical_analysis,
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # Backwards-compatible shortcuts (in case other code calls these
    # directly instead of generate_full_report)
    # ------------------------------------------------------------------
    def generate_summary(self, findings, attack_chain, risk_summary):
        findings_summary = build_findings_summary(findings)
        risk = build_risk_summary(risk_summary)
        chain_summary = build_attack_chain_summary(attack_chain)
        return self._executive_summary(risk, findings_summary, [], chain_summary)

    def generate_recommendations(self, findings):
        findings_summary = build_findings_summary(findings)
        return self._recommendations(findings_summary, risk={})

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------
    def _executive_summary(self, risk, findings_summary, mitre_summary, chain_summary) -> str:
        prompt = EXECUTIVE_PROMPT.format(
            target=risk.get("scope", "N/A"),
            risk_level=risk.get("overall_risk", "UNKNOWN"),
            risk_score=risk.get("risk_score", 0),
            findings=self._bullets(findings_summary),
            mitre=self._bullets(mitre_summary),
            chain=self._bullets(chain_summary),
        )
        return self.llm.generate(
            prompt, system=SYSTEM_PROMPT, temperature=0.3, max_tokens=400
        ).strip()

    def _technical_analysis(self, mitre_summary, top_n: int = 5) -> str:
        if not mitre_summary:
            return "No MITRE ATT&CK techniques were confirmed by the rule-based engine."

        sections = []
        for i, tech in enumerate(mitre_summary[:top_n], start=1):
            print(f"    [LLM] Technique {i}/{min(len(mitre_summary), top_n)}: {tech.get('technique_id', 'N/A')}...")
            prompt = TECHNICAL_PROMPT.format(
                technique_id=tech.get("technique_id", "N/A"),
                technique_name=tech.get("technique_name", "Unknown technique"),
                tactic=tech.get("tactic", "unknown"),
                score=tech.get("score", 0),
                confidence=tech.get("confidence", "N/A"),
                source=tech.get("source", "N/A"),
                severity=self._risk_label(tech.get("score", 0)),
            )
            text = self.llm.generate(
                prompt, system=SYSTEM_PROMPT, temperature=0.2, max_tokens=250
            ).strip()
            sections.append(text)

        return "\n\n".join(sections)

    def _recommendations(self, findings_summary, risk) -> str:
        prompt = RECOMMENDATION_PROMPT.format(
            risk_level=risk.get("overall_risk", "UNKNOWN"),
            findings=self._bullets(findings_summary),
        )
        return self.llm.generate(
            prompt, system=SYSTEM_PROMPT, temperature=0.3, max_tokens=400
        ).strip()

    @staticmethod
    def _risk_label(score) -> str:
        """Deterministic Critical/High/Medium label from a numeric score —
        computed by code, never left for the LLM to guess."""
        try:
            score = float(score)
        except (TypeError, ValueError):
            return "Medium"
        if score >= 90:
            return "Critical"
        if score >= 70:
            return "High"
        return "Medium"

    @staticmethod
    def _bullets(items) -> str:
        if not items:
            return "- None"
        lines = []
        for item in items:
            if isinstance(item, dict):
                lines.append("- " + ", ".join(f"{k}: {v}" for k, v in item.items()))
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)
