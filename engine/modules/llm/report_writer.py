"""
report_writer.py
------------------
The "brain" of AI report writing.

Pipeline:
    Deterministic pipeline outputs
        -> summary_builder
        -> prompts
        -> llm_engine (Qwen2.5 via Ollama - phrasing only)
        -> executive_summary / technical_analysis / recommendations

IMPORTANT:
This module NEVER decides severity, priority, exploitation success,
or MITRE ATT&CK mappings. Those values are already decided upstream.
The LLM only explains and phrases the supplied facts.
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
    build_exploitation_summary,
)

logger = logging.getLogger(__name__)


class ReportWriter:

    def __init__(self, llm: LLMEngine = None):
        self.llm = llm or LLMEngine()

    def generate_full_report(
        self,
        findings: list[dict],
        mapped_results: list[dict],
        attack_chain,
        risk_summary: dict,
        exploit_results: list[dict] | None = None,
    ) -> dict:
        findings_summary = build_findings_summary(findings)
        mitre_summary = build_mitre_summary(mapped_results)
        risk = build_risk_summary(risk_summary)
        chain_summary = build_attack_chain_summary(attack_chain)
        exploitation = build_exploitation_summary(exploit_results or [])

        print("  [LLM] Generating executive summary...")
        executive_summary = self._executive_summary(
            risk=risk,
            findings_summary=findings_summary,
            mitre_summary=mitre_summary,
            chain_summary=chain_summary,
            exploitation=exploitation,
        )
        print("  [LLM] Executive summary done.")

        print(
            f"  [LLM] Generating technical analysis for "
            f"{min(len(mitre_summary), 5)} technique(s)..."
        )
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

    def generate_summary(
        self,
        findings,
        attack_chain,
        risk_summary,
        exploit_results=None,
    ):
        findings_summary = build_findings_summary(findings)
        risk = build_risk_summary(risk_summary)
        chain_summary = build_attack_chain_summary(attack_chain)
        exploitation = build_exploitation_summary(exploit_results or [])

        return self._executive_summary(
            risk=risk,
            findings_summary=findings_summary,
            mitre_summary=[],
            chain_summary=chain_summary,
            exploitation=exploitation,
        )

    def generate_recommendations(self, findings):
        findings_summary = build_findings_summary(findings)
        return self._recommendations(findings_summary, risk={})

    def _executive_summary(
        self,
        risk,
        findings_summary,
        mitre_summary,
        chain_summary,
        exploitation,
    ) -> str:
        prompt = EXECUTIVE_PROMPT.format(
            target=risk.get("scope", "N/A"),
            risk_level=risk.get("overall_risk", "UNKNOWN"),
            risk_score=risk.get("risk_score", 0),
            exploit_attempts=exploitation.get("attempts", 0),
            exploit_success=exploitation.get("successful", 0),
            exploit_failed=exploitation.get("failed", 0),
            exploit_rate=exploitation.get("success_rate", 0.0),
            successful_exploits=self._bullets(
                exploitation.get("successful_examples", [])
            ),
            findings=self._bullets(findings_summary),
            mitre=self._bullets(mitre_summary),
            chain=self._bullets(chain_summary),
        )

        return self.llm.generate(
            prompt,
            system=SYSTEM_PROMPT,
            temperature=0.3,
            max_tokens=260,
        ).strip()

    def _technical_analysis(
        self,
        mitre_summary,
        top_n: int = 5,
    ) -> str:
        if not mitre_summary:
            return (
                "No MITRE ATT&CK techniques were confirmed "
                "by the deterministic analysis engine."
            )

        sections = []

        for i, tech in enumerate(mitre_summary[:top_n], start=1):
            print(
                f"    [LLM] Technique "
                f"{i}/{min(len(mitre_summary), top_n)}: "
                f"{tech.get('technique_id', 'N/A')}..."
            )

            prompt = TECHNICAL_PROMPT.format(
                technique_id=tech.get("technique_id", "N/A"),
                technique_name=tech.get(
                    "technique_name",
                    "Unknown technique",
                ),
                tactic=tech.get("tactic", "unknown"),
                score=tech.get("score", 0),
                confidence=tech.get("confidence", "N/A"),
                source=tech.get("source", "N/A"),
                severity=tech.get("severity", "UNKNOWN"),
            )

            text = self.llm.generate(
                prompt,
                system=SYSTEM_PROMPT,
                temperature=0.2,
                max_tokens=180,
            ).strip()

            sections.append(text)

        return "\n\n".join(sections)

    def _recommendations(self, findings_summary, risk) -> str:
        prompt = RECOMMENDATION_PROMPT.format(
            risk_level=risk.get("overall_risk", "UNKNOWN"),
            findings=self._bullets(findings_summary),
        )

        return self.llm.generate(
            prompt,
            system=SYSTEM_PROMPT,
            temperature=0.3,
            max_tokens=280,
        ).strip()

    @staticmethod
    def _risk_label(score) -> str:
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
                lines.append(
                    "- "
                    + ", ".join(
                        f"{key}: {value}"
                        for key, value in item.items()
                    )
                )
            else:
                lines.append(f"- {item}")

        return "\n".join(lines)
