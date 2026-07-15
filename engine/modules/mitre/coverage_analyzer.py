"""
mitre/coverage_analyzer.py
-----------------------------
Measures what percentage of ATT&CK tactics/techniques are covered.
"""

from engine.config.constants import MITRE_TACTICS_ORDER


class CoverageAnalyzer:

    def analyze(self, mapped_results: list[dict]) -> dict:
        covered_tactics: set[str] = set()
        covered_techs:   set[str] = set()

        for r in mapped_results:
            for layer in r.get("layers", []):
                tid = layer.get("technique_id", "")
                if not tid.startswith("T-"):
                    covered_techs.add(str(tid))
                tactic = layer.get("tactic", "")
                if tactic:
                    covered_tactics.add(str(tactic))

        total_tactics = len(MITRE_TACTICS_ORDER)
        return {
            "covered_tactics":  sorted(covered_tactics),
            "covered_techniques": sorted(covered_techs),
            "tactic_coverage_pct":  round(len(covered_tactics) / total_tactics * 100, 1),
            "technique_count":  len(covered_techs),
        }
