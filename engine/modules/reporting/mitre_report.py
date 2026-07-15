"""
reporting/mitre_report.py
---------------------------
Builds the MITRE ATT&CK section of the report.
"""


class MitreReport:

    def build(self, mapped_results: list[dict], attack_chain: dict,
              coverage: dict) -> dict:

        all_techniques = []
        tactic_counts  = {}

        for r in mapped_results:
            for layer in r.get("layers", []):
                tid = layer.get("technique_id", "")
                if not tid or tid.startswith("T-"):
                    continue
                tactic = layer.get("tactic", "unknown")
                all_techniques.append({
                    "technique_id":   tid,
                    "technique_name": layer.get("technique_name", ""),
                    "tactic":         tactic,
                    "confidence":     layer.get("confidence", 0),
                    "source":         layer.get("source", ""),
                    "host":           r.get("host", ""),
                })
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        return {
            "total_techniques":   len({t["technique_id"] for t in all_techniques}),
            "total_tactics":      len(tactic_counts),
            "tactic_distribution": tactic_counts,
            "techniques":         all_techniques,
            "attack_chain_phases": len(attack_chain),
            "coverage_percentage": coverage.get("tactic_coverage_pct", 0),
        }
