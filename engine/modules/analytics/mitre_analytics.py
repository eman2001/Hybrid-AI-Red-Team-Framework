"""
analytics/mitre_analytics.py
------------------------------
MITRE ATT&CK analytics — tactic/technique frequency and distribution.
"""

from collections import Counter


class MitreAnalytics:

    def compute(self, mapped_results: list[dict]) -> dict:
        tactic_counter    = Counter()
        technique_counter = Counter()
        source_counter    = Counter()

        for r in mapped_results:
            for layer in r.get("layers", []):
                tid = layer.get("technique_id", "")
                if not tid or tid.startswith("T-"):
                    continue
                tactic_counter[layer.get("tactic", "unknown")] += 1
                technique_counter[tid] += 1
                source_counter[layer.get("source", "unknown")] += 1

        return {
            "top_tactics":    tactic_counter.most_common(5),
            "top_techniques": technique_counter.most_common(10),
            "resolver_distribution": dict(source_counter),
            "unique_techniques": len(technique_counter),
            "unique_tactics":   len(tactic_counter),
        }
