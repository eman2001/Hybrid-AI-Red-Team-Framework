"""
mitre/tactic_statistics.py
-----------------------------
Aggregates per-tactic statistics from mapped results.
"""

from collections import defaultdict


class TacticStatistics:

    def compute(self, mapped_results: list[dict]) -> dict:
        stats: dict[str, dict] = defaultdict(lambda: {"count": 0, "techniques": [], "avg_conf": 0.0})

        for r in mapped_results:
            for layer in r.get("layers", []):
                tactic = layer.get("tactic", "unknown")
                tid    = layer.get("technique_id", "")
                if tid.startswith("T-"):
                    continue
                s = stats[tactic]
                s["count"] += 1
                if tid not in s["techniques"]:
                    s["techniques"].append(tid)
                s["avg_conf"] = round(
                    (s["avg_conf"] * (s["count"] - 1) + layer.get("confidence", 0)) / s["count"], 3
                )

        return dict(stats)
