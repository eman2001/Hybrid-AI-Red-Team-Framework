"""
mitre/technique_statistics.py
--------------------------------
Per-technique frequency and confidence statistics.
"""

from collections import defaultdict


class TechniqueStatistics:

    def compute(self, mapped_results: list[dict]) -> list[dict]:
        counts: dict[str, dict] = defaultdict(lambda: {"hits": 0, "total_conf": 0.0,
                                                        "name": "", "tactic": "", "sources": set()})
        for r in mapped_results:
            for layer in r.get("layers", []):
                tid = layer.get("technique_id", "")
                if not tid or tid.startswith("T-"):
                    continue
                c = counts[tid]
                c["hits"]       += 1
                c["total_conf"] += layer.get("confidence", 0)
                c["name"]        = layer.get("technique_name", c["name"])
                c["tactic"]      = layer.get("tactic", c["tactic"])
                c["sources"].add(layer.get("source", ""))

        result = []
        for tid, d in counts.items():
            result.append({
                "technique_id":   tid,
                "technique_name": d["name"],
                "tactic":         d["tactic"],
                "hits":           d["hits"],
                "avg_confidence": round(d["total_conf"] / d["hits"], 3),
                "sources":        list(d["sources"]),
            })
        return sorted(result, key=lambda x: x["hits"], reverse=True)
