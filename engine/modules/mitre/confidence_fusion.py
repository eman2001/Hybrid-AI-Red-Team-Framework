"""
mitre/confidence_fusion.py
-----------------------------
Fuses confidence scores from multiple resolvers into a single verdict.
"""


class ConfidenceFusion:

    WEIGHTS = {"cve_enricher": 0.92, "rule_exact": 1.0, "rule_service": 0.9, "rule_cve": 0.85,
               "post_exploit": 1.0, "stix": 0.7, "ml": 0.6, "ml_fallback": 0.4}

    def fuse(self, layers: list[dict]) -> dict:
        if not layers:
            return {}
        # Weighted vote by source weight * confidence
        scores: dict[str, float] = {}
        for l in layers:
            tid = l.get("technique_id", "")
            if tid.startswith("T-"):
                continue
            w = self.WEIGHTS.get(l.get("source", ""), 0.5)
            scores[tid] = scores.get(tid, 0) + w * l["confidence"]

        if not scores:
            return max(layers, key=lambda x: x.get("confidence", 0))

        best_tid = max(scores, key=lambda k: scores[k])
        best_layer = next(l for l in layers if l.get("technique_id") == best_tid)
        best_layer["fused_score"] = round(scores[best_tid], 3)
        return best_layer
