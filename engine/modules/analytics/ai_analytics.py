"""
analytics/ai_analytics.py
---------------------------
AI/ML model performance analytics.
"""


class AiAnalytics:

    def compute(self, mapped_results: list[dict]) -> dict:
        ml_results = [
            layer for r in mapped_results
            for layer in r.get("layers", [])
            if layer.get("source") in ("ml", "ml_fallback")
        ]
        if not ml_results:
            return {"ml_predictions": 0, "avg_confidence": 0}

        confs = [l.get("confidence", 0) for l in ml_results]
        return {
            "ml_predictions":      len(ml_results),
            "avg_confidence":      round(sum(confs) / len(confs), 3),
            "high_confidence":     sum(1 for c in confs if c >= 0.75),
            "low_confidence":      sum(1 for c in confs if c < 0.50),
        }
