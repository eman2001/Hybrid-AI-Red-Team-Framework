"""
analytics/risk_analytics.py
-----------------------------
Risk analytics — aggregates and trends risk scores across findings.
"""


class RiskAnalytics:

    def compute(self, findings: list[dict]) -> dict:
        if not findings:
            return {"avg_risk": 0, "max_risk": 0, "min_risk": 0, "total": 0}

        scores = [f.get("risk_score", 0) for f in findings]
        by_host: dict[str, list] = {}
        for f in findings:
            h = f.get("host", "unknown")
            by_host.setdefault(h, []).append(f.get("risk_score", 0))

        return {
            "total":      len(findings),
            "avg_risk":   round(sum(scores) / len(scores), 1),
            "max_risk":   max(scores),
            "min_risk":   min(scores),
            "risk_by_host": {h: round(sum(v)/len(v), 1) for h, v in by_host.items()},
            "high_risk_count": sum(1 for s in scores if s >= 60),
        }
