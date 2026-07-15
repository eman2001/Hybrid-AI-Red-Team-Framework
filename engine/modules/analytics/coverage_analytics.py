"""
analytics/coverage_analytics.py
---------------------------------
Detection coverage analytics.
"""


class CoverageAnalytics:

    def compute(self, coverage: dict, detection_score: dict) -> dict:
        return {
            "tactic_coverage_pct":    coverage.get("tactic_coverage_pct", 0),
            "technique_count":        coverage.get("technique_count", 0),
            "covered_tactics":        coverage.get("covered_tactics", []),
            "uncovered_techniques":   coverage.get("uncovered", []),
            "detection_score":        detection_score.get("detection_score", 0),
            "detection_posture":      detection_score.get("posture", "UNKNOWN"),
            "critical_gaps":          detection_score.get("critical_gaps", 0),
        }
