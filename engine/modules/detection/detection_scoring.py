"""
detection/detection_scoring.py
--------------------------------
Scores overall detection posture (0–100).
"""


class DetectionScoring:

    def score(self, coverage: dict) -> dict:
        pct     = coverage.get("coverage_percentage", 0)
        gaps    = coverage.get("gap_count", 0)
        total   = coverage.get("total_techniques", 1)

        # Base score from coverage %
        base = pct

        # Penalty for uncovered critical techniques
        CRITICAL_TECHS = {"T1003", "T1059", "T1190", "T1021", "T1110"}
        uncovered = set(coverage.get("uncovered", []))
        critical_gaps = len(CRITICAL_TECHS & uncovered)
        penalty = critical_gaps * 10

        final = max(0.0, min(100.0, base - penalty))

        return {
            "detection_score":  round(final, 1),
            "posture":          self._label(final),
            "critical_gaps":    critical_gaps,
            "coverage_pct":     pct,
        }

    @staticmethod
    def _label(score: float) -> str:
        if score >= 80: return "STRONG"
        if score >= 60: return "MODERATE"
        if score >= 40: return "WEAK"
        return "CRITICAL_GAP"
