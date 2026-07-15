"""
analytics/dashboard_metrics.py
--------------------------------
Aggregates all analytics into a single dashboard-ready metrics object.
"""

from engine.modules.analytics.risk_analytics     import RiskAnalytics
from engine.modules.analytics.mitre_analytics    import MitreAnalytics
from engine.modules.analytics.threat_analytics   import ThreatAnalytics
from engine.modules.analytics.ai_analytics       import AiAnalytics
from engine.modules.analytics.coverage_analytics import CoverageAnalytics


class DashboardMetrics:

    def __init__(self):
        self._risk     = RiskAnalytics()
        self._mitre    = MitreAnalytics()
        self._threat   = ThreatAnalytics()
        self._ai       = AiAnalytics()
        self._coverage = CoverageAnalytics()

    def compute(self, findings: list[dict], mapped_results: list[dict],
                coverage: dict, detection_score: dict) -> dict:
        return {
            "risk":     self._risk.compute(findings),
            "mitre":    self._mitre.compute(mapped_results),
            "threat":   self._threat.compute(findings),
            "ai":       self._ai.compute(mapped_results),
            "coverage": self._coverage.compute(coverage, detection_score),
        }
