"""
attack_path/critical_path_analyzer.py
----------------------------------------
Identifies the single most dangerous attack path through the network.
"""

from engine.modules.attack_path.path_prioritizer import PathPrioritizer
from engine.modules.attack_path.exposure_engine  import ExposureEngine


class CriticalPathAnalyzer:

    def __init__(self):
        self._prio = PathPrioritizer()
        self._exp  = ExposureEngine()

    def analyze(self, findings: list[dict], scan_results: dict) -> dict:
        prioritized = self._prio.prioritize(findings)
        exposure    = self._exp.score_all(scan_results)

        if not prioritized:
            return {}

        top = prioritized[0]
        return {
            "critical_target":    f"{top.get('host')}:{top.get('port')}",
            "service":            top.get("service"),
            "exploit":            top.get("exploit"),
            "risk_score":         top.get("risk_score", 0),
            "cvss":               top.get("cvss", 0),
            "top_exposed_ports":  exposure[:3],
            "recommendation":     f"Patch {top.get('service')} on {top.get('host')} immediately.",
        }
