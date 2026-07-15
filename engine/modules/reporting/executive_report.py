"""
reporting/executive_report.py
-------------------------------
Builds a high-level executive summary section from full report data.
"""

from datetime import datetime


class ExecutiveReport:

    def build(self, scan_results: dict, findings: list[dict],
              attack_chain: dict, risk_summary: dict) -> dict:

        hosts        = list(scan_results.keys())
        total_ports  = sum(len(h.get("ports", [])) for h in scan_results.values())
        sev_counts   = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        overall_risk = "CRITICAL" if sev_counts["critical"] > 0 else \
                       "HIGH"     if sev_counts["high"] > 0     else \
                       "MEDIUM"   if sev_counts["medium"] > 0   else "LOW"

        return {
            "generated_at":     datetime.now().isoformat(),
            "scope":            hosts,
            "total_hosts":      len(hosts),
            "total_open_ports": total_ports,
            "total_findings":   len(findings),
            "severity_breakdown": sev_counts,
            "overall_risk":     overall_risk,
            "attack_phases":    len(attack_chain),
            "risk_score":       risk_summary.get("risk_score", 0),
            "top_findings":     findings[:3],
            "recommendation":   self._recommendation(overall_risk),
        }

    @staticmethod
    def _recommendation(risk: str) -> str:
        if risk == "CRITICAL":
            return "Immediate patching required. Isolate affected systems and apply emergency mitigations."
        if risk == "HIGH":
            return "High-priority patching within 24–72 hours. Review access controls."
        if risk == "MEDIUM":
            return "Schedule patching within next maintenance window. Monitor for exploitation."
        return "Low risk. Maintain regular patch cycle and monitoring."
