"""
reporting/threat_report.py
----------------------------
Builds the threat intelligence section of the report.
"""


class ThreatReport:

    def build(self, findings: list[dict]) -> dict:
        kev_findings    = [f for f in findings if f.get("in_kev")]
        high_epss       = [f for f in findings if f.get("epss", 0) >= 0.4]
        eol_findings    = [f for f in findings if f.get("eol_risk") == "CRITICAL"]
        threat_actors   = set()

        for f in findings:
            for actor in f.get("threat_actors", []):
                threat_actors.add(actor)

        return {
            "kev_count":         len(kev_findings),
            "kev_cves":          [f.get("cve") for f in kev_findings],
            "high_epss_count":   len(high_epss),
            "eol_count":         len(eol_findings),
            "threat_actors":     sorted(threat_actors),
            "top_ti_findings":   sorted(findings, key=lambda x: x.get("epss", 0), reverse=True)[:5],
        }
