"""
analytics/threat_analytics.py
-------------------------------
Threat intelligence analytics — KEV, EPSS, EOL trends.
"""


class ThreatAnalytics:

    def compute(self, findings: list[dict]) -> dict:
        kev   = [f for f in findings if f.get("in_kev")]
        epss  = sorted(findings, key=lambda x: x.get("epss", 0), reverse=True)
        eol   = [f for f in findings if f.get("eol_risk") == "CRITICAL"]

        actors: dict[str, int] = {}
        for f in findings:
            for a in f.get("threat_actors", []):
                actors[a] = actors.get(a, 0) + 1

        return {
            "kev_findings":       len(kev),
            "avg_epss":           round(sum(f.get("epss", 0) for f in findings) / len(findings), 4) if findings else 0,
            "top_epss":           [{"cve": f.get("cve"), "epss": f.get("epss")} for f in epss[:5]],
            "eol_findings":       len(eol),
            "top_threat_actors":  sorted(actors.items(), key=lambda x: x[1], reverse=True)[:5],
        }
