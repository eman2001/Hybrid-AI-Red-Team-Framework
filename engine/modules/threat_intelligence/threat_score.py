"""
threat_intelligence/threat_score.py
-------------------------------------
Composite threat score (0–100) combining CVSS, EPSS, KEV, and exposure.
"""


class ThreatScore:

    def calculate(self, finding: dict) -> float:
        score = 0.0

        # CVSS contribution (max 40)
        cvss = finding.get("cvss_live", finding.get("cvss", 3.0))
        score += cvss * 4

        # EPSS contribution (max 25)
        epss = finding.get("epss", 0.1)
        score += epss * 25

        # KEV bonus (+20)
        if finding.get("in_kev"):
            score += 20

        # EOL bonus (+15)
        if finding.get("eol_risk") == "CRITICAL":
            score += 15

        return round(min(score, 100), 1)

    def label(self, score: float) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "INFORMATIONAL"
