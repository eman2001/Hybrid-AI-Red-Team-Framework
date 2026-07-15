"""
ai/recommendation_engine.py
-----------------------------
Generates remediation recommendations based on findings and MITRE coverage.
"""

RECS = {
    "initial-access":       "Patch public-facing services; enforce WAF and input validation.",
    "credential-access":    "Enable MFA; enforce password policy; monitor for hashdump activity.",
    "privilege-escalation": "Audit SUID binaries; restrict sudo; apply kernel patches.",
    "lateral-movement":     "Segment network; restrict SMB/RDP; deploy honeypots.",
    "persistence":          "Audit scheduled tasks and registry run keys; deploy FIM.",
    "discovery":            "Deploy deception assets; alert on enumeration patterns.",
    "exfiltration":         "Monitor outbound traffic; DLP controls; encrypt sensitive data.",
    "impact":               "Backup and DR plan; ransomware-resilient architecture.",
}

class RecommendationEngine:

    def recommend(self, covered_tactics: list[str]) -> list[dict]:
        out = []
        for tactic in covered_tactics:
            rec = RECS.get(tactic)
            if rec:
                out.append({"tactic": tactic, "recommendation": rec})
        return out
