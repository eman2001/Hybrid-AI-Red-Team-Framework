"""
ai/risk_predictor.py
---------------------
Predicts composite risk score using trained model or heuristic fallback.
"""

class RiskPredictor:

    def predict(self, finding: dict) -> float:
        cvss  = finding.get("cvss", 3.0)
        epss  = finding.get("epss", 0.1)
        kev   = 20 if finding.get("in_kev") else 0
        etype = {"metasploit": 20, "hydra": 15, "web": 8, "manual": 3}.get(
                    finding.get("type", ""), 0)
        score = min(100, cvss * 4 + epss * 25 + kev + etype)
        return round(score, 1)
