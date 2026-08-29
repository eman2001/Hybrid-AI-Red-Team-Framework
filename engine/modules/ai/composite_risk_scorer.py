"""
ai/composite_risk_scorer.py
-----------------------------
Composite risk score from CVSS, EPSS, KEV status, and exploit type.
NOTE: this is a fixed heuristic formula, not a trained ML model --
named accordingly (CompositeRiskScorer, not "Predictor") to avoid
implying a learned model where there isn't one. If a trained
regression/ranking model replaces this formula later, that's the
point to reintroduce "Predictor" in the name.
"""
class CompositeRiskScorer:
    def score(self, finding: dict) -> float:
        cvss  = finding.get("cvss", 3.0)
        epss  = finding.get("epss", 0.1)
        kev   = 20 if finding.get("in_kev") else 0
        etype = {"metasploit": 20, "hydra": 15, "web": 8, "manual": 3}.get(
                    finding.get("type", ""), 0)
        composite = min(100, cvss * 4 + epss * 25 + kev + etype)
        return round(composite, 1)
