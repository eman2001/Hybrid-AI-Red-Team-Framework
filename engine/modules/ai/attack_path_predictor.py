"""
ai/attack_path_predictor.py
-----------------------------
Predicts the most likely attack path through the network.
"""

class AttackPathPredictor:

    def predict(self, findings: list[dict], post_data: dict) -> list[dict]:
        """
        Returns ordered list of hosts/services representing the predicted
        attacker traversal path.
        """
        sorted_f = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)
        path = []
        for f in sorted_f:
            path.append({
                "host":       f.get("host"),
                "port":       f.get("port"),
                "service":    f.get("service"),
                "tactic":     f.get("mitre", {}).get("tactic", "initial-access"),
                "risk_score": f.get("risk_score", 0),
            })
        return path
