"""
attack_path/path_prioritizer.py
---------------------------------
Prioritises attack paths by composite score (risk + exploit type + CVSS).
"""


class PathPrioritizer:

    def prioritize(self, findings: list[dict]) -> list[dict]:
        def _score(f):
            return (
                f.get("risk_score", 0) * 0.5 +
                f.get("cvss", 0) * 4 +
                {"metasploit": 30, "hydra": 20, "web": 10}.get(f.get("type", ""), 0)
            )
        return sorted(findings, key=_score, reverse=True)
