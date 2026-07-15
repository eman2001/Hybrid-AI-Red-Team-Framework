"""
attack_path/path_ranker.py
----------------------------
Ranks complete attack paths end-to-end (multi-hop).
"""


class PathRanker:

    def rank(self, paths: list[list[dict]]) -> list[dict]:
        """
        paths: list of attack paths, each path is a list of step dicts.
        Returns paths sorted by total probability descending.
        """
        scored = []
        for path in paths:
            if not path:
                continue
            probs = [s.get("probability", 0.5) for s in path]
            # Joint probability
            joint = 1.0
            for p in probs:
                joint *= p
            scored.append({"path": path, "joint_probability": round(joint, 4),
                           "steps": len(path)})
        return sorted(scored, key=lambda x: x["joint_probability"], reverse=True)
