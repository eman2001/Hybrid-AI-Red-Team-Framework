"""
ai/adversary_similarity.py
----------------------------
Computes cosine similarity between observed attack patterns and known APT profiles.
"""

class AdversarySimilarity:

    PROFILES = {
        "APT29":        ["T1190","T1078","T1059","T1003","T1082"],
        "APT28":        ["T1190","T1110","T1059","T1547","T1016"],
        "Lazarus":      ["T1190","T1059","T1486","T1105","T1082"],
        "FIN7":         ["T1566","T1059","T1003","T1041","T1082"],
        "Volt Typhoon": ["T1190","T1021","T1016","T1049","T1083"],
    }

    def score(self, observed_techniques: list[str]) -> list[dict]:
        obs = set(observed_techniques)
        results = []
        for apt, techs in self.PROFILES.items():
            profile = set(techs)
            if not profile:
                continue
            intersection = obs & profile
            sim = len(intersection) / len(profile | obs) if (profile | obs) else 0
            results.append({
                "apt":        apt,
                "similarity": round(sim, 3),
                "matched":    sorted(intersection),
            })
        return sorted(results, key=lambda x: x["similarity"], reverse=True)
