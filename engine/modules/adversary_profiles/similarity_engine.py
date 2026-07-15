"""
adversary_profiles/similarity_engine.py
------------------------------------------
Computes similarity between observed attack techniques and known adversary profiles.
"""

from engine.modules.adversary_profiles.apt29       import PROFILE as APT29
from engine.modules.adversary_profiles.apt28       import PROFILE as APT28
from engine.modules.adversary_profiles.lazarus     import PROFILE as LAZARUS
from engine.modules.adversary_profiles.fin7        import PROFILE as FIN7
from engine.modules.adversary_profiles.volt_typhoon import PROFILE as VOLT

ALL_PROFILES = [APT29, APT28, LAZARUS, FIN7, VOLT]


class SimilarityEngine:

    def compare(self, observed_techniques: list[str]) -> list[dict]:
        observed_set = set(t.upper() for t in observed_techniques)
        results = []

        for profile in ALL_PROFILES:
            known_set = set(t.upper() for t in profile.get("techniques", []))
            if not known_set:
                continue

            overlap   = observed_set & known_set
            jaccard   = len(overlap) / len(observed_set | known_set)
            precision = len(overlap) / len(known_set)

            results.append({
                "adversary":        profile["name"],
                "aliases":          profile.get("aliases", []),
                "origin":           profile.get("origin", ""),
                "motivation":       profile.get("motivation", []),
                "overlap":          sorted(overlap),
                "overlap_count":    len(overlap),
                "jaccard":          round(jaccard, 3),
                "precision":        round(precision, 3),
                "similarity_pct":   round(jaccard * 100, 1),
            })

        return sorted(results, key=lambda x: x["jaccard"], reverse=True)

    def top_match(self, observed_techniques: list[str]) -> dict:
        results = self.compare(observed_techniques)
        return results[0] if results else {}
