"""
detection/detection_coverage.py
---------------------------------
Measures detection coverage across mapped ATT&CK techniques.
"""


class DetectionCoverage:

    def analyze(self, mapped_techniques: list[dict], sigma_rules: list[dict]) -> dict:
        covered_ids = {r.get("technique_id") for r in sigma_rules if r.get("technique_id")}
        all_ids     = {t.get("technique_id") for t in mapped_techniques if t.get("technique_id")}

        covered   = all_ids & covered_ids
        uncovered = all_ids - covered_ids

        pct = round(len(covered) / len(all_ids) * 100, 1) if all_ids else 0.0

        return {
            "total_techniques":    len(all_ids),
            "covered":             sorted(covered),
            "uncovered":           sorted(uncovered),
            "coverage_percentage": pct,
            "gap_count":           len(uncovered),
        }
