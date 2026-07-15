"""
ai/dataset_builder.py
----------------------
Builds training datasets from vulnerability and MITRE mapping results.
"""
import csv, json, os
from datetime import datetime

class DatasetBuilder:

    FEATURES = ["exploit", "service", "cve", "edb_title", "product", "version",
                "port", "severity", "cvss"]

    def build_from_results(self, mapped_results: list[dict]) -> list[dict]:
        rows = []
        for r in mapped_results:
            label = r.get("mitre", {}).get("tactic", "unknown")
            if label == "unknown":
                continue
            row = {f: r.get(f, "") for f in self.FEATURES}
            row["label"] = label
            rows.append(row)
        return rows

    def save_csv(self, rows: list[dict], path: str = "data/training_dataset.csv"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not rows:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        print(f"  [Dataset] {len(rows)} rows → {path}")
