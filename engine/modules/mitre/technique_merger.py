"""
mitre/technique_merger.py
--------------------------
Deduplicates and merges technique lists from multiple results.
"""


class TechniqueMerger:

    def merge(self, results: list[dict]) -> list[dict]:
        seen: dict[str, dict] = {}
        for r in results:
            for layer in r.get("layers", []):
                tid = layer.get("technique_id", "")
                if tid.startswith("T-") or not tid:
                    continue
                if tid not in seen or layer["confidence"] > seen[tid]["confidence"]:
                    seen[tid] = {**layer, "hosts": [r.get("host", "")]}
                elif r.get("host") not in seen[tid].get("hosts", []):
                    seen[tid]["hosts"].append(r.get("host", ""))
        return list(seen.values())
