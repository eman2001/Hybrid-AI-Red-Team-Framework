"""
attack_chain/chain_builder.py
-------------------------------
Standalone ChainBuilder — same logic as mitre/chain_builder.py but lives
here per the project structure. mitre/chain_builder.py re-exports this.
"""

from engine.modules.attack_chain.phase_mapper  import PhaseMapper, PHASE_ORDER, PHASE_DISPLAY


class ChainBuilder:

    def __init__(self):
        self._pm = PhaseMapper()

    def build(self, mapped_results: list[dict]) -> dict:
        by_tactic: dict[str, list] = {}

        for result in mapped_results:
            for layer in result.get("layers", []):
                tactic = layer.get("tactic", "unknown").lower()
                entry  = {
                    "technique_id":   layer.get("technique_id", "T?"),
                    "technique_name": layer.get("technique_name", "Unknown"),
                    "confidence":     layer.get("confidence", 0.5),
                    "source":         layer.get("source", "unknown"),
                    "host":           result.get("host", ""),
                }
                if entry["technique_id"].startswith("T-"):
                    continue
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                if entry["technique_id"] not in [e["technique_id"] for e in by_tactic[tactic]]:
                    by_tactic[tactic].append(entry)

        chain = {}
        phase_num = 1
        for phase_key in PHASE_ORDER:
            if phase_key not in by_tactic:
                continue
            entries  = by_tactic[phase_key]
            hosts    = list({e["host"] for e in entries if e["host"]})
            avg_conf = round(sum(e["confidence"] for e in entries) / len(entries), 3)
            chain[str(phase_num)] = {
                "phase_name": PHASE_DISPLAY.get(phase_key, phase_key.replace("-", " ").title()),
                "tactic":     phase_key,
                "techniques": [{"id": e["technique_id"], "name": e["technique_name"]} for e in entries],
                "hosts":      hosts,
                "confidence": avg_conf,
                "source":     entries[0]["source"],
            }
            phase_num += 1

        print(f"  [Chain] {len(chain)} phases reconstructed.")
        return chain
