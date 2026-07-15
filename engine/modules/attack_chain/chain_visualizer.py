"""
attack_chain/chain_visualizer.py
----------------------------------
Produces a text/ASCII and JSON representation of the attack chain.
"""

import json
import os


class ChainVisualizer:

    def ascii(self, chain: dict) -> str:
        if not chain:
            return "[ No chain data ]"
        lines = []
        phases = sorted(chain.items(), key=lambda x: int(x[0]))
        for i, (num, phase) in enumerate(phases):
            techs = ", ".join(t["id"] for t in phase.get("techniques", []))
            arrow = " →\n" if i < len(phases) - 1 else ""
            lines.append(
                f"  [{num}] {phase['phase_name']} ({phase['tactic']})\n"
                f"       Techniques : {techs}\n"
                f"       Confidence : {phase.get('confidence', 0):.0%}{arrow}"
            )
        return "\n".join(lines)

    def save_json(self, chain: dict, path: str):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(chain, f, indent=2, ensure_ascii=False)
        print(f"  [ChainVisualizer] Saved → {path}")
