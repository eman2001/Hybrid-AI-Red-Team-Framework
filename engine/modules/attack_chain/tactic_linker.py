"""
attack_chain/tactic_linker.py
-------------------------------
Creates directed links between consecutive tactics in the kill chain.
Used to build the graph edges for attack_graph and chain_visualizer.
"""

from engine.modules.attack_chain.phase_mapper import PhaseMapper


class TacticLinker:

    def __init__(self):
        self._pm = PhaseMapper()

    def link(self, techniques: list[dict]) -> list[dict]:
        """
        Returns a list of directed edges:
        [{"from_tactic": ..., "to_tactic": ..., "techniques": [...]}]
        """
        ordered_tactics = self._pm.ordered(
            list({t.get("tactic", "") for t in techniques if t.get("tactic")})
        )
        edges = []
        for i in range(len(ordered_tactics) - 1):
            src = ordered_tactics[i]
            dst = ordered_tactics[i + 1]
            src_techs = [t for t in techniques if t.get("tactic") == src]
            edges.append({
                "from_tactic": src,
                "to_tactic":   dst,
                "from_display": self._pm.display(src),
                "to_display":   self._pm.display(dst),
                "techniques":   [t.get("technique_id") for t in src_techs],
            })
        return edges
