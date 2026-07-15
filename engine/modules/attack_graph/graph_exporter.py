"""
attack_graph/graph_exporter.py
--------------------------------
Exports the attack graph to JSON, GraphML, and DOT formats.
"""

import json
import os


class GraphExporter:

    def to_json(self, graph_data: dict, path: str):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        print(f"  [GraphExporter] JSON → {path}")

    def to_dot(self, graph_data: dict, path: str):
        lines = ["digraph AttackGraph {", '  rankdir=LR;']
        for node in graph_data.get("nodes", []):
            nid   = node["id"].replace(":", "_").replace(".", "_")
            color = "#ff4444" if node.get("type") == "attacker" else "#4488ff"
            lines.append(f'  {nid} [label="{node["id"]}" style=filled fillcolor="{color}"];')
        for edge in graph_data.get("edges", []):
            src = edge["from"].replace(":", "_").replace(".", "_")
            dst = edge["to"].replace(":", "_").replace(".", "_")
            tactic = edge.get("tactic", "")
            lines.append(f'  {src} -> {dst} [label="{tactic}"];')
        lines.append("}")

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"  [GraphExporter] DOT  → {path}")

    def to_graphml(self, G, path: str):
        try:
            import networkx as nx
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
            nx.write_graphml(G, path)
            print(f"  [GraphExporter] GraphML → {path}")
        except Exception as e:
            print(f"  [GraphExporter] GraphML failed: {e}")
