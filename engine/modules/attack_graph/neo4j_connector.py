"""
attack_graph/neo4j_connector.py
---------------------------------
Optional Neo4j connector for persisting the attack graph.
Gracefully disabled if neo4j driver is not installed.
"""

try:
    from neo4j import GraphDatabase
    _NEO4J = True
except ImportError:
    _NEO4J = False


class Neo4jConnector:

    def __init__(self, uri: str = "bolt://localhost:7687",
                 user: str = "neo4j", password: str = "password"):
        self._driver = None
        if _NEO4J:
            try:
                self._driver = GraphDatabase.driver(uri, auth=(user, password))
                print("  [Neo4j] Connected.")
            except Exception as e:
                print(f"  [Neo4j] Connection failed: {e}")
        else:
            print("  [Neo4j] Driver not installed — skipping.")

    def push_graph(self, graph_data: dict):
        if not self._driver:
            return
        with self._driver.session() as session:
            # Clear existing
            session.run("MATCH (n) DETACH DELETE n")
            # Create nodes
            for node in graph_data.get("nodes", []):
                session.run(
                    "CREATE (n:Node {id: $id, type: $type, label: $label})",
                    id=node["id"], type=node.get("type", "host"),
                    label=node.get("label", node["id"]),
                )
            # Create edges
            for edge in graph_data.get("edges", []):
                session.run(
                    "MATCH (a:Node {id: $from}), (b:Node {id: $to}) "
                    "CREATE (a)-[:ATTACKS {tactic: $tactic, technique: $technique}]->(b)",
                    **{"from": edge["from"], "to": edge["to"],
                       "tactic": edge.get("tactic", ""),
                       "technique": edge.get("technique", "")},
                )
        print(f"  [Neo4j] Graph pushed — "
              f"{len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges.")

    def close(self):
        if self._driver:
            self._driver.close()
