"""
chain_builder.py  —  Kill-Chain Phase Grouper
Groups all mapped techniques into ordered ATT&CK kill-chain phases.
"""

PHASE_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

PHASE_DISPLAY = {
    "reconnaissance":      "Reconnaissance",
    "resource-development":"Resource Development",
    "initial-access":      "Initial Access",
    "execution":           "Execution",
    "persistence":         "Persistence",
    "privilege-escalation":"Privilege Escalation",
    "defense-evasion":     "Defense Evasion",
    "credential-access":   "Credential Access",
    "discovery":           "Discovery",
    "lateral-movement":    "Lateral Movement",
    "collection":          "Collection",
    "command-and-control": "Command & Control",
    "exfiltration":        "Exfiltration",
    "impact":              "Impact",
}


class ChainBuilder:

    def build(self, mapped_results: list[dict]) -> dict:
        """
        Parameters
        ----------
        mapped_results : output of MitreEngine.map_all()  (list of per-finding dicts)

        Returns
        -------
        Ordered dict keyed by phase index (1-based string),
        each value contains tactic name, techniques list, hosts, confidence.
        """
        # Collect all techniques grouped by tactic
        by_tactic: dict[str, list] = {}

        for result in mapped_results:
            for layer_result in result.get("layers", []):
                tactic = str(layer_result.get("tactic", "unknown")).lower()
                entry  = {
                    "technique_id":   layer_result.get("technique_id", "T?"),
                    "technique_name": layer_result.get("technique_name", "Unknown"),
                    "confidence":     layer_result.get("confidence", 0.5),
                    "source":         layer_result.get("source", "unknown"),
                    "host":           result.get("host", ""),
                }
                # Skip ML pseudo-IDs (T-KW, T-ML) — not real ATT&CK IDs
                if entry["technique_id"].startswith("T-"):
                    continue
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                # Deduplicate by technique_id
                ids = [e["technique_id"] for e in by_tactic[tactic]]
                if entry["technique_id"] not in ids:
                    by_tactic[tactic].append(entry)

        # Build ordered chain
        chain = {}
        phase_num = 1

        for phase_key in PHASE_ORDER:
            if phase_key not in by_tactic:
                continue

            entries = by_tactic[phase_key]
            hosts   = list({e["host"] for e in entries if e["host"]})
            avg_conf = round(
                sum(e["confidence"] for e in entries) / len(entries), 3
            ) if entries else 0.0

            chain[str(phase_num)] = {
                "phase_name": PHASE_DISPLAY.get(phase_key, phase_key.replace("-", " ").title()),
                "tactic":     phase_key,
                "techniques": [
                    {"id": e["technique_id"], "name": e["technique_name"]}
                    for e in entries
                ],
                "hosts":      hosts,
                "confidence": avg_conf,
                "source":     entries[0]["source"] if entries else "unknown",
            }
            phase_num += 1

        print(f"  [Chain] {len(chain)} phases reconstructed.")
        return chain
