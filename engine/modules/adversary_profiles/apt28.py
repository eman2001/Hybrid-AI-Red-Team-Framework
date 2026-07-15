"""
adversary_profiles/apt28.py
-----------------------------
APT28 (Fancy Bear) — Russian GRU-linked threat actor.
"""

PROFILE = {
    "name":        "APT28",
    "aliases":     ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
    "origin":      "Russia",
    "sponsor":     "GRU (Military Intelligence)",
    "motivation":  ["espionage", "influence-operations"],
    "targets":     ["government", "military", "political-parties", "aerospace"],
    "tactics": [
        "reconnaissance", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion",
        "credential-access", "discovery", "lateral-movement",
        "collection", "exfiltration",
    ],
    "techniques": [
        "T1595",      # Active Scanning
        "T1566.002",  # Spearphishing Link
        "T1059.003",  # Windows Command Shell
        "T1547.001",  # Registry Run Key
        "T1068",      # Exploitation for PrivEsc
        "T1003",      # OS Credential Dumping
        "T1016",      # System Network Config Discovery
        "T1021.002",  # SMB/Windows Admin Shares
        "T1074",      # Data Staged
        "T1048",      # Exfiltration Over Alternative Protocol
    ],
    "tools":    ["X-Agent", "X-Tunnel", "Zebrocy", "LoJax", "Drovorub"],
    "severity": "CRITICAL",
}
