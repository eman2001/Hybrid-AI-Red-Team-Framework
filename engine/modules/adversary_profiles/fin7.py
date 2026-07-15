"""
adversary_profiles/fin7.py
----------------------------
FIN7 — Financially motivated cybercrime group (Carbanak).
"""

PROFILE = {
    "name":        "FIN7",
    "aliases":     ["Carbanak", "ELBRUS", "ITG14"],
    "origin":      "Eastern Europe",
    "sponsor":     "Criminal",
    "motivation":  ["financial-gain"],
    "targets":     ["retail", "hospitality", "restaurant", "finance", "healthcare"],
    "tactics": [
        "initial-access", "execution", "persistence",
        "defense-evasion", "credential-access",
        "collection", "exfiltration", "impact",
    ],
    "techniques": [
        "T1566.001",  # Spearphishing Attachment
        "T1204.002",  # Malicious File
        "T1059.001",  # PowerShell
        "T1547.001",  # Registry Run Key
        "T1027",      # Obfuscated Files
        "T1056.001",  # Keylogging
        "T1041",      # Exfiltration Over C2
        "T1486",      # Data Encrypted for Impact
        "T1539",      # Steal Web Session Cookie
    ],
    "tools":    ["Carbanak", "GRIFFON", "BOOSTWRITE", "RDFSNIFFER", "Cobalt Strike"],
    "severity": "HIGH",
}
