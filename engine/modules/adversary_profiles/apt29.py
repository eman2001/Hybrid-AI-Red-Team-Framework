"""
adversary_profiles/apt29.py
-----------------------------
APT29 (Cozy Bear) — Russian SVR-linked threat actor.
"""

PROFILE = {
    "name":        "APT29",
    "aliases":     ["Cozy Bear", "The Dukes", "NOBELIUM"],
    "origin":      "Russia",
    "sponsor":     "SVR (Foreign Intelligence Service)",
    "motivation":  ["espionage", "data-theft"],
    "targets":     ["government", "think-tanks", "healthcare", "energy"],
    "tactics": [
        "initial-access", "execution", "persistence",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "exfiltration",
        "command-and-control",
    ],
    "techniques": [
        "T1566.001",  # Spearphishing Attachment
        "T1078",      # Valid Accounts
        "T1059.001",  # PowerShell
        "T1003.001",  # LSASS Memory
        "T1021.001",  # RDP
        "T1071.001",  # Web Protocols C2
        "T1083",      # File & Directory Discovery
        "T1560",      # Archive Collected Data
        "T1041",      # Exfiltration Over C2
    ],
    "tools":    ["SUNBURST", "TEARDROP", "Cobalt Strike", "WellMess"],
    "severity": "CRITICAL",
}
