"""
adversary_profiles/volt_typhoon.py
-------------------------------------
Volt Typhoon — Chinese state-sponsored, living-off-the-land actor.
"""

PROFILE = {
    "name":        "Volt Typhoon",
    "aliases":     ["BRONZE SILHOUETTE", "DEV-0391"],
    "origin":      "China",
    "sponsor":     "PRC State",
    "motivation":  ["espionage", "pre-positioning"],
    "targets":     ["critical-infrastructure", "communications", "government",
                    "maritime", "transportation"],
    "tactics": [
        "reconnaissance", "initial-access", "execution",
        "persistence", "defense-evasion", "discovery",
        "lateral-movement", "collection", "command-and-control",
    ],
    "techniques": [
        "T1190",      # Exploit Public-Facing Application
        "T1078",      # Valid Accounts
        "T1059.003",  # Windows Command Shell (LOLBins)
        "T1036",      # Masquerading
        "T1003",      # Credential Dumping
        "T1049",      # System Network Connections Discovery
        "T1021.001",  # RDP
        "T1560",      # Archive Collected Data
        "T1572",      # Protocol Tunneling
    ],
    "tools":    ["netsh", "wmic", "ntdsutil", "PowerShell", "FRP"],
    "severity": "CRITICAL",
    "notes":    "Primarily uses built-in OS tools to avoid detection (living-off-the-land).",
}
