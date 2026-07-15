"""
adversary_profiles/lazarus.py
-------------------------------
Lazarus Group — North Korean state-sponsored threat actor.
"""

PROFILE = {
    "name":        "Lazarus Group",
    "aliases":     ["HIDDEN COBRA", "Guardians of Peace", "ZINC"],
    "origin":      "North Korea",
    "sponsor":     "RGB (Reconnaissance General Bureau)",
    "motivation":  ["financial-gain", "espionage", "sabotage"],
    "targets":     ["finance", "cryptocurrency", "defense", "media"],
    "tactics": [
        "initial-access", "execution", "persistence",
        "privilege-escalation", "defense-evasion",
        "credential-access", "lateral-movement",
        "collection", "impact", "exfiltration",
    ],
    "techniques": [
        "T1566.001",  # Spearphishing Attachment
        "T1059.001",  # PowerShell
        "T1547",      # Boot Autostart
        "T1055",      # Process Injection
        "T1003",      # Credential Dumping
        "T1021",      # Remote Services
        "T1113",      # Screen Capture
        "T1486",      # Data Encrypted for Impact (ransomware)
        "T1041",      # Exfiltration Over C2
    ],
    "tools":    ["WannaCry", "ELECTRICFISH", "BADCALL", "Bankshot", "HOPLIGHT"],
    "severity": "CRITICAL",
}
