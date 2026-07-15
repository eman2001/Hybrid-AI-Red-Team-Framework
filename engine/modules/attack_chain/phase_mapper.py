"""
attack_chain/phase_mapper.py
------------------------------
Maps ATT&CK tactic slugs to ordered kill-chain phase numbers and display names.
"""

PHASE_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

PHASE_DISPLAY = {p: p.replace("-", " ").title() for p in PHASE_ORDER}
PHASE_DISPLAY.update({
    "initial-access":       "Initial Access",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "lateral-movement":     "Lateral Movement",
    "command-and-control":  "Command & Control",
})


class PhaseMapper:

    def phase_num(self, tactic: str) -> int:
        try:
            return PHASE_ORDER.index(tactic.lower()) + 1
        except ValueError:
            return 99

    def display(self, tactic: str) -> str:
        return PHASE_DISPLAY.get(tactic.lower(), tactic.replace("-", " ").title())

    def ordered(self, tactics: list[str]) -> list[str]:
        return sorted(set(tactics), key=lambda t: self.phase_num(t))
