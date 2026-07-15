"""
detection/sigma_mapper.py
---------------------------
Maps ATT&CK techniques to Sigma rule IDs and detection logic summaries.
"""

import os
import json

# Built-in technique → sigma rule mapping
SIGMA_MAP = {
    "T1059.001": {"rule_id": "sigma-ps-exec",     "title": "PowerShell Execution",         "log_source": "windows/powershell"},
    "T1003.001": {"rule_id": "sigma-lsass",       "title": "LSASS Memory Access",          "log_source": "windows/security"},
    "T1021.001": {"rule_id": "sigma-rdp",         "title": "Remote Desktop Login",         "log_source": "windows/security"},
    "T1021.002": {"rule_id": "sigma-smb-admin",   "title": "SMB Admin Share Access",       "log_source": "windows/security"},
    "T1547.001": {"rule_id": "sigma-reg-run",     "title": "Registry Run Key Persistence", "log_source": "windows/registry"},
    "T1053.005": {"rule_id": "sigma-schtask",     "title": "Scheduled Task Creation",      "log_source": "windows/security"},
    "T1190":     {"rule_id": "sigma-web-exploit", "title": "Web Application Exploit",      "log_source": "webserver"},
    "T1110":     {"rule_id": "sigma-bruteforce",  "title": "Brute Force Attempt",          "log_source": "windows/security"},
    "T1068":     {"rule_id": "sigma-privesc",     "title": "Privilege Escalation Attempt", "log_source": "windows/security"},
    "T1486":     {"rule_id": "sigma-ransomware",  "title": "Ransomware File Encryption",   "log_source": "windows/sysmon"},
    "T1566.001": {"rule_id": "sigma-phish-attach","title": "Spearphishing Attachment",     "log_source": "email"},
    "T1082":     {"rule_id": "sigma-sysinfo",     "title": "System Info Discovery",        "log_source": "windows/sysmon"},
}


class SigmaMapper:

    def __init__(self, rules_dir: str = "data/sigma_rules"):
        self._rules_dir = rules_dir
        self._custom: dict = {}
        self._load_custom()

    def _load_custom(self):
        if not os.path.isdir(self._rules_dir):
            return
        for fname in os.listdir(self._rules_dir):
            if fname.endswith(".json"):
                try:
                    with open(os.path.join(self._rules_dir, fname)) as f:
                        rule = json.load(f)
                    tid = rule.get("technique_id", "")
                    if tid:
                        self._custom[tid] = rule
                except Exception:
                    pass

    def map(self, technique_id: str) -> dict | None:
        return self._custom.get(technique_id) or SIGMA_MAP.get(technique_id)

    def map_all(self, technique_ids: list[str]) -> list[dict]:
        results = []
        for tid in technique_ids:
            rule = self.map(tid)
            if rule:
                results.append({"technique_id": tid, **rule})
        return results
