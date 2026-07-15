"""
os_support/windows_post_mapper.py
-----------------------------------
Maps Windows post-exploitation output to ATT&CK techniques.
"""

WIN_POST_MAP = {
    "getsystem":    ("T1068",     "Exploitation for Privilege Escalation", "privilege-escalation", 0.93),
    "hashdump":     ("T1003.002", "Security Account Manager",              "credential-access",    0.95),
    "creds_all":    ("T1003",     "OS Credential Dumping",                 "credential-access",    0.95),
    "kiwi":         ("T1003",     "OS Credential Dumping",                 "credential-access",    0.95),
    "migrate":      ("T1055",     "Process Injection",                     "defense-evasion",      0.88),
    "load kiwi":    ("T1003",     "OS Credential Dumping",                 "credential-access",    0.90),
    "arp":          ("T1016",     "System Network Configuration Discovery","discovery",            0.93),
    "ipconfig":     ("T1016",     "System Network Configuration Discovery","discovery",            0.93),
    "ps":           ("T1057",     "Process Discovery",                     "discovery",            0.93),
    "sysinfo":      ("T1082",     "System Information Discovery",          "discovery",            0.95),
    "getuid":       ("T1033",     "System Owner/User Discovery",           "discovery",            0.95),
    "persistence":  ("T1547",     "Boot/Logon Autostart Execution",        "persistence",          0.87),
}


class WindowsPostMapper:

    def map(self, commands: list[str]) -> list[dict]:
        results = []
        seen = set()
        for cmd in commands:
            cl = cmd.lower().strip()
            for kw, (tid, name, tactic, conf) in WIN_POST_MAP.items():
                if kw in cl and tid not in seen:
                    results.append({"technique_id": tid, "technique_name": name,
                                    "tactic": tactic, "confidence": conf,
                                    "source": "post_exploit_windows", "command": cmd})
                    seen.add(tid)
                    break
        return results
