"""
os_support/linux_post_mapper.py
---------------------------------
Maps Linux post-exploitation output to ATT&CK techniques.
"""

LINUX_POST_MAP = {
    "id":           ("T1033",     "System Owner/User Discovery",          "discovery",            0.95),
    "uname":        ("T1082",     "System Information Discovery",         "discovery",            0.95),
    "whoami":       ("T1033",     "System Owner/User Discovery",          "discovery",            0.95),
    "passwd":       ("T1003.008", "/etc/passwd and /etc/shadow",          "credential-access",    0.90),
    "shadow":       ("T1003.008", "/etc/passwd and /etc/shadow",          "credential-access",    0.95),
    "perm -4000":   ("T1548.001", "Setuid and Setgid",                    "privilege-escalation", 0.88),
    "ps aux":       ("T1057",     "Process Discovery",                    "discovery",            0.93),
    "ss -":         ("T1049",     "System Network Connections Discovery", "discovery",            0.93),
    "ifconfig":     ("T1016",     "System Network Configuration Discovery","discovery",           0.93),
    "arp":          ("T1016",     "System Network Configuration Discovery","discovery",           0.90),
    "crontab":      ("T1053.003", "Cron",                                 "persistence",          0.88),
    "bashrc":       ("T1546.004", ".bash_profile and .bashrc",            "persistence",          0.87),
}


class LinuxPostMapper:

    def map(self, commands: list[str]) -> list[dict]:
        results = []
        seen = set()
        for cmd in commands:
            cl = cmd.lower().strip()
            for kw, (tid, name, tactic, conf) in LINUX_POST_MAP.items():
                if kw in cl and tid not in seen:
                    results.append({"technique_id": tid, "technique_name": name,
                                    "tactic": tactic, "confidence": conf,
                                    "source": "post_exploit_linux", "command": cmd})
                    seen.add(tid)
                    break
        return results
