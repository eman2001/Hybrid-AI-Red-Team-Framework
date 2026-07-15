"""
os_support/linux_mapper.py
----------------------------
Linux-specific ATT&CK technique and exploit mappings.
"""

LINUX_SERVICE_MAP = {
    "ssh":    {"techniques": ["T1021.004", "T1110"], "tools": ["Hydra", "ssh-audit"]},
    "ftp":    {"techniques": ["T1021.005", "T1110"], "tools": ["Hydra", "ftp"]},
    "telnet": {"techniques": ["T1021", "T1110"],     "tools": ["Hydra", "telnet"]},
    "nfs":    {"techniques": ["T1039", "T1083"],     "tools": ["showmount", "mount"]},
    "smtp":   {"techniques": ["T1566.001"],          "tools": ["swaks", "sendmail"]},
    "mysql":  {"techniques": ["T1505.001", "T1110"], "tools": ["mysql", "Hydra"]},
    "http":   {"techniques": ["T1190", "T1059.007"], "tools": ["nikto", "sqlmap"]},
}

LINUX_POST_COMMANDS = [
    "shell id", "shell uname -a", "shell whoami",
    "shell cat /etc/passwd", "shell cat /etc/shadow",
    "shell find / -perm -4000 2>/dev/null",
    "shell ss -tulnp", "shell ps aux",
    "shell arp -n", "shell ifconfig",
]


class LinuxMapper:

    def service_map(self, service: str) -> dict:
        return LINUX_SERVICE_MAP.get(service.lower(), {})

    def post_commands(self) -> list[str]:
        return list(LINUX_POST_COMMANDS)
