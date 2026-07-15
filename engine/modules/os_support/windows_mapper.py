"""
os_support/windows_mapper.py
------------------------------
Windows-specific ATT&CK technique and exploit mappings.
"""

WINDOWS_SERVICE_MAP = {
    "smb":   {"techniques": ["T1021.002", "T1570"], "tools": ["PsExec", "Impacket"]},
    "rdp":   {"techniques": ["T1021.001", "T1110"], "tools": ["xfreerdp", "Hydra"]},
    "winrm": {"techniques": ["T1021.006"],           "tools": ["Evil-WinRM"]},
    "msrpc": {"techniques": ["T1021.003"],           "tools": ["rpcclient"]},
    "mssql": {"techniques": ["T1505.001", "T1110"],  "tools": ["sqsh", "Hydra"]},
    "ldap":  {"techniques": ["T1018", "T1069"],      "tools": ["ldapsearch", "BloodHound"]},
}

WINDOWS_POST_COMMANDS = [
    "sysinfo", "getuid", "getsystem", "hashdump",
    "run post/multi/recon/local_exploit_suggester",
    "load kiwi", "creds_all",
    "arp", "ipconfig /all", "ps", "migrate",
]


class WindowsMapper:

    def service_map(self, service: str) -> dict:
        return WINDOWS_SERVICE_MAP.get(service.lower(), {})

    def post_commands(self) -> list[str]:
        return list(WINDOWS_POST_COMMANDS)
