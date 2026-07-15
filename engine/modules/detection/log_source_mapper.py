"""
detection/log_source_mapper.py
--------------------------------
Maps ATT&CK techniques to required log sources for detection.
"""

TECHNIQUE_LOG_MAP = {
    "T1003": ["Security", "System", "PowerShell/Operational"],
    "T1059": ["Security", "PowerShell/Operational", "Sysmon"],
    "T1082": ["Sysmon", "Security"],
    "T1021": ["Security", "System", "Network"],
    "T1547": ["Security", "System", "Registry"],
    "T1053": ["Security", "System", "TaskScheduler"],
    "T1190": ["WebServer", "Firewall", "IDS"],
    "T1110": ["Security", "Authentication"],
    "T1068": ["Security", "System", "Sysmon"],
    "T1016": ["Sysmon", "Network"],
    "T1057": ["Sysmon", "Security"],
    "T1033": ["Sysmon", "Security"],
    "T1105": ["Firewall", "Network", "Proxy"],
    "T1005": ["Sysmon", "Security"],
}


class LogSourceMapper:

    def sources_for(self, technique_id: str) -> list[str]:
        return TECHNIQUE_LOG_MAP.get(technique_id, ["Security", "Sysmon"])

    def map_all(self, techniques: list[dict]) -> dict:
        result = {}
        for t in techniques:
            tid = t.get("technique_id", "")
            if tid:
                result[tid] = self.sources_for(tid)
        return result
