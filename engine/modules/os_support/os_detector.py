"""
os_support/os_detector.py
---------------------------
Detects target OS from scan results using nmap output and port heuristics.
"""

from engine.config.constants import OS_WINDOWS, OS_LINUX, OS_UNKNOWN
from engine.config.constants import OS_KEYWORDS_WINDOWS, OS_KEYWORDS_LINUX


class OsDetector:

    WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}
    LINUX_PORTS   = {22, 111, 2049}

    def detect(self, host_data: dict) -> str:
        # From nmap OS field
        os_str = host_data.get("os", "").lower()
        for kw in OS_KEYWORDS_WINDOWS:
            if kw in os_str:
                return OS_WINDOWS
        for kw in OS_KEYWORDS_LINUX:
            if kw in os_str:
                return OS_LINUX

        # From open ports heuristic
        open_ports = {p["port"] for p in host_data.get("ports", [])}
        win_score  = len(open_ports & self.WINDOWS_PORTS)
        lin_score  = len(open_ports & self.LINUX_PORTS)

        if win_score > lin_score:   return OS_WINDOWS
        if lin_score > win_score:   return OS_LINUX
        return OS_UNKNOWN
