"""
recon/os_detection.py
---------------------
Passive OS detection — combines nmap -O output with banner/TTL heuristics.
"""

import nmap
from engine.config.constants import OS_WINDOWS, OS_LINUX, OS_MACOS, OS_UNKNOWN
from engine.config.constants import OS_KEYWORDS_WINDOWS, OS_KEYWORDS_LINUX


class OsDetection:

    def __init__(self, host: str):
        self.host    = host
        self.scanner = nmap.PortScanner()

    def detect(self) -> str:
        """Return OS_WINDOWS | OS_LINUX | OS_MACOS | OS_UNKNOWN."""
        print(f"[Recon] OS detection → {self.host}")

        try:
            self.scanner.scan(hosts=self.host, arguments="-O --osscan-guess")
            host_data = self.scanner[self.host]

            # nmap osmatch
            osmatches = host_data.get("osmatch", [])
            if osmatches:
                name = osmatches[0].get("name", "").lower()
                return self._classify(name)

            # TTL heuristic from hostnames / extra info
            extra = str(host_data.get("vendor", "")).lower()
            return self._classify(extra)

        except Exception as e:
            print(f"  [-] OS detection failed: {e}")
            return OS_UNKNOWN

    @staticmethod
    def _classify(text: str) -> str:
        for kw in OS_KEYWORDS_WINDOWS:
            if kw in text:
                return OS_WINDOWS
        for kw in OS_KEYWORDS_LINUX:
            if kw in text:
                return OS_LINUX
        if "mac" in text or "darwin" in text:
            return OS_MACOS
        return OS_UNKNOWN
