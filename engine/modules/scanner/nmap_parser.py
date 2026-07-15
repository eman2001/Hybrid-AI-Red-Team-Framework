"""
scanner/nmap_parser.py
----------------------
Runs nmap -sV -sC -O --open and returns raw structured data.
"""
import nmap

class NmapParser:
    SCAN_ARGS = "-sV -sC -O --open --host-timeout 120s"

    def __init__(self, target: str):
        self.target  = target
        self.scanner = nmap.PortScanner()

    def run(self) -> nmap.PortScanner:
        print(f"[Scanner] nmap {self.SCAN_ARGS} {self.target}")
        self.scanner.scan(hosts=self.target, arguments=self.SCAN_ARGS)
        return self.scanner

    def get_os(self, host: str) -> str:
        """استخرج OS من نتائج الـ scan"""
        try:
            osmatch = self.scanner[host].get("osmatch", [])
            if osmatch:
                return osmatch[0].get("name", "unknown")
        except Exception:
            pass
        return "unknown"
