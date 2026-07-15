"""
modules/scanner/__init__.py
---------------------------
Preserves original ScannerModule interface.
"""

import nmap
from engine.modules.scanner.nmap_parser        import NmapParser
from engine.modules.scanner.xml_parser         import XmlParser
from engine.modules.scanner.json_parser        import JsonParser
from engine.modules.scanner.service_fingerprint import ServiceFingerprint


class ScannerModule:

    def __init__(self, target: str):
        self.target      = target
        self._fp         = ServiceFingerprint()

    def scan_target(self) -> dict:
        print(f"\n[R3/R4/R5] Starting Scan on: {self.target}")

        parser  = NmapParser(self.target)
        raw     = parser.run()
        results = {}

        for host in raw.all_hosts():
            print(f"\n[+] Host: {host}")
            os_name = parser.get_os(host)
            results[host] = {"os": os_name, "ports": []}
            if os_name != "unknown":
                print(f"  OS: {os_name}")

            for proto in raw[host].all_protocols():
                for port, svc in raw[host][proto].items():
                    port_info = {
                        "port":    port,
                        "service": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                    }
                    results[host]["ports"].append(port_info)
                    print(f"  Port: {port} | {svc.get('name')} | "
                          f"{svc.get('product')} {svc.get('version')}")

        self._fp.enrich_all(results)
        return results

    # Convenience helpers exposed for external use
    @staticmethod
    def from_xml(path: str) -> dict:
        return XmlParser().parse_file(path)

    @staticmethod
    def from_json(path: str) -> dict:
        return JsonParser().parse_file(path)


__all__ = ["ScannerModule", "NmapParser", "XmlParser", "JsonParser", "ServiceFingerprint"]
