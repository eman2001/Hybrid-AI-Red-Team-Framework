"""
scanner/xml_parser.py
---------------------
Parses nmap XML output files (saved with -oX) into scan_results format.
"""

import xml.etree.ElementTree as ET


class XmlParser:

    def parse_file(self, xml_path: str) -> dict:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        return self._parse_root(root)

    def parse_string(self, xml_str: str) -> dict:
        root = ET.fromstring(xml_str)
        return self._parse_root(root)

    def _parse_root(self, root) -> dict:
        results = {}
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")

            os_name = "unknown"
            osmatch = host_el.find(".//osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "unknown")

            ports = []
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc = port_el.find("service") or {}
                ports.append({
                    "port":    int(port_el.get("portid", 0)),
                    "service": svc.get("name", "") if hasattr(svc, "get") else "",
                    "product": svc.get("product", "") if hasattr(svc, "get") else "",
                    "version": svc.get("version", "") if hasattr(svc, "get") else "",
                })

            results[ip] = {"os": os_name, "ports": ports}
        return results
