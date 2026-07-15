"""
scanner/service_fingerprint.py
-------------------------------
Enriches a port entry with CPE / product fingerprint
and normalises service names to a canonical form.
"""

SERVICE_ALIASES = {
    "microsoft-ds": "smb",
    "netbios-ssn":  "smb",
    "ms-wbt-server":"rdp",
    "domain":       "dns",
    "www":          "http",
    "ssl/http":     "https",
    "oracle-tns":   "oracle",
    "ms-sql-s":     "mssql",
}


class ServiceFingerprint:

    def enrich(self, port_info: dict) -> dict:
        """Add canonical_service and cpe fields to a port dict."""
        service = port_info.get("service", "").lower()
        port_info["canonical_service"] = SERVICE_ALIASES.get(service, service)
        port_info.setdefault("cpe", "")
        return port_info

    def enrich_all(self, scan_results: dict) -> dict:
        for host_data in scan_results.values():
            host_data["ports"] = [self.enrich(p) for p in host_data.get("ports", [])]
        return scan_results
