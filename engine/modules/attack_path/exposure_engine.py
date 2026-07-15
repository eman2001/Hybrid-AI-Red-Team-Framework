"""
attack_path/exposure_engine.py
--------------------------------
Calculates surface exposure score for each host/service combination.
"""

from engine.config.constants import WELL_KNOWN_PORTS


class ExposureEngine:

    INTERNET_FACING_PORTS = {21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443}

    def score(self, port: int, service: str, product: str, version: str) -> dict:
        exposure = 0

        # Internet-facing port
        if port in self.INTERNET_FACING_PORTS:
            exposure += 30

        # Known high-risk service
        risky = {"smb", "rdp", "telnet", "ftp", "vnc"}
        if service.lower() in risky:
            exposure += 25

        # Well-known port
        if port in WELL_KNOWN_PORTS:
            exposure += 15

        # Version info leaked (fingerprinting possible)
        if version:
            exposure += 10

        return {
            "port":         port,
            "service":      service,
            "exposure":     min(exposure, 100),
            "internet_facing": port in self.INTERNET_FACING_PORTS,
        }

    def score_all(self, scan_results: dict) -> list[dict]:
        scored = []
        for host, data in scan_results.items():
            for p in data.get("ports", []):
                s = self.score(p["port"], p.get("service", ""),
                               p.get("product", ""), p.get("version", ""))
                s["host"] = host
                scored.append(s)
        return sorted(scored, key=lambda x: x["exposure"], reverse=True)
