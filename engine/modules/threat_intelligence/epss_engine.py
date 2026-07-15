"""
threat_intelligence/epss_engine.py
------------------------------------
EPSS (Exploit Prediction Scoring System) score lookup.
Fetches from the FIRST.org EPSS API. Falls back to heuristic if offline.
"""

import json
import urllib.request

EPSS_API = "https://api.first.org/data/v1/epss?cve="

# Heuristic: recent/famous CVEs with known high exploitation
EPSS_KNOWN = {
    "CVE-2017-0144": 0.975,
    "CVE-2021-44228": 0.972,
    "CVE-2019-0708": 0.961,
    "CVE-2014-6271": 0.960,
    "CVE-2011-2523": 0.855,
}


class EpssEngine:

    def score(self, cve: str) -> float:
        """Return EPSS probability 0.0–1.0 for a CVE."""
        try:
            url = f"{EPSS_API}{cve}"
            with urllib.request.urlopen(url, timeout=4) as r:
                data = json.loads(r.read())
            items = data.get("data", [])
            if items:
                return float(items[0].get("epss", 0.0))
        except Exception:
            pass
        return EPSS_KNOWN.get(cve, 0.1)

    def risk_label(self, epss: float) -> str:
        if epss >= 0.7: return "VERY_HIGH"
        if epss >= 0.4: return "HIGH"
        if epss >= 0.1: return "MEDIUM"
        return "LOW"
