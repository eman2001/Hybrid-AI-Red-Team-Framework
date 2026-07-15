"""
threat_intelligence/cvss_engine.py
------------------------------------
CVSS v3.1 score lookup and band classification.

Lookup order (no hardcoded tables):
  1. GitHub - MITRE's official CVEProject/cvelistV5 repo (raw.githubusercontent.com),
              cached locally in data/cvss_github_cache.json so repeat runs are instant
  2. NVD API - only if VULN_NVD_API_KEY is configured
  3. None    - caller decides the fallback (keeps an existing finding's own CVSS
               instead of silently overwriting it with a generic default)
"""

import json
import urllib.request
from pathlib import Path

from engine.config.settings import VULN_NVD_API_URL, VULN_NVD_API_KEY

_CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "cvss_github_cache.json"


class CvssEngine:

    def __init__(self):
        self._cache = self._load_cache()

    def score(self, cve: str):
        """Returns a CVSS base score, or None if no data could be found anywhere."""
        if not cve:
            return None
        gh = self._github_lookup(cve)
        if gh is not None:
            return gh
        if VULN_NVD_API_KEY:
            nvd = self._nvd_lookup(cve)
            if nvd is not None:
                return nvd
        return None

    def band(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score >= 0.1: return "LOW"
        return "NONE"

    # -- GitHub (MITRE CVEProject/cvelistV5) --------------------------------
    def _github_lookup(self, cve: str):
        if cve in self._cache:
            return self._cache[cve]
        try:
            parts = cve.split("-")
            year, num = parts[1], parts[2].zfill(4)
            bucket = num[:-3] + "xxx"
            url = (f"https://raw.githubusercontent.com/CVEProject/cvelistV5/"
                   f"main/cves/{year}/{bucket}/{cve}.json")
            req = urllib.request.Request(url, headers={"User-Agent": "redteam-framework"})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read())
            metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
            for m in metrics:
                for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    if key in m:
                        score = m[key].get("baseScore")
                        if score is not None:
                            self._cache[cve] = score
                            self._save_cache()
                            return score
        except Exception:
            pass
        return None

    def _load_cache(self) -> dict:
        try:
            return json.loads(_CACHE_PATH.read_text())
        except Exception:
            return {}

    def _save_cache(self):
        try:
            _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _CACHE_PATH.write_text(json.dumps(self._cache, indent=2))
        except Exception:
            pass

    # -- NVD (only used if an API key is configured) ------------------------
    def _nvd_lookup(self, cve: str):
        try:
            url = f"{VULN_NVD_API_URL}?cveId={cve}"
            req = urllib.request.Request(url, headers={"apiKey": VULN_NVD_API_KEY})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0]["cve"].get("metrics", {})
                cvss3 = metrics.get("cvssMetricV31", [{}])[0]
                return cvss3.get("cvssData", {}).get("baseScore")
        except Exception:
            pass
        return None
