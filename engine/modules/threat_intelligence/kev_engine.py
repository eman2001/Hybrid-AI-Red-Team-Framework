"""
threat_intelligence/kev_engine.py
-----------------------------------
CISA Known Exploited Vulnerabilities (KEV) catalog check.
Downloads the catalog once and caches it locally.
"""

import json
import os
import urllib.request
from datetime import datetime

KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = "data/kev_catalog.json"


# Embedded known exploited CVEs (CISA KEV catalog subset)
EMBEDDED_KEV = {
    "CVE-2017-0144","CVE-2019-0708","CVE-2021-44228","CVE-2021-26855",
    "CVE-2020-1472","CVE-2021-34527","CVE-2022-26134","CVE-2018-13379",
    "CVE-2010-2075","CVE-2011-2523","CVE-2007-2447","CVE-2020-5902",
    "CVE-2014-6271","CVE-2017-11882","CVE-2019-11580","CVE-2021-21985",
}

class KevEngine:

    def __init__(self):
        self._catalog: set[str] = set(EMBEDDED_KEV)
        self._load()

    def is_kev(self, cve: str) -> bool:
        return cve.upper() in self._catalog

    def _load(self):
        if os.path.exists(KEV_CACHE):
            try:
                with open(KEV_CACHE, encoding="utf-8") as f:
                    data = json.load(f)
                self._catalog = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
                print(f"  [KEV] {len(self._catalog)} known exploited CVEs loaded.")
                return
            except Exception:
                pass

        self._download()

    def _download(self):
        try:
            os.makedirs("data", exist_ok=True)
            urllib.request.urlretrieve(KEV_URL, KEV_CACHE)
            self._load()
        except Exception as e:
            print(f"  [KEV] Could not load catalog: {e}")
