"""
cve_enricher.py  -  Layer 0: CVE -> NVD -> CWE -> ATT&CK Technique
Confidence: 0.88 - 0.93

- اذا الشبكة متاحة: يسأل NVD API ويحفظ في cache
- اذا الشبكة مقطوعة: يشتغل من cache المحفوظ
- اذا CVE جديد وما في انترنت: يكمل بدونه بدون error
"""

import json
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CACHE_PATH = "data/cve_cache.json"

CWE_TO_TECHNIQUE = {
    "CWE-78":  ("T1059", "Command and Scripting Interpreter",     "execution",            0.90),
    "CWE-89":  ("T1190", "Exploit Public-Facing Application",     "initial-access",       0.90),
    "CWE-22":  ("T1083", "File and Directory Discovery",          "discovery",            0.85),
    "CWE-287": ("T1078", "Valid Accounts",                        "initial-access",       0.88),
    "CWE-200": ("T1082", "System Information Discovery",          "discovery",            0.85),
    "CWE-20":  ("T1190", "Exploit Public-Facing Application",     "initial-access",       0.87),
    "CWE-119": ("T1203", "Exploitation for Client Execution",     "execution",            0.88),
    "CWE-416": ("T1203", "Exploitation for Client Execution",     "execution",            0.87),
    "CWE-476": ("T1499", "Endpoint Denial of Service",            "impact",               0.85),
    "CWE-502": ("T1059", "Command and Scripting Interpreter",     "execution",            0.88),
    "CWE-918": ("T1090", "Proxy",                                 "command-and-control",  0.85),
    "CWE-434": ("T1190", "Exploit Public-Facing Application",     "initial-access",       0.89),
    "CWE-611": ("T1190", "Exploit Public-Facing Application",     "initial-access",       0.87),
    "CWE-798": ("T1078", "Valid Accounts",                        "initial-access",       0.90),
    "CWE-306": ("T1078", "Valid Accounts",                        "initial-access",       0.88),
    "CWE-269": ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation", 0.90),
    "CWE-732": ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation", 0.87),
    "CWE-426": ("T1574", "Hijack Execution Flow",                 "persistence",          0.86),
    "CWE-427": ("T1574", "Hijack Execution Flow",                 "persistence",          0.86),
    "CWE-352": ("T1185", "Browser Session Hijacking",             "collection",           0.85),
}


def _make_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


class CVEEnricher:

    def __init__(self):
        self._cache   = self._load_cache()
        self._session = _make_session()

    def resolve(self, context: dict) -> dict | None:
        cve = context.get("cve", "").upper().strip()
        if not cve or not cve.startswith("CVE-"):
            return None

        if cve in self._cache:
            print(f"  [CVE] Cache hit: {cve}")
            return self._map(self._cache[cve], cve)

        print(f"  [CVE] Querying NVD for {cve} ...")
        try:
            r = self._session.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                timeout=10
            )
            if r.status_code != 200:
                print(f"  [CVE] NVD returned {r.status_code} - skipping.")
                return None

            data  = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_obj = vulns[0].get("cve", {})
            cwe_ids = []
            for weakness in cve_obj.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        val = desc.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(val)

            cve_data = {"cwe_ids": cwe_ids, "cve_id": cve}
            self._cache[cve] = cve_data
            self._save_cache()
            print(f"  [CVE] Cached {cve} -> CWEs: {cwe_ids}")
            return self._map(cve_data, cve)

        except requests.exceptions.Timeout:
            print(f"  [CVE] Timeout - no internet? continuing without.")
            return None
        except requests.exceptions.ConnectionError:
            print(f"  [CVE] No internet connection - continuing without CVE enrichment.")
            return None
        except Exception as e:
            print(f"  [CVE] Unexpected error: {e} - skipping.")
            return None

    def _map(self, cve_data: dict, cve_id: str) -> dict | None:
        for cwe in cve_data.get("cwe_ids", []):
            if cwe in CWE_TO_TECHNIQUE:
                tid, tname, tactic, conf = CWE_TO_TECHNIQUE[cwe]
                print(f"  [CVE] {cve_id} -> {cwe} -> {tid} ({tactic})")
                return {
                    "technique_id":   tid,
                    "technique_name": tname,
                    "tactic":         tactic,
                    "confidence":     conf,
                    "source":         "cve_enricher",
                    "cve":            cve_id,
                    "cwe":            cwe,
                }
        print(f"  [CVE] No CWE mapping found for {cve_id}.")
        return None

    def _load_cache(self) -> dict:
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=2)
