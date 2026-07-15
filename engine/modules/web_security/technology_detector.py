"""
web_security/technology_detector.py
-------------------------------------
Fingerprints web technology stack from service banners, HTTP headers,
and nmap HTTP script output.  No active probing — passive analysis only.
"""

import re
import json
import urllib.request
from typing import Dict, List, Optional


# ── NVD API base (shared with web_findings) ────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Known signatures ────────────────────────────────────────────────────────
BANNER_SIGNATURES: Dict[str, List[str]] = {
    "apache":     ["apache", "httpd"],
    "nginx":      ["nginx"],
    "iis":        ["microsoft-iis", "iis"],
    "tomcat":     ["tomcat", "apache-coyote", "jserv"],
    "php":        ["php/", "x-powered-by: php"],
    "asp_net":    ["asp.net", "x-aspnet-version", "x-powered-by: asp.net"],
    "django":     ["django", "csrftoken"],
    "flask":      ["werkzeug", "flask"],
    "rails":      ["x-powered-by: phusion passenger", "x-runtime"],
    "wordpress":  ["wp-content", "wp-includes", "wordpress"],
    "joomla":     ["joomla", "/components/com_"],
    "drupal":     ["drupal", "x-generator: drupal"],
    "laravel":    ["laravel", "x-powered-by: lumen"],
    "express":    ["express", "x-powered-by: express"],
    "spring":     ["spring", "x-application-context"],
    "struts":     ["struts", ".action"],
    "mysql":      ["mysql"],
    "mssql":      ["sql server", "mssql"],
    "oracle":     ["oracle"],
    "mongodb":    ["mongodb"],
    "jquery":     ["jquery"],
    "bootstrap":  ["bootstrap"],
    "react":      ["react"],
    "angularjs":  ["ng-version", "angular"],
}

# Tech stacks → likely attack surfaces
ATTACK_SURFACE_MAP: Dict[str, List[str]] = {
    "php":       ["sql_injection", "xss", "xxe", "path_traversal"],
    "asp_net":   ["sql_injection", "xss", "misconfiguration"],
    "tomcat":    ["misconfiguration", "exposed_admin", "outdated_component"],
    "struts":    ["command_injection", "outdated_component"],
    "wordpress": ["broken_auth", "outdated_component", "xss"],
    "joomla":    ["sql_injection", "broken_auth", "outdated_component"],
    "drupal":    ["sql_injection", "broken_auth", "outdated_component"],
    "spring":    ["ssrf", "xxe", "misconfiguration"],
    "iis":       ["misconfiguration", "path_traversal"],
    "nginx":     ["misconfiguration"],
    "apache":    ["misconfiguration", "directory_listing"],
    "mysql":     ["sql_injection"],
    "mongodb":   ["broken_access_control", "misconfiguration"],
    "oracle":    ["sql_injection"],
}

# EOL markers: tech → max safe version prefix
EOL_MARKERS: Dict[str, str] = {
    "apache":    "2.2",
    "php":       "7.4",
    "tomcat":    "8.5",
    "iis":       "6.0",
    "jquery":    "1.",
    "wordpress": "5.8",
    "struts":    "2.3",
}

# tech → CPE prefix for NVD query
CPE_MAP: Dict[str, str] = {
    "apache":    "apache:http_server",
    "nginx":     "nginx:nginx",
    "php":       "php:php",
    "tomcat":    "apache:tomcat",
    "iis":       "microsoft:iis",
    "struts":    "apache:struts",
    "wordpress": "wordpress:wordpress",
    "spring":    "pivotal_software:spring_framework",
    "jquery":    "jquery:jquery",
}

# in-memory cache
_nvd_tech_cache: dict = {}


def fetch_nvd_by_product(tech: str, version: str) -> List[dict]:
    """
    Query NVD for CVEs by product keyword + version.
    Returns list of {cve_id, cvss, description}.
    Falls back to [] if offline.
    """
    cache_key = f"{tech}:{version}"
    if cache_key in _nvd_tech_cache:
        return _nvd_tech_cache[cache_key]

    try:
        keyword = tech.replace("_", " ")
        url = (f"{NVD_API_BASE}"
               f"?keywordSearch={urllib.request.quote(keyword)}"
               f"&resultsPerPage=3"
               f"&sortBy=publishedDate&sortOrder=desc")
        req = urllib.request.Request(
            url, headers={"User-Agent": "RedTeamFramework/2.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())

        results = []
        for item in data.get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc   = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:120]
                    break
            cvss_score = 0.0
            metrics = cve.get("metrics", {})
            for m in metrics.get("cvssMetricV31", []):
                cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                break
            if cve_id:
                results.append({"cve_id": cve_id, "cvss": cvss_score,
                                 "description": desc})

        _nvd_tech_cache[cache_key] = results
        return results

    except Exception:
        _nvd_tech_cache[cache_key] = []
        return []


class TechnologyDetector:
    """
    Detects web technology from passive data (banner, nmap output, headers).
    Enriches EOL components with live CVEs from NVD.
    """

    def detect(self, service_data: dict, enrich_nvd: bool = True) -> dict:
        """
        Parameters
        ----------
        service_data : dict
            Keys: host, port, service, product, version, banner (optional),
                  nmap_scripts (optional dict)
        enrich_nvd : bool
            If True, queries NVD for CVEs on detected EOL components.

        Returns
        -------
        {
          tech_stack, attack_surfaces, eol_risk,
          eol_components, raw_banner, version_hints, nvd_findings
        }
        """
        banner       = self._collect_banner(service_data)
        banner_lower = banner.lower()

        tech_stack:    List[str]       = []
        version_hints: Dict[str, str]  = {}

        for tech, keywords in BANNER_SIGNATURES.items():
            if any(kw in banner_lower for kw in keywords):
                tech_stack.append(tech)
                v = self._extract_version(banner_lower, tech)
                if v:
                    version_hints[tech] = v

        attack_surfaces: List[str] = []
        for tech in tech_stack:
            for surface in ATTACK_SURFACE_MAP.get(tech, []):
                if surface not in attack_surfaces:
                    attack_surfaces.append(surface)

        eol_components: List[str] = []
        for tech, max_safe in EOL_MARKERS.items():
            if tech in version_hints:
                v = version_hints[tech]
                if v.startswith(max_safe) or self._is_older(v, max_safe):
                    eol_components.append(f"{tech}/{v}")

        # NVD enrichment for EOL components
        nvd_findings: Dict[str, List[dict]] = {}
        if enrich_nvd:
            for component in eol_components:
                tech, ver = component.split("/", 1)
                cves = fetch_nvd_by_product(tech, ver)
                if cves:
                    nvd_findings[component] = cves
                    print(f"  [NVD] {component} → {len(cves)} CVE(s) found")

        return {
            "tech_stack":      tech_stack,
            "attack_surfaces": attack_surfaces,
            "eol_risk":        len(eol_components) > 0,
            "eol_components":  eol_components,
            "raw_banner":      banner[:500],
            "version_hints":   version_hints,
            "nvd_findings":    nvd_findings,
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _collect_banner(self, service_data: dict) -> str:
        parts = [
            service_data.get("product", ""),
            service_data.get("version", ""),
            service_data.get("banner", ""),
        ]
        scripts = service_data.get("nmap_scripts", {})
        for val in scripts.values():
            if isinstance(val, str):
                parts.append(val)
        return " ".join(filter(None, parts))

    def _extract_version(self, banner: str, tech: str) -> Optional[str]:
        patterns = [
            rf"{tech}[/\s]+([\d\.]+)",
            r"([\d]+\.[\d]+\.[\d]+)",
            r"([\d]+\.[\d]+)",
        ]
        for pattern in patterns:
            m = re.search(pattern, banner)
            if m:
                return m.group(1)
        return None

    def _is_older(self, version: str, max_safe: str) -> bool:
        try:
            v_parts = [int(x) for x in version.split(".")[:2]]
            m_parts = [int(x) for x in max_safe.rstrip(".").split(".")[:2]]
            return v_parts <= m_parts
        except (ValueError, AttributeError):
            return False
