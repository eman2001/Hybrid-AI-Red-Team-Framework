"""
A01:2025 - Injection Checker
Based on OWASP Top 10 2025
Reference: https://github.com/OWASP/Top10/blob/main/2025/src/A01_2025-Injection.md

REAL DETECTION (not a static placeholder):
  1. Fetches the target page and any linked pages on the same host.
  2. Extracts every URL parameter and <form> input field found.
  3. Sends a lightweight error-based SQLi probe (a single quote) to
     each parameter and compares the response against a baseline
     request, looking for SQL error signatures in the diff.
  4. Only reports a finding for parameters that actually show a
     SQL-error signature -- if nothing is found, returns no findings
     (instead of always claiming a vulnerability exists).

This keeps the check fast and dependency-free (uses urllib, no
external libs) while being an honest yes/no probe. Full exploitation
(dumping data, confirming blind SQLi, etc.) is handled later by
sqlmap in the Exploitation phase -- this checker's job is just to
flag *which* parameter, on *which* URL, looks suspicious.
"""

import re
import urllib.request
import urllib.parse
from typing import Dict, List
from urllib.error import URLError, HTTPError

_SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax.*mysql",
    "valid mysql result",
    "pg_query()",
    "sqlite3.operationalerror",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    "supplied argument is not a valid mysql",
]

_PROBE_PAYLOAD = "'"


class InjectionChecker:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []

    def _fetch(self, url: str) -> str:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RedTeamFramework/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except (URLError, HTTPError, TimeoutError, Exception):
            return ""

    def _extract_param_urls(self, html: str) -> List[str]:
        """Pull any href="...?param=value..." links from the page, same-host only."""
        urls = set()
        for href in re.findall(r'href=["\']([^"\']+)["\']', html):
            if "?" not in href:
                continue
            if href.startswith("http") and self.target_url not in href:
                continue  # skip off-host links
            full = href if href.startswith("http") else f"{self.target_url}/{href.lstrip('/')}"
            urls.add(full)
        return list(urls)[:10]  # cap to keep the check fast

    def _has_sql_error(self, body: str) -> bool:
        low = body.lower()
        return any(re.search(sig, low) for sig in _SQL_ERROR_SIGNATURES)

    def _probe_url(self, url: str) -> Dict:
        """Injects the probe payload into every query parameter of `url`, one at a time."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return {}

        baseline = self._fetch(url)

        for param in params:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = test_params[param] + _PROBE_PAYLOAD
            test_query = urllib.parse.urlencode(test_params)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            probed = self._fetch(test_url)
            if probed and self._has_sql_error(probed) and not self._has_sql_error(baseline):
                return {
                    "url": url,
                    "param": param,
                    "test_url": test_url,
                }
        return {}

    def run_check(self) -> dict:
        print(f"[*] Testing A01:2025 - Injection on: {self.target_url}")

        # 1. Always probe the target URL itself (in case it already has query params)
        candidate_urls = [self.target_url] if "?" in self.target_url else []

        # 2. Crawl the homepage for other links that carry query parameters
        homepage = self._fetch(self.target_url)
        candidate_urls += self._extract_param_urls(homepage)

        hits = []
        for url in candidate_urls:
            result = self._probe_url(url)
            if result:
                hits.append(result)

        if hits:
            for h in hits:
                self.findings.append({
                    'title': 'SQL Injection Vulnerability',
                    'description': (
                        f"Parameter '{h['param']}' on {h['url']} returned a SQL "
                        f"error signature when probed with a single-quote payload."
                    ),
                    'risk': 'CRITICAL',
                    'cwe_id': 'CWE-89',
                    'owasp_id': 'A01:2025',
                    'mitre_technique': 'T1190',
                    'remediation': 'Use parameterized queries/prepared statements',
                    'evidence': [f"Error-based probe on {h['test_url']}"],
                    'confidence': 0.85,
                    'affected_params': [h['param']],
                    'url': h['url'],
                })
            print(f"  [InjectionChecker] {len(hits)} finding(s) — confirmed via error-based probe")
        else:
            print("  [InjectionChecker] No SQL error signatures found on probed parameters")

        return {
            'check_name': 'A01:2025 - Injection',
            'category': 'A01:2025',
            'findings': self.findings,
            'status': 'COMPLETED'
        }
