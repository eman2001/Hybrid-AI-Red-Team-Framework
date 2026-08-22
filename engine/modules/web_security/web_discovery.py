"""
web_security/web_discovery.py
---------------------------------
WebDiscovery -- a shared, bounded crawler that turns "one static URL"
into a real list of same-host endpoints (links, forms, query params,
robots.txt/sitemap.xml entries, and a short curated probe of common
REST/API path prefixes) that every OWASP checker can test against.

This directly targets the empirically-observed gap: on a JS-routed SPA
(e.g. OWASP Juice Shop), the homepage HTML has almost no <a href="?...">
links, so any checker that only looks at the bare homepage finds nothing
to test -- not because the app is secure, but because it was never
actually probed. This module does NOT decide anything is vulnerable; it
only expands "what to test", and every candidate is a *Candidate*, not a
*Confirmed* finding -- that judgment still belongs to each checker.

Bounded by design (never an unbounded crawler):
  - same-host only (scope)
  - max depth (default 2)
  - max pages (default 25)
  - per-request timeout
No JS execution/rendering -- this is a plain HTML/robots/sitemap crawler
plus a static REST-prefix probe list, not a headless browser. That is a
known, explicitly-stated limitation for pure client-side-routed SPAs
(see LIMITATIONS at the bottom of this file).
"""

from __future__ import annotations

import re
import urllib.request
import urllib.parse
from collections import deque
from typing import Dict, List, Set
from urllib.error import URLError, HTTPError

# A short, curated list -- NOT a blind assumption of vulnerability.
# These are just extra candidate paths worth checking whether they
# *exist* (non-404). Whether anything found there is exploitable is
# entirely up to the checkers, same as any other discovered endpoint.
_COMMON_API_PREFIXES = [
    "/api/", "/rest/", "/graphql", "/api/v1/", "/api/v2/",
    "/rest/user/login", "/rest/products", "/rest/user/whoami",
    "/admin", "/login", "/api/users", "/api/products",
]

# Same idea as _COMMON_API_PREFIXES (existence probe, not a vulnerability
# assumption) but for search/query-style endpoints -- these are the ones
# that actually carry a query parameter, which is what InjectionChecker
# needs to have anything to test. Without these, a pure-SPA target can
# have plenty of discovered endpoints and still yield zero candidates,
# because none of the bare REST paths above ever contain "?param=".
_COMMON_PARAM_PROBES = [
    "/rest/products/search?q=test",
    "/search?q=test",
    "/api/search?q=test",
    "/rest/user/login?email=test",
    "/api/products?id=1",
    "/rest/products?id=1",
]

_LINK_RE  = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
_FORM_RE  = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_ATTR_RE  = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(r'<(?:input|select|textarea)\b([^>]*)>', re.IGNORECASE)


class WebDiscovery:

    def __init__(self, base_url: str, max_depth: int = 2, max_pages: int = 25,
                 timeout: int = 8, probe_common_paths: bool = True):
        self.base_url = base_url.rstrip("/")
        self.host = urllib.parse.urlparse(self.base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.probe_common_paths = probe_common_paths

    # ── low-level fetch ──────────────────────────────────────────
    def _fetch(self, url: str) -> tuple[int, str]:
        """Returns (status_code, body). status 0 means the request
        itself failed (DNS/connection/timeout), not a 4xx/5xx."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RedTeamFramework/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.getcode(), r.read().decode("utf-8", errors="ignore")
        except HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return e.code, body
        except (URLError, TimeoutError, Exception):
            return 0, ""

    def _in_scope(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return (not parsed.netloc) or parsed.netloc == self.host

    def _normalize(self, url: str, current: str) -> str:
        return urllib.parse.urljoin(current, url).split("#")[0]

    # ── extraction ────────────────────────────────────────────────
    def _extract_links(self, html: str, page_url: str) -> Set[str]:
        found = set()
        for href in _LINK_RE.findall(html):
            full = self._normalize(href, page_url)
            if self._in_scope(full) and full.startswith(("http://", "https://")):
                found.add(full)
        return found

    def _extract_forms(self, html: str, page_url: str) -> List[Dict]:
        forms = []
        for attrs_str, body in _FORM_RE.findall(html):
            attrs = dict(_ATTR_RE.findall(attrs_str))
            action = self._normalize(attrs.get("action", page_url), page_url)
            method = attrs.get("method", "get").upper()
            inputs = []
            for field_attrs_str in _INPUT_RE.findall(body):
                field_attrs = dict(_ATTR_RE.findall(field_attrs_str))
                name = field_attrs.get("name")
                if name:
                    inputs.append({"name": name, "type": field_attrs.get("type", "text")})
            if self._in_scope(action):
                forms.append({"action": action, "method": method, "inputs": inputs, "source_page": page_url})
        return forms

    def _extract_query_params(self, url: str) -> List[str]:
        return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())

    def _parse_robots(self, body: str) -> Set[str]:
        paths = set()
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                val = line.split(":", 1)[1].strip()
                if val and val != "/":
                    if val.startswith("http"):
                        paths.add(val)
                    else:
                        paths.add(self.base_url + "/" + val.lstrip("/"))
        return paths

    def _parse_sitemap(self, body: str) -> Set[str]:
        return set(re.findall(r"<loc>([^<]+)</loc>", body, re.IGNORECASE))

    # ── main entry point ─────────────────────────────────────────
    def discover(self) -> Dict:
        """Bounded BFS crawl + robots/sitemap + common-path probe.
        Returns a dict, never raises on individual page failures --
        a single unreachable page just yields fewer endpoints, it
        doesn't abort the whole discovery."""
        visited: Set[str] = set()
        endpoints: List[Dict] = []
        forms: List[Dict] = []
        queue = deque([(self.base_url, 0)])
        seeds_tried = set()

        # robots.txt / sitemap.xml first -- cheap, high-signal
        for seed_path in ("/robots.txt", "/sitemap.xml"):
            seed_url = self.base_url + seed_path
            status, body = self._fetch(seed_url)
            if status and 200 <= status < 400:
                for extra in (self._parse_robots(body) if "robots" in seed_path
                              else self._parse_sitemap(body)):
                    if self._in_scope(extra) and extra not in visited:
                        queue.append((extra, 1))

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            status, body = self._fetch(url)
            query_params = self._extract_query_params(url)
            endpoints.append({
                "url": url, "status": status, "depth": depth,
                "query_params": query_params, "method": "GET",
            })
            if not body:
                continue

            forms.extend(self._extract_forms(body, url))
            if depth < self.max_depth:
                for link in self._extract_links(body, url):
                    if link not in visited:
                        queue.append((link, depth + 1))

        # curated common-path probe: existence check only, not a
        # vulnerability claim -- lets SPAs' hidden REST APIs surface
        # even when nothing links to them from rendered HTML.
        if self.probe_common_paths:
            for path in _COMMON_API_PREFIXES + _COMMON_PARAM_PROBES:
                url = self.base_url + path
                if url in visited or len(visited) >= self.max_pages:
                    continue
                status, _ = self._fetch(url)
                visited.add(url)
                if status and status != 404:
                    endpoints.append({
                        "url": url, "status": status, "depth": 0,
                        "query_params": self._extract_query_params(url),
                        "method": "GET",
                        "source": "common_path_probe",
                    })

        return {
            "base_url": self.base_url,
            "pages_visited": len(visited),
            "endpoints": endpoints,
            "forms": forms,
        }


# ── LIMITATIONS (state these explicitly in the thesis, not silently) ──
# 1. No JS execution: client-side-only routes/links that only appear
#    after JS runs (common in Angular/React SPAs like Juice Shop) are
#    NOT discovered by HTML parsing alone. The common-path probe list
#    is a partial mitigation, not a replacement for real JS rendering
#    (e.g. headless Chrome) -- that is a larger, separate addition.
# 2. No authentication: discovery here is unauthenticated. Endpoints
#    behind a login form are found (the form itself is discovered) but
#    not crawled past, since no session/token handling exists yet.
# 3. `_COMMON_API_PREFIXES` is a small curated list, not a wordlist
#    brute-force -- deliberately, to avoid turning discovery into a
#    noisy/aggressive scan against a lab target.
