"""
http_utils.py
-------------
Single shared HTTP client for every web_security checker.

Why this file exists: the existing codebase had TWO parallel HTTP
stacks -- most checkers (injection_checker, broken_access_control_checker,
auth_failure_checker, security_misconfiguration_checker) hand-rolled
urllib.request calls inline, while webapp_logic_checker.py used the
external `requests` library. That split meant timeout policy, User-Agent,
and error handling silently diverged between checkers. This module
standardizes on urllib (stdlib, dependency-free, matches the majority
of the existing code) so every checker shares one request path.

Existing checkers are NOT required to switch immediately -- their
inline urllib calls keep working. New/rewritten checkers should use
HttpClient going forward.
"""

import json
import time
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError

from .response_differ import HttpResponse

DEFAULT_UA = "RedTeamFramework/3.0"
DEFAULT_TIMEOUT = 10


class HttpClient:
    """Thin, stateful (base_url + optional bearer token) wrapper.
    Every method returns an HttpResponse -- status==0 signals a
    network-level failure (timeout/DNS/connection refused), which
    callers must treat as ERROR, never as a vulnerability signal."""

    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT, token: str = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = token

    def with_token(self, token: str) -> "HttpClient":
        return HttpClient(self.base_url, self.timeout, token)

    def _headers(self, extra: dict = None) -> dict:
        h = {"User-Agent": DEFAULT_UA}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else self.base_url + "/" + path.lstrip("/")

    def request(self, method: str, path: str, json_body: dict = None,
                form_data: dict = None, extra_headers: dict = None) -> HttpResponse:
        url = self._url(path)
        data = None
        headers = self._headers(extra_headers)

        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form_data is not None:
            data = urllib.parse.urlencode(form_data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        start = time.time()
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", errors="ignore")
                elapsed = time.time() - start
                return HttpResponse(
                    status=r.getcode(),
                    headers={k.lower(): v for k, v in r.headers.items()},
                    body=body,
                    elapsed=elapsed,
                )
        except HTTPError as e:
            elapsed = time.time() - start
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return HttpResponse(status=e.code, headers=hdrs, body=body, elapsed=elapsed)
        except (URLError, TimeoutError, Exception):
            elapsed = time.time() - start
            return HttpResponse(status=0, headers={}, body="", elapsed=elapsed)

    def get(self, path: str, extra_headers: dict = None) -> HttpResponse:
        return self.request("GET", path, extra_headers=extra_headers)

    def post_json(self, path: str, payload: dict, extra_headers: dict = None) -> HttpResponse:
        return self.request("POST", path, json_body=payload, extra_headers=extra_headers)

    def post_form(self, path: str, payload: dict, extra_headers: dict = None) -> HttpResponse:
        return self.request("POST", path, form_data=payload, extra_headers=extra_headers)

    def method(self, verb: str, path: str, extra_headers: dict = None) -> HttpResponse:
        return self.request(verb.upper(), path, extra_headers=extra_headers)
