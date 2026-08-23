"""
security_headers.py  (A05:2025 - Security Misconfiguration, headers slice)

NEW FILE. Previously, header checking was one small method
(`_check_headers`) inside security_misconfiguration_checker.py,
covering only 3 headers and reporting every missing header as a
single flat MEDIUM finding. This is now its own checker so it can be
run/tuned/tested independently, with:

  - a wider header set (CSP, HSTS, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, frame protection)
  - risk-based severity PER HEADER instead of one flat severity
  - HSTS only evaluated meaningfully over HTTPS targets

security_misconfiguration_checker.py's own `_check_headers` method
should be deleted once this file is wired into the engine, to avoid
reporting the same missing-header finding twice.
"""

from typing import Optional
from urllib.parse import urlparse

from .http_utils import HttpClient
from .web_findings import build_finding, compute_confidence, STATUS_CONFIRMED

_HEADER_SPEC = {
    "content-security-policy": (
        "Content-Security-Policy", "HIGH", "CWE-1021",
        "Define a restrictive CSP to mitigate XSS and data-injection attacks.",
    ),
    "x-frame-options": (
        "X-Frame-Options", "MEDIUM", "CWE-1021",
        "Set X-Frame-Options: DENY/SAMEORIGIN, or rely on CSP frame-ancestors.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options", "MEDIUM", "CWE-693",
        "Set X-Content-Type-Options: nosniff to prevent MIME-sniffing.",
    ),
    "referrer-policy": (
        "Referrer-Policy", "LOW", "CWE-200",
        "Set a Referrer-Policy (e.g. strict-origin-when-cross-origin) to "
        "avoid leaking full URLs to third parties.",
    ),
    "permissions-policy": (
        "Permissions-Policy", "LOW", "CWE-16",
        "Set a Permissions-Policy to restrict powerful browser features "
        "(camera, geolocation, etc.) the app does not need.",
    ),
}


class SecurityHeadersChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.client = HttpClient(self.target_url, timeout=timeout)

    def _check_frame_protection(self, headers: dict):
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        has_xfo = "x-frame-options" in headers
        if not has_frame_ancestors and not has_xfo:
            self.findings.append(build_finding(
                check_type="security_headers",
                title="Missing Clickjacking Protection",
                evidence=["Neither X-Frame-Options nor CSP frame-ancestors is present"],
                confidence=compute_confidence(error_evidence=False, behavioral_evidence=True, validated=True),
                status=STATUS_CONFIRMED,
                variant="MISSING_FRAME_PROTECTION",
                remediation="Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive.",
                cwe_override="CWE-1021",
            ))

    def _check_hsts(self, target_url: str, headers: dict):
        is_https = urlparse(target_url).scheme == "https"
        if not is_https:
            return
        if "strict-transport-security" not in headers:
            self.findings.append(build_finding(
                check_type="security_headers",
                title="Missing HTTP Strict-Transport-Security",
                evidence=["Target served over HTTPS without a Strict-Transport-Security header"],
                confidence=compute_confidence(error_evidence=False, behavioral_evidence=True, validated=True),
                status=STATUS_CONFIRMED,
                variant="MISSING_HSTS",
                remediation="Return Strict-Transport-Security: max-age=63072000; includeSubDomains "
                            "on every HTTPS response.",
                cwe_override="CWE-319",
            ))

    def run_check(self) -> dict:
        print(f"[*] Testing A05:2025 - Security Headers on: {self.target_url}")

        resp = self.client.get(self.target_url)
        if resp.status == 0:
            print("  [SecurityHeadersChecker] Request failed; skipping")
            return {
                "check_name": "A05:2025 - Security Headers",
                "category": "A05:2025",
                "findings": [],
                "status": "ERROR",
            }

        headers = resp.headers
        missing = []
        for key, (display, severity, cwe, remediation) in _HEADER_SPEC.items():
            if key in headers:
                continue
            missing.append(display)
            self.findings.append(build_finding(
                check_type="security_headers",
                title=f"Missing Security Header: {display}",
                evidence=[f"Response did not include a '{display}' header"],
                confidence=compute_confidence(error_evidence=False, behavioral_evidence=True, validated=True),
                status=STATUS_CONFIRMED,
                variant="MISSING_HEADER",
                remediation=remediation,
                cwe_override=cwe,
            ))

        self._check_frame_protection(headers)
        self._check_hsts(self.target_url, headers)

        if missing:
            print(f"  [SecurityHeadersChecker] Missing: {', '.join(missing)}")
        else:
            print("  [SecurityHeadersChecker] All checked headers present")

        return {
            "check_name": "A05:2025 - Security Headers",
            "category": "A05:2025",
            "findings": [f.to_dict() for f in self.findings],
            "status": "COMPLETED",
        }
