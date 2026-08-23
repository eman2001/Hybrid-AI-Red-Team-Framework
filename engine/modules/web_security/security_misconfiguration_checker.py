"""
A05:2025 - Security Misconfiguration Checker
Validates common HTTP security headers, directory listing exposure,
unauthenticated version/info disclosure, verbose error/stack-trace
disclosure, and permissive CORS configuration.
"""

import json
import urllib.request
from urllib.error import URLError, HTTPError

# Paths worth checking for accidental directory-listing exposure. A
# short curated list (not a wordlist brute-force), consistent with
# WebDiscovery's own curated-probe philosophy elsewhere in this engine.
_LISTING_PROBE_PATHS = ["/ftp/", "/encryptionkeys/"]

# Common unauthenticated info-disclosure endpoints worth checking for
# existence. Read-only GET requests only.
_VERSION_DISCLOSURE_PATHS = ["/rest/admin/application-version"]

# A stack trace/verbose error is detected by pattern, not by assuming
# any specific endpoint is broken -- these substrings are generic
# Node.js/Express stack-trace markers, not app-specific text.
_STACK_TRACE_MARKERS = ["at /", ".js:", "stacktrace"]


class SecurityMisconfigurationChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []

    def _get(self, url: str):
        """Returns (status, headers_dict, body) or (0, {}, '') on failure."""
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "RedTeamFramework/2.1"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                return r.getcode(), headers, r.read().decode("utf-8", errors="ignore")
        except HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return e.code, headers, body
        except (URLError, TimeoutError, Exception):
            return 0, {}, ""

    def _check_headers(self):
        status, headers, _ = self._get(self.target_url)
        if status == 0:
            print("  [SecurityMisconfigurationChecker] Request failed for header check")
            return

        required_headers = {
            "content-security-policy": "Content-Security-Policy",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
        }
        missing = [display for key, display in required_headers.items() if key not in headers]

        if missing:
            self.findings.append({
                "title": "Missing HTTP Security Headers",
                "description": (
                    "The HTTP response is missing one or more "
                    "recommended security headers."
                ),
                "risk": "MEDIUM",
                "cwe_id": "CWE-693",
                "owasp_id": "A05:2025",
                "mitre_technique": "T1190",
                "remediation": "Configure the web server to return the missing security headers.",
                "evidence": ["Missing header: " + h for h in missing],
                "confidence": 0.90
            })
            print(f"  [SecurityMisconfigurationChecker] Missing: {', '.join(missing)}")
        else:
            print("  [SecurityMisconfigurationChecker] Required headers detected")

        # Independent finding from the required-headers check above -- an
        # app can have every required header present and still allow any
        # origin to read responses via a wildcard CORS policy.
        acao = headers.get("access-control-allow-origin")
        if acao == "*":
            self.findings.append({
                "title": "Permissive CORS Configuration",
                "description": (
                    "The server returns 'Access-Control-Allow-Origin: *', "
                    "allowing any origin to read API responses via "
                    "cross-origin requests."
                ),
                "risk": "LOW",
                "cwe_id": "CWE-942",
                "owasp_id": "A05:2025",
                "mitre_technique": "T1190",
                "remediation": (
                    "Restrict Access-Control-Allow-Origin to a known, "
                    "trusted set of origins instead of a wildcard."
                ),
                "evidence": ["Access-Control-Allow-Origin: *"],
                "confidence": 0.90
            })
            print("  [SecurityMisconfigurationChecker] Permissive CORS (Access-Control-Allow-Origin: *)")

    def _check_directory_listing(self):
        for path in _LISTING_PROBE_PATHS:
            url = self.target_url + path
            status, _, body = self._get(url)
            low = body.lower()
            if status == 200 and ("listing directory" in low or "index of " in low):
                self.findings.append({
                    "title": "Directory Listing Exposed",
                    "description": f"The path {path} returns a browsable directory listing.",
                    "risk": "MEDIUM",
                    "cwe_id": "CWE-548",
                    "owasp_id": "A05:2025",
                    "mitre_technique": "T1083",
                    "remediation": "Disable directory listing/indexing for this path on the web server.",
                    "evidence": [f"Directory listing observed at {url}"],
                    "confidence": 0.90
                })
                print(f"  [SecurityMisconfigurationChecker] Directory listing exposed: {path}")

    def _check_version_disclosure(self):
        for path in _VERSION_DISCLOSURE_PATHS:
            url = self.target_url + path
            status, _, body = self._get(url)
            if status == 200:
                try:
                    data = json.loads(body)
                except Exception:
                    data = None
                if isinstance(data, dict) and "version" in data:
                    self.findings.append({
                        "title": "Unauthenticated Version Disclosure",
                        "description": (
                            f"The endpoint {path} discloses the application "
                            f"version ({data['version']}) without requiring authentication."
                        ),
                        "risk": "LOW",
                        "cwe_id": "CWE-200",
                        "owasp_id": "A05:2025",
                        "mitre_technique": "T1592",
                        "remediation": (
                            "Require authentication for version/diagnostic "
                            "endpoints, or remove them in production."
                        ),
                        "evidence": [f"{url} -> {body.strip()[:200]}"],
                        "confidence": 0.90
                    })
                    print(f"  [SecurityMisconfigurationChecker] Version disclosed at {path}: {data['version']}")

    def _check_verbose_errors(self):
        # A deliberately-malformed request to a common password-reset
        # endpoint; a well-behaved app returns a generic 4xx error with
        # no internal detail. Read-only probe -- no account is created
        # or modified (distinct from BrokenAccessControlChecker's IDOR
        # check, which does register a test account).
        url = self.target_url + "/rest/user/reset-password"
        try:
            payload = json.dumps({
                "email": "nonexistent-probe-account@example.invalid",
                "newPassword": "Probe1234!",
                "repeatNewPassword": "Probe1234!",
                "securityAnswer": "probe",
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"User-Agent": "RedTeamFramework/2.1", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", errors="ignore")
        except HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except (URLError, TimeoutError, Exception):
            body = ""

        low = body.lower()
        if any(marker in low for marker in _STACK_TRACE_MARKERS):
            self.findings.append({
                "title": "Verbose Error / Stack Trace Disclosure",
                "description": (
                    "An error response from the server includes internal "
                    "file paths and/or a stack trace instead of a generic "
                    "error message."
                ),
                "risk": "MEDIUM",
                "cwe_id": "CWE-209",
                "owasp_id": "A05:2025",
                "mitre_technique": "T1592",
                "remediation": (
                    "Disable verbose/debug error output in production and "
                    "return generic error messages to clients."
                ),
                "evidence": [f"Stack trace observed in response from {url}"],
                "confidence": 0.85
            })
            print("  [SecurityMisconfigurationChecker] Verbose error / stack trace disclosed")

    def run_check(self) -> dict:
        print(f"[*] Testing A05:2025 - Security Misconfiguration on: {self.target_url}")

        # NOTE: self._check_headers() is intentionally NOT called here.
        # Header checks (missing CSP/X-Frame-Options/etc.) and CORS
        # checks now live in dedicated checkers -- security_headers.py's
        # SecurityHeadersChecker and cors_checker.py's CORSChecker --
        # registered separately in owasp_engine.py. Calling
        # _check_headers() here as well would report the same missing
        # header / permissive CORS finding twice per scan. The method
        # itself is left in place (unused) rather than deleted, in case
        # something else still references it directly.
        self._check_directory_listing()
        self._check_version_disclosure()
        self._check_verbose_errors()

        return {
            "check_name": "A05:2025 - Security Misconfiguration",
            "category": "A05:2025",
            "findings": self.findings,
            "status": "COMPLETED"
        }
