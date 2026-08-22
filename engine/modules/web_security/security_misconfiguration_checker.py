"""
A05:2025 - Security Misconfiguration Checker
Validates common HTTP security headers.
"""

import urllib.request
from urllib.error import URLError, HTTPError


class SecurityMisconfigurationChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings = []

    def run_check(self) -> dict:
        print(
            f"[*] Testing A05:2025 - Security Misconfiguration "
            f"on: {self.target_url}"
        )

        try:
            req = urllib.request.Request(
                self.target_url,
                headers={"User-Agent": "RedTeamFramework/2.1"}
            )

            with urllib.request.urlopen(
                req,
                timeout=self.timeout
            ) as response:
                headers = {
                    k.lower(): v
                    for k, v in response.headers.items()
                }

            required_headers = {
                "content-security-policy":
                    "Content-Security-Policy",
                "x-frame-options":
                    "X-Frame-Options",
                "x-content-type-options":
                    "X-Content-Type-Options",
            }

            missing = [
                display
                for key, display in required_headers.items()
                if key not in headers
            ]

            if missing:
                self.findings.append({
                    "title": "Missing HTTP Security Headers",
                    "description":
                        "The HTTP response is missing one or more "
                        "recommended security headers.",
                    "risk": "MEDIUM",
                    "cwe_id": "CWE-693",
                    "owasp_id": "A05:2025",
                    "mitre_technique": "T1190",
                    "remediation":
                        "Configure the web server to return the "
                        "missing security headers.",
                    "evidence": [
                        "Missing header: " + h
                        for h in missing
                    ],
                    "confidence": 0.90
                })

                print(
                    f"  [SecurityMisconfigurationChecker] "
                    f"Missing: {', '.join(missing)}"
                )
            else:
                print(
                    "  [SecurityMisconfigurationChecker] "
                    "Required headers detected"
                )

        except (URLError, HTTPError, TimeoutError, Exception) as e:
            print(
                f"  [SecurityMisconfigurationChecker] "
                f"Request failed: {e}"
            )

        return {
            "check_name":
                "A05:2025 - Security Misconfiguration",
            "category": "A05:2025",
            "findings": self.findings,
            "status": "COMPLETED"
        }
