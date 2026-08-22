"""
A07:2025 - Identification and Authentication Failures Checker
Validates security attributes on cookies returned by the target.
"""

import urllib.request
from urllib.error import URLError, HTTPError


class AuthFailureChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings = []

    def run_check(self) -> dict:
        print(
            f"[*] Testing A07:2025 - Authentication Failures "
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
                cookies = response.headers.get_all(
                    "Set-Cookie"
                ) or []

            if not cookies:
                print(
                    "  [AuthFailureChecker] "
                    "No Set-Cookie headers observed"
                )

            for cookie in cookies:
                low = cookie.lower()

                missing = []

                if "secure" not in low:
                    missing.append("Secure")

                if "httponly" not in low:
                    missing.append("HttpOnly")

                if "samesite" not in low:
                    missing.append("SameSite")

                if missing:
                    cookie_name = (
                        cookie.split("=", 1)[0].strip()
                        if "=" in cookie
                        else "unknown"
                    )

                    self.findings.append({
                        "title":
                            "Session Cookie Security Attributes Missing",
                        "description":
                            f"Cookie '{cookie_name}' is missing "
                            f"recommended security attributes.",
                        "risk": "MEDIUM",
                        "cwe_id": "CWE-614",
                        "owasp_id": "A07:2025",
                        "mitre_technique": "T1539",
                        "remediation":
                            "Configure sensitive session cookies with "
                            "Secure, HttpOnly and an appropriate "
                            "SameSite attribute.",
                        "evidence": [
                            f"Cookie: {cookie_name}",
                            f"Missing attributes: {', '.join(missing)}"
                        ],
                        "confidence": 0.90
                    })

            print(
                f"  [AuthFailureChecker] "
                f"{len(self.findings)} finding(s)"
            )

        except (URLError, HTTPError, TimeoutError, Exception) as e:
            print(
                f"  [AuthFailureChecker] Request failed: {e}"
            )

        return {
            "check_name":
                "A07:2025 - Authentication Failures",
            "category": "A07:2025",
            "findings": self.findings,
            "status": "COMPLETED"
        }
