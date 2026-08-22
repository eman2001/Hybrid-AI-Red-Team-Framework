"""
A03:2025 - Cryptographic Failures Checker
Checks whether HTTP traffic is redirected to HTTPS.
"""

import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError


class CryptographicFailureChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings = []

    def run_check(self) -> dict:
        print(
            f"[*] Testing A03:2025 - Cryptographic Failures "
            f"on: {self.target_url}"
        )

        parsed = urllib.parse.urlparse(self.target_url)

        # If the supplied target is already HTTPS, don't claim
        # that HTTPS is not enforced based only on its scheme.
        if parsed.scheme.lower() == "https":
            print(
                "  [CryptographicFailureChecker] "
                "Target is using HTTPS"
            )

            return {
                "check_name":
                    "A03:2025 - Cryptographic Failures",
                "category": "A03:2025",
                "findings": self.findings,
                "status": "COMPLETED"
            }

        try:
            req = urllib.request.Request(
                self.target_url,
                headers={"User-Agent": "RedTeamFramework/2.1"}
            )

            with urllib.request.urlopen(
                req,
                timeout=self.timeout
            ) as response:
                final_url = response.geturl()

            final_scheme = urllib.parse.urlparse(
                final_url
            ).scheme.lower()

            if final_scheme != "https":
                self.findings.append({
                    "title": "HTTPS Not Enforced",
                    "description":
                        "The tested HTTP endpoint remained accessible "
                        "without redirection to HTTPS.",
                    "risk": "HIGH",
                    "cwe_id": "CWE-319",
                    "owasp_id": "A03:2025",
                    "mitre_technique": "T1040",
                    "remediation":
                        "Redirect HTTP traffic to HTTPS and configure "
                        "HSTS where appropriate.",
                    "evidence": [
                        f"Requested URL: {self.target_url}",
                        f"Final URL: {final_url}",
                        "HTTP request was not redirected to HTTPS"
                    ],
                    "confidence": 0.95
                })

                print(
                    "  [CryptographicFailureChecker] "
                    "HTTP accessible without HTTPS redirect"
                )
            else:
                print(
                    "  [CryptographicFailureChecker] "
                    f"Redirected to HTTPS: {final_url}"
                )

        except (URLError, HTTPError, TimeoutError, Exception) as e:
            print(
                f"  [CryptographicFailureChecker] "
                f"Request failed: {e}"
            )

        return {
            "check_name":
                "A03:2025 - Cryptographic Failures",
            "category": "A03:2025",
            "findings": self.findings,
            "status": "COMPLETED"
        }
