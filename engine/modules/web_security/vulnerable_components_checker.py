"""
A06:2025 - Vulnerable and Outdated Components Checker

Uses TechnologyDetector to identify technology/version evidence.
Only components classified as EOL/outdated by the detector are
reported.
"""

import urllib.request
from urllib.error import URLError, HTTPError

from engine.modules.web_security.technology_detector import (
    TechnologyDetector,
)


class VulnerableComponentsChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings = []
        self.detector = TechnologyDetector()

    def run_check(self) -> dict:
        print(
            f"[*] Testing A06:2025 - Vulnerable Components "
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
                server = response.headers.get(
                    "Server", ""
                )
                powered = response.headers.get(
                    "X-Powered-By", ""
                )

            banner = " ".join(
                x for x in [server, powered] if x
            )

            service_data = {
                "product": server,
                "version": "",
                "banner": banner,
                "nmap_scripts": {}
            }

            detected = self.detector.detect(
                service_data,
                enrich_nvd=True
            )

            tech_stack = detected.get(
                "tech_stack", []
            )

            eol_components = detected.get(
                "eol_components", []
            )

            nvd_findings = detected.get(
                "nvd_findings", {}
            )

            print(
                f"  [TechnologyDetector] "
                f"Stack: {tech_stack or 'unknown'}"
            )

            if eol_components:
                for component in eol_components:

                    evidence = [
                        f"Detected component: {component}"
                    ]

                    for cve in nvd_findings.get(
                        component, []
                    )[:3]:
                        evidence.append(
                            f"NVD reference: "
                            f"{cve.get('cve_id', '')} "
                            f"(CVSS {cve.get('cvss', 0.0)})"
                        )

                    self.findings.append({
                        "title":
                            f"Potentially Outdated Component: "
                            f"{component}",
                        "description":
                            "A component version identified from the "
                            "HTTP service banner matched the framework's "
                            "configured outdated/EOL criteria.",
                        "risk": "HIGH",
                        "cwe_id": "CWE-1104",
                        "owasp_id": "A06:2025",
                        "mitre_technique": "T1190",
                        "remediation":
                            "Verify the detected component version "
                            "and upgrade unsupported or vulnerable "
                            "software to a supported release.",
                        "evidence": evidence,
                        "confidence": 0.85
                    })

            else:
                print(
                    "  [VulnerableComponentsChecker] "
                    "No outdated component validated"
                )

        except (URLError, HTTPError, TimeoutError, Exception) as e:
            print(
                f"  [VulnerableComponentsChecker] "
                f"Detection failed: {e}"
            )

        return {
            "check_name":
                "A06:2025 - Vulnerable Components",
            "category": "A06:2025",
            "findings": self.findings,
            "status": "COMPLETED"
        }
