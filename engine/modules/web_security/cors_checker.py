"""
cors_checker.py  (A05:2025 - Security Misconfiguration, CORS slice)
"""

from typing import List, Optional

from .http_utils import HttpClient
from .web_findings import build_finding, compute_confidence, STATUS_CONFIRMED

_PROBE_ORIGIN = "https://cors-probe.example.invalid"


class CORSChecker:

    def __init__(self, target_url: str, timeout: int = 10,
                 sensitive_paths: Optional[List[str]] = None):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.client = HttpClient(self.target_url, timeout=timeout)
        self._sensitive_paths = sensitive_paths or []

    def _probe(self, path: str) -> Optional[dict]:
        resp = self.client.get(path, extra_headers={"Origin": _PROBE_ORIGIN})
        if resp.status == 0:
            return None
        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao is None:
            return None
        reflected = acao == _PROBE_ORIGIN
        wildcard = acao == "*"
        if not (reflected or wildcard):
            return None

        return {"path": path, "acao": acao, "reflected": reflected, "wildcard": wildcard, "credentials": acac}

    def run_check(self) -> dict:
        print(f"[*] Testing A05:2025 - CORS Misconfiguration on: {self.target_url}")

        paths_to_check = [self.target_url] + [self.target_url + p for p in self._sensitive_paths]
        seen = set()

        for path in paths_to_check:
            if path in seen:
                continue
            seen.add(path)
            hit = self._probe(path)
            if not hit:
                continue

            is_sensitive = path != self.target_url
            dangerous_combo = hit["credentials"] and (hit["reflected"] or hit["wildcard"])

            if dangerous_combo:
                severity_note = "credentials=true combined with an open origin policy"
                confidence = compute_confidence(error_evidence=False, behavioral_evidence=True, validated=True)
                cwe = "CWE-942"
            elif is_sensitive:
                severity_note = "open origin policy on an endpoint expected to return sensitive data"
                confidence = compute_confidence(error_evidence=False, behavioral_evidence=True, validated=False)
                cwe = "CWE-942"
            else:
                severity_note = "open origin policy on a page of unconfirmed sensitivity"
                confidence = compute_confidence(error_evidence=False, behavioral_evidence=True, validated=False) - 0.15
                cwe = "CWE-942"

            variant = "REFLECTED_ORIGIN" if hit["reflected"] else "WILDCARD_ORIGIN"
            self.findings.append(build_finding(
                check_type="cors_misconfiguration",
                title=f"Permissive CORS Configuration ({variant.replace('_', ' ').title()})",
                evidence=[
                    f"GET {path} with Origin: {_PROBE_ORIGIN} -> "
                    f"Access-Control-Allow-Origin: {hit['acao']}",
                    f"Access-Control-Allow-Credentials: {hit['credentials']}",
                    severity_note,
                ],
                confidence=max(confidence, 0.0),
                status=STATUS_CONFIRMED,
                variant=variant,
                remediation="Restrict Access-Control-Allow-Origin to a known, trusted allow-list "
                            "instead of a wildcard or reflected Origin, especially on any endpoint "
                            "that also sets Access-Control-Allow-Credentials: true.",
                cwe_override=cwe,
            ))
            print(f"  [CORSChecker] {variant} on {path} (credentials={hit['credentials']})")

        if not self.findings:
            print("  [CORSChecker] No permissive CORS policy observed on tested paths")

        return {
            "check_name": "A05:2025 - CORS Misconfiguration",
            "category": "A05:2025",
            "findings": [f.to_dict() for f in self.findings],
            "status": "COMPLETED",
        }
