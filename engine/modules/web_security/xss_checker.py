"""
xss_checker.py  (A03:2025 - Cross-Site Scripting)

NEW FILE. Replaces `ActiveXSSChecker` (webapp_logic_checker.py), whose
entire test was "does the literal canary string appear anywhere in
the response body" -- true both for real XSS AND for an app that
HTML-encodes the input, with no way to tell confirmed injection apart
from harmless reflection.

This version:
  - Uses a canary containing characters that must survive UN-ESCAPED
    to be exploitable (`<`, `>`, `"`, `'`), and explicitly checks
    whether the response instead contains the HTML-ENCODED form. If
    only the encoded form appears, that is reported as
    REFLECTION_ONLY rather than XSS.
  - Distinguishes HTML-context injection (raw tag reflected) from
    attribute-context injection (canary lands inside an existing
    attribute value).
  - Only classifies REFLECTED for now; STORED/DOM require a second
    request or a headless browser this stdlib-only checker doesn't
    have -- left as out of scope rather than silently claimed.
"""

import re
from typing import List, Optional
from urllib.parse import quote

from .http_utils import HttpClient
from .web_findings import build_finding, compute_confidence, STATUS_CONFIRMED, STATUS_DETECTED

_CANARY_ID = "xsscanary8f2e"
_RAW_CANARY = f"<script>alert('{_CANARY_ID}')</script>"
_ENCODED_MARKER_RE = re.compile(rf"&lt;script&gt;.*{_CANARY_ID}.*&lt;/script&gt;", re.IGNORECASE)

_DEFAULT_PARAMS = ["q", "search", "id", "redirect", "returnUrl", "query", "name", "comment"]


class XSSChecker:

    def __init__(self, target_url: str, timeout: int = 10,
                 candidate_params: Optional[List[str]] = None):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.client = HttpClient(self.target_url, timeout=timeout)
        self._params = candidate_params or _DEFAULT_PARAMS

    def _classify(self, body: str) -> str:
        if _RAW_CANARY in body:
            idx = body.find(_RAW_CANARY)
            preceding = body[max(0, idx - 3):idx]
            if preceding.endswith('="') or preceding.endswith("='"):
                return "CONFIRMED_ATTRIBUTE_CONTEXT"
            return "CONFIRMED_HTML_CONTEXT"
        if _ENCODED_MARKER_RE.search(body) or _CANARY_ID in body:
            return "REFLECTION_ONLY"
        return "NONE"

    def run_check(self) -> dict:
        print(f"[*] Testing A03:2025 - Cross-Site Scripting (reflected) on: {self.target_url}")

        for param in self._params:
            probe_url = f"{self.target_url}/?{param}={quote(_RAW_CANARY)}"
            resp = self.client.get(probe_url)
            if resp.status == 0 or not resp.body:
                continue

            classification = self._classify(resp.body)
            if classification == "NONE":
                continue

            if classification.startswith("CONFIRMED"):
                resp2 = self.client.get(probe_url)
                repeatable = resp2.status != 0 and self._classify(resp2.body or "").startswith("CONFIRMED")

                confidence = compute_confidence(
                    error_evidence=True,
                    behavioral_evidence=True,
                    repeatable=repeatable,
                    validated=True,
                )
                status = STATUS_CONFIRMED if repeatable else STATUS_DETECTED
                context = "attribute" if "ATTRIBUTE" in classification else "html"

                self.findings.append(build_finding(
                    check_type="xss",
                    title=f"Reflected Cross-Site Scripting ({context} context)",
                    evidence=[
                        f"GET {probe_url}",
                        f"Unescaped canary reflected in {context} context",
                        f"repeatable={repeatable}",
                    ],
                    confidence=confidence,
                    affected_params=[param],
                    url=probe_url,
                    parameter=param,
                    variant="REFLECTED",
                    status=status,
                    repeatable=repeatable,
                    remediation="HTML-encode all user input before rendering into the response; "
                                "adopt a strict Content-Security-Policy as defense-in-depth.",
                    cwe_override="CWE-79",
                ))
                print(f"  [XSSChecker] CONFIRMED reflected XSS ({context}) via '{param}' -> {status}")
            else:
                print(f"  [XSSChecker] '{param}' reflects input but appears HTML-encoded (not vulnerable)")

        if not self.findings:
            print("  [XSSChecker] No confirmed unescaped reflection found on tested parameters")

        return {
            "check_name": "A03:2025 - Cross-Site Scripting",
            "category": "A03:2025",
            "findings": [f.to_dict() for f in self.findings],
            "status": "COMPLETED",
        }
