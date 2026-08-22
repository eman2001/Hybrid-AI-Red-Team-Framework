"""
A02:2025 - Broken Access Control Checker

Confirms IDOR (Insecure Direct Object Reference) using a self-contained,
evidence-based procedure rather than assuming access control is broken
from the homepage alone:

  1. Register a fresh, low-privilege test account on the target (no
     assumption is made about any pre-existing account or credentials).
  2. Log in as that account and read back its own object ID (its basket
     ID, returned directly in the login response).
  3. Using ONLY that account's own token, request a neighbouring object
     ID (own_id +/- 1) at the same endpoint.
  4. A finding is only generated if the server returns 200 with another
     account's actual data for that ID -- not merely because the request
     didn't error out.

This keeps the check self-contained: it does not depend on any other
checker (e.g. InjectionChecker's login-bypass finding) having already
obtained a token, and it does not require prior knowledge of another
user's ID.

Active/stateful check: this DOES create one new account on the target
(this differs from the purely read-only checks elsewhere in this OWASP
engine) -- acceptable only in an authorized lab/test environment.
"""

import json
import random
import string
import urllib.request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from .web_findings import build_finding, compute_confidence, STATUS_CONFIRMED


class BrokenAccessControlChecker:

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self._host = urlparse(self.target_url).hostname

    def _post_json(self, path: str, payload: dict):
        """Returns (status, parsed_json_or_None, raw_body)."""
        url = self.target_url + path
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"User-Agent": "RedTeamFramework/2.1", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", errors="ignore")
                status = r.getcode()
        except HTTPError as e:
            status = e.code
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except (URLError, TimeoutError, Exception):
            return 0, None, ""

        try:
            parsed = json.loads(body)
        except Exception:
            parsed = None
        return status, parsed, body

    def _get_json(self, path: str, token: str):
        url = self.target_url + path
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "RedTeamFramework/2.1", "Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", errors="ignore")
                status = r.getcode()
        except HTTPError as e:
            status = e.code
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except (URLError, TimeoutError, Exception):
            return 0, None

        try:
            parsed = json.loads(body)
        except Exception:
            parsed = None
        return status, parsed

    def _register_probe_account(self):
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        email = f"idor-probe-{suffix}@example.invalid"
        password = "Probe1234!"
        status, _, _ = self._post_json("/api/Users", {
            "email": email, "password": password, "passwordRepeat": password,
        })
        if status not in (200, 201):
            print(f"  [BrokenAccessControlChecker] Registration returned status {status}")
            return None
        return email, password

    def _login(self, email: str, password: str):
        status, parsed, _ = self._post_json("/rest/user/login", {
            "email": email, "password": password,
        })
        if status != 200 or not isinstance(parsed, dict):
            return None
        auth = parsed.get("authentication", {})
        token = auth.get("token")
        own_id = auth.get("bid")
        if not token or own_id is None:
            return None
        return token, own_id

    def _check_idor(self):
        creds = self._register_probe_account()
        if not creds:
            print("  [BrokenAccessControlChecker] Could not register a probe account; skipping IDOR test")
            return
        email, password = creds

        session = self._login(email, password)
        if not session:
            print("  [BrokenAccessControlChecker] Could not authenticate probe account; skipping IDOR test")
            return
        token, own_id = session

        for neighbour_id in (own_id - 1, own_id + 1):
            if neighbour_id <= 0:
                continue
            status, data = self._get_json(f"/rest/basket/{neighbour_id}", token)
            if status != 200 or not isinstance(data, dict):
                continue
            record = data.get("data") or data
            if not isinstance(record, dict):
                continue
            owner_id = record.get("UserId", record.get("id"))
            if owner_id is not None and owner_id != own_id:
                self.findings.append(build_finding(
                    check_type="idor",
                    title="Insecure Direct Object Reference (IDOR)",
                    evidence=[
                        f"GET /rest/basket/{neighbour_id} with own token "
                        f"(own id={own_id}) returned data owned by {owner_id}"
                    ],
                    confidence=compute_confidence(
                        error_evidence=False, behavioral_evidence=True, validated=True
                    ),
                    host=self._host,
                    status=STATUS_CONFIRMED,
                    variant="RESOURCE_ACCESS_CHANGED",
                    parameter="id",
                    affected_params=["id"],
                    remediation=(
                        "Verify object ownership server-side on every request "
                        "(e.g. compare the authenticated user's ID against the "
                        "requested object's owner) instead of trusting the "
                        "object ID supplied by the client."
                    ),
                    cwe_override="CWE-639",
                ))
                print(
                    f"  [BrokenAccessControlChecker] IDOR confirmed — "
                    f"own id={own_id}, accessed id={neighbour_id} (owner={owner_id})"
                )

    def run_check(self) -> dict:
        print(f"[*] Testing A02:2025 - Broken Access Control on: {self.target_url}")

        self._check_idor()

        if not self.findings:
            print(
                "  [BrokenAccessControlChecker] "
                "No validated object-level authorization evidence; "
                "no finding generated."
            )

        return {
            "check_name": "A02:2025 - Broken Access Control",
            "category": "A02:2025",
            "findings": [f.to_dict() for f in self.findings],
            "status": "COMPLETED"
        }
