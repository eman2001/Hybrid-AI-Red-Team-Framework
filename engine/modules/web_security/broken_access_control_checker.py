"""
A02:2025 - Broken Access Control Checker (IDOR / BOLA)

REWRITE NOTE: keeps the core procedure from the previous version
(register a fresh low-privilege probe account -> log in -> request a
neighbouring object ID with only that account's own token -> only
report if the server actually returns another account's data) because
that procedure is sound and evidence-based. What changed:

  - Generalized beyond a single hardcoded endpoint (/rest/basket/{id})
    to a configurable list of resource patterns covering numeric IDs,
    order IDs, and user IDs.
  - Repeatability: an IDOR hit is re-requested once before being
    marked CONFIRMED -- a single 200-with-foreign-data response is
    reported at VALIDATED, not CONFIRMED, until it repeats.
  - Migrated to the shared WebFinding schema via build_finding().
  - Replaces the separate, weaker `ActiveIDORChecker` that used to
    live in webapp_logic_checker.py (unauthenticated sequential-ID
    probing with no ownership comparison at all -- removed).

Active/stateful check: this DOES create one new account on the target
-- acceptable only in an authorized lab/test environment.
"""

import random
import string
from typing import List, Optional, Tuple

from .http_utils import HttpClient
from .response_differ import HttpResponse
from .web_findings import (
    build_finding, compute_confidence,
    STATUS_VALIDATED, STATUS_CONFIRMED,
)


class BrokenAccessControlChecker:

    DEFAULT_NUMERIC_RESOURCE_PATTERNS = [
        "/rest/basket/{id}",
        "/api/Users/{id}",
        "/api/orders/{id}",
        "/api/BasketItems/{id}",
    ]

    def __init__(self, target_url: str, timeout: int = 10,
                 register_path: str = "/api/Users",
                 login_path: str = "/rest/user/login",
                 resource_patterns: Optional[List[str]] = None,
                 owner_field_candidates: Optional[List[str]] = None):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.client = HttpClient(self.target_url, timeout=timeout)
        self._register_path = register_path
        self._login_path = login_path
        self._resource_patterns = resource_patterns or self.DEFAULT_NUMERIC_RESOURCE_PATTERNS
        self._owner_fields = owner_field_candidates or ["UserId", "userId", "OwnerId", "id"]

    def _register_probe_account(self) -> Optional[Tuple[str, str]]:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        email = f"idor-probe-{suffix}@example.invalid"
        password = "Probe1234!"
        resp = self.client.post_json(self._register_path, {
            "email": email, "password": password, "passwordRepeat": password,
        })
        if resp.status not in (200, 201):
            print(f"  [BrokenAccessControlChecker] Registration returned status {resp.status}")
            return None
        return email, password

    def _login(self, email: str, password: str) -> Optional[Tuple[str, int]]:
        resp = self.client.post_json(self._login_path, {"email": email, "password": password})
        if resp.status != 200:
            return None
        parsed = resp.json_body
        if not isinstance(parsed, dict):
            return None
        auth = parsed.get("authentication", {})
        token = auth.get("token")
        own_id = auth.get("bid")
        if not token or own_id is None:
            return None
        return token, own_id

    def _get_as(self, path: str, token: str) -> HttpResponse:
        return self.client.request("GET", path, extra_headers={"Authorization": f"Bearer {token}"})

    def _extract_owner(self, record: dict) -> Optional[int]:
        for field_name in self._owner_fields:
            if field_name in record:
                return record[field_name]
        return None

    def _probe_resource(self, pattern: str, own_id: int, token: str) -> Optional[dict]:
        for neighbour_id in (own_id - 1, own_id + 1):
            if neighbour_id <= 0:
                continue
            path = pattern.format(id=neighbour_id)
            resp = self._get_as(path, token)
            if resp.status != 200:
                continue
            data = resp.json_body
            if not isinstance(data, dict):
                continue
            record = data.get("data") if isinstance(data.get("data"), dict) else data
            owner_id = self._extract_owner(record)
            if owner_id is None or owner_id == own_id:
                continue

            resp2 = self._get_as(path, token)
            record2 = resp2.json_body
            record2 = record2.get("data") if isinstance(record2, dict) and isinstance(record2.get("data"), dict) else record2
            repeatable = (
                resp2.status == 200 and isinstance(record2, dict)
                and self._extract_owner(record2) == owner_id
            )

            return {
                "pattern": pattern, "path": path, "own_id": own_id,
                "neighbour_id": neighbour_id, "owner_id": owner_id,
                "repeatable": repeatable,
            }
        return None

    def _check_idor(self):
        creds = self._register_probe_account()
        if not creds:
            print("  [BrokenAccessControlChecker] Could not register a probe account; skipping IDOR test")
            return
        session = self._login(*creds)
        if not session:
            print("  [BrokenAccessControlChecker] Could not authenticate probe account; skipping IDOR test")
            return
        token, own_id = session

        for pattern in self._resource_patterns:
            hit = self._probe_resource(pattern, own_id, token)
            if not hit:
                continue

            confidence = compute_confidence(
                error_evidence=False,
                behavioral_evidence=True,
                repeatable=hit["repeatable"],
                validated=True,
            )
            status = STATUS_CONFIRMED if hit["repeatable"] else STATUS_VALIDATED

            finding = build_finding(
                check_type="idor",
                title="Insecure Direct Object Reference (IDOR)",
                evidence=[
                    f"GET {hit['path']} with own token (own id={hit['own_id']}) "
                    f"returned data owned by {hit['owner_id']}",
                    f"repeatable={hit['repeatable']}",
                ],
                confidence=confidence,
                affected_params=["id"],
                url=hit["path"],
                parameter="id",
                variant="RESOURCE_ACCESS_CHANGED",
                status=status,
                repeatable=hit["repeatable"],
                remediation="Verify object ownership server-side on every request "
                            "(compare the authenticated user's ID against the "
                            "requested object's owner) instead of trusting the "
                            "object ID supplied by the client.",
                cwe_override="CWE-639",
            )
            self.findings.append(finding)
            print(
                f"  [BrokenAccessControlChecker] IDOR {status} on {hit['pattern']} -- "
                f"own id={own_id}, accessed id={hit['neighbour_id']} (owner={hit['owner_id']})"
            )

    def run_check(self) -> dict:
        print(f"[*] Testing A02:2025 - Broken Access Control on: {self.target_url}")

        self._check_idor()

        if not self.findings:
            print("  [BrokenAccessControlChecker] No validated object-level authorization evidence; no finding generated.")

        return {
            "check_name": "A02:2025 - Broken Access Control",
            "category": "A02:2025",
            "findings": [f.to_dict() for f in self.findings],
            "status": "COMPLETED",
        }
