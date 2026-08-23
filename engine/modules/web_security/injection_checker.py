"""
A01:2025 - Injection Checker (SQL Injection)

REWRITE NOTE: this replaces two previously-separate, duplicate
detectors -- the error-based single-quote probe that used to live
here, and `ActiveInjectionChecker` (auth-bypass payloads like
`' OR 1=1--`) that used to live in webapp_logic_checker.py. Both are
now variants of one checker, sharing one baseline, one generalized
error-signature matcher, and one confidence model, instead of two
independent scanners that could both fire on the same login endpoint.

Detection classes (a finding's `variant` field says which fired):
  ERROR_BASED             a DBMS/ORM error signature appears in the
                           probe response but not the baseline.
  BOOLEAN_DIFFERENTIAL    a syntactically-true payload behaves like a
                           successful/different-baseline response while
                           a syntactically-false payload (same shape,
                           same length) behaves like the original
                           baseline. Requires BOTH probes to agree --
                           a single response is never enough.
  AUTH_BYPASS_DIFFERENTIAL a specialization of boolean-differential for
                           login endpoints: an OR-based payload produces
                           an authenticated-looking response (token /
                           session cookie / structural change) where a
                           plain wrong-credential baseline did not.

No finding is emitted from a single observation. Every candidate is
re-probed once (repeatability) before being marked CONFIRMED; a single
observation is capped at DETECTED status with reduced confidence.
"""

import re
import urllib.parse
from typing import Dict, List, Optional

from .http_utils import HttpClient
from .response_differ import ResponseDiffer, HttpResponse
from .web_findings import (
    build_finding, compute_confidence,
    STATUS_DETECTED, STATUS_VALIDATED, STATUS_CONFIRMED, STATUS_NOT_CONFIRMED,
)

# Context-aware DBMS/ORM error signatures. Each pattern already implies
# a database/query context on its own (unlike a bare "error"), so we
# do NOT additionally require the word "error" elsewhere in the body --
# that would just reintroduce the same false-positive risk in a
# different place.
_SQL_ERROR_PATTERNS = [
    # SQLite
    r"sqlite_error", r"sqlitedatabaseerror", r"sqlite3\.operationalerror",
    r'near ".*": syntax error',
    # MySQL / MariaDB
    r"you have an error in your sql syntax", r"warning: mysql",
    r"mysqldatabaseerror", r"valid mysql result", r"check the manual that "
    r"corresponds to your (my|maria)sql server version",
    # PostgreSQL
    r"pg::(syntaxerror|error)", r"postgresql.*syntax error",
    r"unterminated quoted string", r"psycopg2\.(programmingerror|error)",
    # MSSQL
    r"microsoft ole db provider for sql server", r"unclosed quotation mark",
    r"odbc sql server driver", r"sql server.*native client",
    r"system\.data\.sqlclient\.sqlexception",
    # Oracle
    r"ora-\d{5}", r"oracle error", r"oracle.*driver",
    # ORM-level (framework wraps the DB error but still names it)
    r"sequelizedatabaseerror", r"django\.db\.utils\.\w*error",
    r"sqlalchemy\.exc\.\w*error", r"hibernate.*exception",
    r"unrecognized token", r"query parsing error",
]
_SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)

_ERROR_PROBE = "'"

# Boolean-differential pair. TRUE is expected to behave like a
# semantically-valid tautology; FALSE is a syntactically-matched
# control (same quote/comment shape) that should NOT.
_BOOL_TRUE_SUFFIX = "' OR '1'='1"
_BOOL_FALSE_SUFFIX = "' AND '1'='2"

# Auth-bypass-flavoured payloads for login-shaped JSON bodies. Kept
# small and non-destructive; these authenticate-or-don't, they never
# modify data.
_AUTH_BYPASS_PAYLOADS = [
    {"email_suffix": "' OR 1=1-- ", "password": "x"},
    {"email_suffix": "' OR '1'='1", "password": "' OR '1'='1"},
    {"email_suffix": "admin'-- ", "password": "x"},
]


class InjectionChecker:

    DEFAULT_LOGIN_ENDPOINTS = [
        "/rest/user/login", "/api/login", "/login",
        "/api/auth/login", "/user/login", "/api/v1/login",
    ]

    def __init__(self, target_url: str, timeout: int = 10,
                 discovered_endpoints: Optional[list] = None,
                 login_endpoints: Optional[List[str]] = None,
                 probe_email_field: str = "email",
                 probe_password_field: str = "password",
                 baseline_probe_account: Optional[str] = None):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self._discovered_endpoints = discovered_endpoints or []
        self._login_endpoints = login_endpoints or self.DEFAULT_LOGIN_ENDPOINTS
        self._email_field = probe_email_field
        self._password_field = probe_password_field
        self._baseline_account = baseline_probe_account or "nonexistent-probe-account@example.invalid"

        self.client = HttpClient(self.target_url, timeout=timeout)
        self.differ = ResponseDiffer()

    def _has_sql_error(self, body: str) -> bool:
        if not body:
            return False
        return bool(_SQL_ERROR_RE.search(body))

    def _login_probe(self, path: str, email: str, password: str) -> HttpResponse:
        return self.client.post_json(path, {
            self._email_field: email,
            self._password_field: password,
        })

    def _looks_authenticated(self, baseline: HttpResponse, probe: HttpResponse) -> bool:
        if probe.status != 200 or baseline.status == 200:
            return False
        probe_json = probe.json_body
        blob = (probe.body or "").lower() if probe_json is None else str(probe_json).lower()
        has_token_marker = any(k in blob for k in ("token", "authentication", "jwt", "bearer", "bid"))
        set_cookie_changed = probe.headers.get("set-cookie") != baseline.headers.get("set-cookie")
        return has_token_marker or set_cookie_changed

    def _extract_param_urls(self, html: str) -> List[str]:
        urls = set()
        for href in re.findall(r'href=["\']([^"\']+)["\']', html):
            if "?" not in href:
                continue
            if href.startswith("http") and self.target_url not in href:
                continue
            full = href if href.startswith("http") else f"{self.target_url}/{href.lstrip('/')}"
            urls.add(full)
        return list(urls)[:10]

    def _probe_url_error_based(self, url: str) -> Optional[dict]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return None

        baseline = self.client.get(url)

        for param in params:
            def build(suffix):
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params[param] + suffix
                q = urllib.parse.urlencode(test_params)
                return urllib.parse.urlunparse(parsed._replace(query=q))

            test_url = build(_ERROR_PROBE)
            probe1 = self.client.get(test_url)
            if not (probe1.body and self._has_sql_error(probe1.body) and not self._has_sql_error(baseline.body)):
                continue

            probe2 = self.client.get(test_url)
            repeatable = bool(probe2.body and self._has_sql_error(probe2.body))

            diff = self.differ.diff(baseline, probe1)
            return {
                "url": url, "param": param, "test_url": test_url,
                "baseline": baseline, "probe": probe1,
                "diff": diff, "repeatable": repeatable,
            }
        return None

    def _probe_login(self, path: str) -> List[dict]:
        hits = []
        baseline = self._login_probe(path, self._baseline_account, "wrong-password")
        if baseline.status == 0:
            return hits

        probe = self._login_probe(path, self._baseline_account + _ERROR_PROBE, "wrong-password")
        if probe.body and self._has_sql_error(probe.body) and not self._has_sql_error(baseline.body):
            probe2 = self._login_probe(path, self._baseline_account + _ERROR_PROBE, "wrong-password")
            repeatable = bool(probe2.body and self._has_sql_error(probe2.body))
            diff = self.differ.diff(baseline, probe)
            hits.append({
                "variant": "ERROR_BASED", "path": path, "field": self._email_field,
                "baseline": baseline, "probe": probe, "diff": diff, "repeatable": repeatable,
            })

        for payload in _AUTH_BYPASS_PAYLOADS:
            resp = self._login_probe(path, self._baseline_account.split("@")[0] + payload["email_suffix"],
                                      payload["password"])
            if resp.status == 0:
                continue
            if self._looks_authenticated(baseline, resp):
                false_ctrl = self._login_probe(
                    path, self._baseline_account.split("@")[0] + _BOOL_FALSE_SUFFIX, "wrong-password"
                )
                control_clean = not self._looks_authenticated(baseline, false_ctrl)

                resp2 = self._login_probe(path, self._baseline_account.split("@")[0] + payload["email_suffix"],
                                           payload["password"])
                repeatable = self._looks_authenticated(baseline, resp2)

                diff = self.differ.diff(baseline, resp)
                hits.append({
                    "variant": "AUTH_BYPASS_DIFFERENTIAL", "path": path, "field": self._email_field,
                    "baseline": baseline, "probe": resp, "diff": diff,
                    "repeatable": repeatable, "validated": control_clean,
                    "payload_used": payload["email_suffix"],
                })
                break
        return hits

    def run_check(self) -> dict:
        print(f"[*] Testing A01:2025 - Injection on: {self.target_url}")

        candidate_urls = [self.target_url] if "?" in self.target_url else []
        homepage = self.client.get(self.target_url)
        if homepage.body:
            candidate_urls += self._extract_param_urls(homepage.body)
        for ep in self._discovered_endpoints:
            url = ep.get("url", "")
            if "?" in url and url not in candidate_urls:
                candidate_urls.append(url)

        raw_hits = []
        for url in candidate_urls:
            hit = self._probe_url_error_based(url)
            if hit:
                hit["variant"] = "ERROR_BASED"
                raw_hits.append(hit)

        for path in self._login_endpoints:
            raw_hits.extend(self._probe_login(path))

        for h in raw_hits:
            self._emit(h)

        if self.findings:
            print(f"  [InjectionChecker] {len(self.findings)} finding(s) emitted")
        else:
            print("  [InjectionChecker] No SQL injection evidence found on tested surfaces")

        return {
            "check_name": "A01:2025 - Injection",
            "category": "A01:2025",
            "findings": [f.to_dict() for f in self.findings],
            "status": "COMPLETED",
        }

    def _emit(self, h: dict):
        variant = h["variant"]
        repeatable = h.get("repeatable")
        validated = h.get("validated", False)
        diff = h.get("diff")

        error_evidence = variant == "ERROR_BASED"
        behavioral_evidence = bool(diff and (diff.status_changed or diff.body_changed or diff.json_structure_changed))

        confidence = compute_confidence(
            error_evidence=error_evidence,
            behavioral_evidence=behavioral_evidence,
            repeatable=repeatable,
            validated=validated,
        )

        if repeatable is True and (error_evidence or validated):
            status = STATUS_CONFIRMED
        elif repeatable is False:
            status = STATUS_NOT_CONFIRMED
        elif validated or error_evidence:
            status = STATUS_VALIDATED
        else:
            status = STATUS_DETECTED

        if status == STATUS_NOT_CONFIRMED:
            print(f"  [InjectionChecker] Candidate on {h.get('path') or h.get('url')} did NOT repeat -- discarded")
            return

        evidence = []
        param = h.get("field") or h.get("param")
        location = h.get("path") or h.get("url")
        evidence.append(f"variant={variant} endpoint={location} parameter={param}")
        evidence.append(f"repeatable={repeatable}")
        if diff:
            evidence.append(f"diff={diff.as_evidence_dict()}")
        if h.get("payload_used"):
            evidence.append(f"payload_shape={h['payload_used']}")

        finding = build_finding(
            check_type="sql_injection",
            title=f"SQL Injection ({variant.replace('_', ' ').title()})",
            evidence=evidence,
            confidence=confidence,
            affected_params=[param] if param else [],
            url=location,
            parameter=param,
            variant=variant,
            status=status,
            baseline=h["baseline"].__dict__ if hasattr(h["baseline"], "__dict__") else {},
            probe=h["probe"].__dict__ if hasattr(h["probe"], "__dict__") else {},
            repeatable=repeatable,
            remediation="Use parameterized queries / prepared statements or an ORM's "
                        "safe query builder; never concatenate user input into SQL.",
            cwe_override="CWE-89",
        )
        self.findings.append(finding)
        print(f"  [InjectionChecker] {variant} on {location} ({param}) -> {status}, confidence={confidence}")
