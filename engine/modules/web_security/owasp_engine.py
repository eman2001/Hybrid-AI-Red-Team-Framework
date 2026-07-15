"""
owasp_engine.py — OWASP Top 10 2025 Main Orchestrator
FIX: run_all_checks() now actually calls all registered checkers.
"""

import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class OWASPEngine:

    def __init__(self, target_url: str, threads: int = 3):
        self.target_url  = target_url
        self.threads     = threads
        self._checkers   = []
        self.results     = {
            "target":          target_url,
            "scan_time":       None,
            "scan_id":         datetime.now().strftime("%Y%m%d_%H%M%S"),
            "owasp_version":   "Top 10 2025",
            "vulnerabilities": [],
            "summary":         {},
        }

    def register_checker(self, checker) -> None:
        self._checkers.append(checker)

    def register_all(self) -> None:
        from engine.modules.web_security.injection_checker                 import InjectionChecker
        from engine.modules.web_security.broken_access_control_checker     import BrokenAccessControlChecker
        from engine.modules.web_security.auth_failure_checker              import AuthFailureChecker
        from engine.modules.web_security.security_misconfiguration_checker import SecurityMisconfigurationChecker
        from engine.modules.web_security.vulnerable_components_checker     import VulnerableComponentsChecker
        from engine.modules.web_security.cryptographic_failure_checker     import CryptographicFailureChecker
        from engine.modules.web_security.ssrf_checker                      import SSRFChecker

        for cls in [
            InjectionChecker, BrokenAccessControlChecker,
            AuthFailureChecker, SecurityMisconfigurationChecker,
            VulnerableComponentsChecker, CryptographicFailureChecker,
            SSRFChecker,
        ]:
            self._checkers.append(cls(self.target_url))

    def run_all_checks(self) -> dict:
        self.results["scan_time"] = datetime.now().isoformat()
        print(f"\n[OWASP] Target  : {self.target_url}")
        print(f"[OWASP] Checkers: {len(self._checkers)}")
        print(f"[OWASP] Standard: OWASP Top 10 2025\n")

        if not self._checkers:
            print("[OWASP] No checkers — calling register_all() automatically")
            self.register_all()

        all_findings = []

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._run_single, checker): checker
                for checker in self._checkers
            }
            for future in as_completed(futures):
                checker = futures[future]
                name    = checker.__class__.__name__
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    print(f"  [{name}] {len(findings)} finding(s)")
                except Exception as e:
                    print(f"  [{name}] ERROR: {e}")

        self.results["vulnerabilities"] = all_findings
        self.results["summary"]         = self._build_summary(all_findings)
        self._print_summary()
        return self.results

    @staticmethod
    def _run_single(checker) -> list:
        result = checker.run_check()
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("findings", "vulnerabilities", "results"):
                if key in result and isinstance(result[key], list):
                    return result[key]
            if "title" in result or "owasp_id" in result:
                return [result]
        return []

    @staticmethod
    def _build_summary(findings: list) -> dict:
        counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        owasp_ids = set()
        for f in findings:
            risk = str(f.get("risk", f.get("risk_level", "INFO"))).upper()
            counts[risk] = counts.get(risk, 0) + 1
            oid = f.get("owasp_id", f.get("owasp", ""))
            if oid:
                owasp_ids.add(oid)
        return {
            "total_findings":   len(findings),
            "critical":         counts["CRITICAL"],
            "high":             counts["HIGH"],
            "medium":           counts["MEDIUM"],
            "low":              counts["LOW"],
            "owasp_categories": sorted(owasp_ids),
            "risk_score":       min(100, counts["CRITICAL"]*20 +
                                        counts["HIGH"]*10 +
                                        counts["MEDIUM"]*5 +
                                        counts["LOW"]*1),
        }

    def _print_summary(self) -> None:
        s = self.results["summary"]
        print(f"\n[OWASP] ── Scan Complete ──────────────")
        print(f"  Total   : {s.get('total_findings', 0)}")
        print(f"  Critical: {s.get('critical', 0)}")
        print(f"  High    : {s.get('high', 0)}")
        print(f"  Medium  : {s.get('medium', 0)}")
        print(f"  Low     : {s.get('low', 0)}")
        print(f"  Categories: {s.get('owasp_categories', [])}")
        print(f"  Risk Score: {s.get('risk_score', 0)}/100")

    def save_report(self, filename: str = None) -> str:
        import os
        if not filename:
            filename = f"reports/owasp_report_{self.results['scan_id']}.json"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[OWASP] Report saved: {filename}")
        return filename
