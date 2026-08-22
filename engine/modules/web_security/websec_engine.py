"""
web_security/websec_engine.py
------------------------------
Orchestrator: runs the registered checkers against a target, collects
their `run_check()` output, feeds it into VulnCorrelator, and returns
one consolidated report.

This module contains NO scanning/probing logic itself -- it only
imports and calls checker classes that already expose:

    Checker(target_url, timeout=..., **kwargs).run_check() -> {
        "check_name": str, "category": str,
        "findings": [WebFinding.to_dict(), ...], "status": str
    }

REGISTERED_CHECKERS below is intentionally the extension point: add a
new checker's import + entry there, nothing else needs to change.
"""

import time
from typing import List, Optional, Type

from .vuln_correlator import VulnCorrelator
from .security_headers import SecurityHeadersChecker
from .cors_checker import CORSChecker
from .broken_access_control_checker import BrokenAccessControlChecker

# ── Extension point ──────────────────────────────────────────────────────
# Each entry: (CheckerClass, kwargs_dict). kwargs_dict is merged with
# {"target_url": ..., "timeout": ...} at run time -- put any
# checker-specific constructor args here (e.g. sensitive_paths for
# CORSChecker) rather than hardcoding them in run_all().
REGISTERED_CHECKERS: List[tuple] = [
    (SecurityHeadersChecker, {}),
    (CORSChecker, {}),
    (BrokenAccessControlChecker, {}),  # active: registers a probe account
    # (InjectionChecker, {}),                  # intentionally NOT registered
    # (XSSChecker, {}),                        # intentionally NOT registered
    # (BrokenAccessControlChecker, {}),        # add here once reviewed
]


class WebSecurityEngine:

    def __init__(self, target_url: str, timeout: int = 10,
                 checkers: Optional[List[tuple]] = None,
                 cors_sensitive_paths: Optional[List[str]] = None):
        """
        checkers: override REGISTERED_CHECKERS entirely if provided
            (e.g. to run a subset, or to inject a checker not in the
            default registry for a one-off scan).
        cors_sensitive_paths: convenience passthrough -- merged into
            CORSChecker's kwargs if CORSChecker is in the active list,
            since it's the one common per-target customization.
        """
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self._checkers = checkers if checkers is not None else REGISTERED_CHECKERS
        self._cors_sensitive_paths = cors_sensitive_paths or []

        self.check_results: List[dict] = []
        self.correlator: Optional[VulnCorrelator] = None
        self.duration_seconds: float = 0.0

    def _instantiate(self, checker_cls: Type, kwargs: dict):
        merged = {"target_url": self.target_url, "timeout": self.timeout}
        merged.update(kwargs)
        if checker_cls is CORSChecker and "sensitive_paths" not in merged:
            merged["sensitive_paths"] = self._cors_sensitive_paths
        return checker_cls(**merged)

    def run_all(self) -> dict:
        """Runs every registered checker, correlates results, returns
        the full report dict. Never raises on an individual checker's
        failure -- a checker that errors is recorded as an ERROR
        result and the run continues."""
        start = time.time()
        self.check_results = []

        for checker_cls, kwargs in self._checkers:
            name = checker_cls.__name__
            try:
                instance = self._instantiate(checker_cls, kwargs)
                result = instance.run_check()
            except Exception as exc:
                result = {
                    "check_name": name,
                    "category": "UNKNOWN",
                    "findings": [],
                    "status": "ERROR",
                    "error": str(exc),
                }
                print(f"  [WebSecurityEngine] {name} raised {exc!r}; recorded as ERROR")
            self.check_results.append(result)

        self.correlator = VulnCorrelator(self.check_results)
        summary = self.correlator.summarize()
        self.duration_seconds = round(time.time() - start, 2)

        return {
            "target": self.target_url,
            "duration_seconds": self.duration_seconds,
            "checks": self.check_results,
            "summary": summary,
        }
