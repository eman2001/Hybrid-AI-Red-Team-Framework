"""
tests/test_threat_intel.py
Unit tests for the Threat Intelligence module.
Run: pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.threat_intelligence.epss_engine  import EpssEngine
from modules.threat_intelligence.kev_engine   import KevEngine
from modules.threat_intelligence.threat_score  import ThreatScore


class TestEpssEngine:
    def setup_method(self):
        self.engine = EpssEngine()

    def test_known_cve_returns_float(self):
        score = self.engine.score("CVE-2017-0144")
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_eternalblue_high_epss(self):
        score = self.engine.score("CVE-2017-0144")
        assert score >= 0.90, "EternalBlue should have very high EPSS"

    def test_log4shell_high_epss(self):
        score = self.engine.score("CVE-2021-44228")
        assert score >= 0.90

    def test_unknown_cve_fallback(self):
        score = self.engine.score("CVE-2099-99999")
        assert 0.0 <= score <= 1.0

    def test_risk_label_very_high(self):
        assert self.engine.risk_label(0.95) == "VERY_HIGH"

    def test_risk_label_high(self):
        assert self.engine.risk_label(0.50) == "HIGH"

    def test_risk_label_medium(self):
        assert self.engine.risk_label(0.20) == "MEDIUM"

    def test_risk_label_low(self):
        assert self.engine.risk_label(0.05) == "LOW"


class TestKevEngine:
    def setup_method(self):
        self.engine = KevEngine()

    def test_eternalblue_is_kev(self):
        assert self.engine.is_kev("CVE-2017-0144") is True

    def test_unknown_cve_not_kev(self):
        assert self.engine.is_kev("CVE-2099-99999") is False

    def test_case_insensitive(self):
        assert self.engine.is_kev("cve-2017-0144") is True

    def test_vsftpd_may_be_kev(self):
        # Should return bool regardless
        result = self.engine.is_kev("CVE-2011-2523")
        assert isinstance(result, bool)


class TestThreatScore:
    def setup_method(self):
        self.scorer = ThreatScore()

    def test_high_cvss_high_score(self):
        finding = {"cvss_live": 10.0, "epss": 0.975, "in_kev": True}
        score = self.scorer.calculate(finding)
        assert score >= 80.0

    def test_kev_bonus_applied(self):
        base    = self.scorer.calculate({"cvss_live": 5.0, "epss": 0.1, "in_kev": False})
        with_kev= self.scorer.calculate({"cvss_live": 5.0, "epss": 0.1, "in_kev": True})
        assert with_kev > base

    def test_score_capped_at_100(self):
        score = self.scorer.calculate({"cvss_live": 10.0, "epss": 1.0, "in_kev": True, "eol_risk": "CRITICAL"})
        assert score <= 100.0

    def test_label_critical(self):
        assert self.scorer.label(85.0) == "CRITICAL"

    def test_label_high(self):
        assert self.scorer.label(65.0) == "HIGH"

    def test_label_medium(self):
        assert self.scorer.label(45.0) == "MEDIUM"

    def test_label_low(self):
        assert self.scorer.label(25.0) == "LOW"

    def test_label_informational(self):
        assert self.scorer.label(10.0) == "INFORMATIONAL"
