"""
tests/test_api.py
FastAPI endpoint integration tests using httpx (no real network calls).
Run: pytest tests/test_api.py -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

try:
    from fastapi.testclient import TestClient
    from app import app
    CLIENT = TestClient(app)
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

skip_no_fastapi = pytest.mark.skipif(
    not HAS_FASTAPI, reason="fastapi not installed"
)


@skip_no_fastapi
class TestHealthEndpoints:
    def test_root(self):
        r = CLIENT.get("/")
        assert r.status_code == 200
        data = r.json()
        assert "framework" in data
        assert "endpoints" in data

    def test_health(self):
        r = CLIENT.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


@skip_no_fastapi
class TestVulnEndpoints:
    def test_list_all(self):
        r = CLIENT.get("/api/vulnerabilities/")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert data["total"] >= 1
        assert "vulnerabilities" in data

    def test_filter_critical(self):
        r = CLIENT.get("/api/vulnerabilities/?severity=critical")
        assert r.status_code == 200
        data = r.json()
        for v in data["vulnerabilities"]:
            assert v["severity"] == "critical"

    def test_filter_min_cvss(self):
        r = CLIENT.get("/api/vulnerabilities/?min_cvss=9.0")
        assert r.status_code == 200
        data = r.json()
        for v in data["vulnerabilities"]:
            assert v["cvss"] >= 9.0

    def test_get_by_cve(self):
        r = CLIENT.get("/api/vulnerabilities/CVE-2011-2523")
        assert r.status_code in (200, 404)

    def test_unknown_cve_404(self):
        r = CLIENT.get("/api/vulnerabilities/CVE-0000-0000")
        assert r.status_code == 404

    def test_kev_list(self):
        r = CLIENT.get("/api/vulnerabilities/kev")
        assert r.status_code == 200
        for v in r.json()["vulnerabilities"]:
            assert v["intel"]["kev"] is True


@skip_no_fastapi
class TestThreatIntelEndpoints:
    def test_get_all(self):
        r = CLIENT.get("/api/threat-intelligence/")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "avg_cvss" in data
        assert "findings" in data

    def test_kev_only(self):
        r = CLIENT.get("/api/threat-intelligence/kev")
        assert r.status_code == 200
        for f in r.json():
            assert f["kev"] is True

    def test_top_epss(self):
        r = CLIENT.get("/api/threat-intelligence/epss/top?limit=3")
        assert r.status_code == 200
        findings = r.json()
        assert len(findings) <= 3
        # Should be sorted descending
        if len(findings) >= 2:
            assert findings[0]["epss"] >= findings[1]["epss"]

    def test_specific_cve(self):
        r = CLIENT.get("/api/threat-intelligence/CVE-2017-0144")
        assert r.status_code == 200
        data = r.json()
        assert data["cve"] == "CVE-2017-0144"
        assert data["kev"] is True


@skip_no_fastapi
class TestMitreEndpoints:
    def test_techniques(self):
        r = CLIENT.get("/api/mitre/techniques")
        assert r.status_code == 200
        data = r.json()
        assert "total_techniques" in data
        assert data["total_techniques"] >= 1

    def test_tactics(self):
        r = CLIENT.get("/api/mitre/tactics")
        assert r.status_code == 200
        data = r.json()
        assert "tactic_distribution" in data

    def test_heatmap(self):
        r = CLIENT.get("/api/mitre/heatmap")
        assert r.status_code == 200
        data = r.json()
        assert "techniques" in data
        assert "domain" in data
        assert data["domain"] == "enterprise-attack"


@skip_no_fastapi
class TestAttackChainEndpoints:
    def test_get_chain(self):
        r = CLIENT.get("/api/attack-chain/")
        assert r.status_code == 200
        data = r.json()
        assert "phase_count" in data
        assert data["phase_count"] >= 1

    def test_get_phases(self):
        r = CLIENT.get("/api/attack-chain/phases")
        assert r.status_code == 200
        assert "phases" in r.json()

    def test_export_navigator(self):
        r = CLIENT.get("/api/attack-chain/export/navigator")
        assert r.status_code == 200
        data = r.json()
        assert "techniques" in data


@skip_no_fastapi
class TestAnalyticsEndpoints:
    def test_dashboard(self):
        r = CLIENT.get("/api/analytics/dashboard")
        assert r.status_code == 200
        data = r.json()
        assert "vuln_count"       in data
        assert "technique_count"  in data
        assert "pipeline_status"  in data
        assert all(data["pipeline_status"].values())

    def test_risk_analytics(self):
        r = CLIENT.get("/api/analytics/risk")
        assert r.status_code == 200
        data = r.json()
        assert "risk_distribution" in data

    def test_coverage_analytics(self):
        r = CLIENT.get("/api/analytics/coverage")
        assert r.status_code == 200
        data = r.json()
        assert "coverage_pct" in data
        assert 0 <= data["coverage_pct"] <= 100

    def test_ml_analytics(self):
        r = CLIENT.get("/api/analytics/ml")
        assert r.status_code == 200
        data = r.json()
        assert "model_type" in data
        assert "accuracy"   in data
