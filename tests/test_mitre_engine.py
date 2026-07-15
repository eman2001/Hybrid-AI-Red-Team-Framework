"""
tests/test_mitre_engine.py
Unit tests for the 3-layer MITRE ATT&CK Engine.
Run: pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.mitre.rule_resolver   import RuleResolver
from modules.mitre.chain_builder   import ChainBuilder
from modules.mitre.heatmap_generator import HeatmapGenerator


class TestRuleResolver:
    def setup_method(self):
        self.resolver = RuleResolver()

    def test_vsftpd_exact_match(self):
        result = self.resolver.resolve({
            "exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
            "service": "ftp", "cve": "CVE-2011-2523",
        })
        assert result is not None
        assert result["technique_id"] == "T1190"
        assert result["source"] == "rule_exact"
        assert result["confidence"] >= 0.90

    def test_eternalblue_exact_match(self):
        result = self.resolver.resolve({
            "exploit": "exploit/windows/smb/ms17_010_eternalblue",
            "service": "smb", "cve": "CVE-2017-0144",
        })
        assert result is not None
        assert result["technique_id"] == "T1210"
        assert result["tactic"] == "lateral-movement"

    def test_smb_service_fallback(self):
        result = self.resolver.resolve({
            "exploit": "unknown_exploit",
            "service": "smb", "cve": "N/A",
        })
        assert result is not None
        assert result["tactic"] == "lateral-movement"

    def test_ssh_service_fallback(self):
        result = self.resolver.resolve({
            "exploit": "", "service": "ssh", "cve": "",
        })
        assert result is not None
        assert result["tactic"] == "credential-access"

    def test_post_command_hashdump(self):
        result = self.resolver.resolve({
            "exploit": "", "service": "misc", "cve": "",
            "post_commands": ["hashdump"],
        })
        assert result is not None
        assert result["technique_id"] == "T1003"
        assert result["tactic"] == "credential-access"
        assert result["source"] == "post_exploit"

    def test_post_command_sysinfo(self):
        result = self.resolver.resolve({
            "exploit": "", "service": "misc", "cve": "",
            "post_commands": ["sysinfo"],
        })
        assert result is not None
        assert result["technique_id"] == "T1082"

    def test_cve_year_fallback(self):
        result = self.resolver.resolve({
            "exploit": "", "service": "misc",
            "cve": "CVE-2017-9999",
        })
        assert result is not None
        assert result["tactic"] == "lateral-movement"

    def test_unknown_returns_none(self):
        result = self.resolver.resolve({
            "exploit": "", "service": "unknown999",
            "cve": "", "post_commands": [],
        })
        assert result is None

    def test_resolve_post_commands_list(self):
        commands = ["sysinfo", "getuid", "hashdump", "arp", "ps"]
        results  = self.resolver.resolve_post_commands(commands)
        assert len(results) >= 3
        ids = [r["technique_id"] for r in results]
        assert "T1082" in ids
        assert "T1003" in ids


class TestChainBuilder:
    def setup_method(self):
        self.builder = ChainBuilder()

    def _make_mapped(self, tactic, tid, tname, conf=0.85, src="rule"):
        return {
            "host": "192.168.1.100",
            "layers": [{"technique_id": tid, "technique_name": tname,
                        "tactic": tactic, "confidence": conf, "source": src}],
        }

    def test_chain_builds_correctly(self):
        mapped = [
            self._make_mapped("initial-access",    "T1190", "Exploit Public-Facing App"),
            self._make_mapped("credential-access", "T1003", "OS Credential Dumping", src="post_exploit"),
            self._make_mapped("discovery",         "T1082", "System Info Discovery",  src="post_exploit"),
        ]
        chain = self.builder.build(mapped)
        assert len(chain) >= 3
        tactics = [v["tactic"] for v in chain.values()]
        assert "initial-access" in tactics

    def test_pseudo_ids_filtered(self):
        mapped = [
            self._make_mapped("initial-access",    "T1190", "Real Technique"),
            self._make_mapped("discovery",         "T-KW",  "Fake ML Technique"),
        ]
        chain = self.builder.build(mapped)
        for phase in chain.values():
            for tech in phase["techniques"]:
                assert not tech["id"].startswith("T-")

    def test_deduplication(self):
        mapped = [
            self._make_mapped("initial-access", "T1190", "Exploit Public-Facing App"),
            self._make_mapped("initial-access", "T1190", "Exploit Public-Facing App"),
        ]
        chain = self.builder.build(mapped)
        for phase in chain.values():
            if phase["tactic"] == "initial-access":
                t_ids = [t["id"] for t in phase["techniques"]]
                assert t_ids.count("T1190") == 1


class TestHeatmapGenerator:
    def setup_method(self):
        self.gen = HeatmapGenerator()

    def _make_result(self, tid, src, conf=0.85):
        return {
            "host": "192.168.1.100",
            "layers": [{"technique_id": tid, "technique_name": "Test",
                        "tactic": "initial-access", "confidence": conf, "source": src}],
        }

    def test_heatmap_generates_techniques(self):
        mapped = [self._make_result("T1190", "rule_exact", 0.95)]
        layer  = self.gen.generate(mapped)
        assert "techniques" in layer
        assert len(layer["techniques"]) >= 1

    def test_heatmap_scores_rule_exact(self):
        mapped = [self._make_result("T1190", "rule_exact", 0.95)]
        layer  = self.gen.generate(mapped)
        tech   = next(t for t in layer["techniques"] if t["techniqueID"] == "T1190")
        assert tech["score"] == 100

    def test_heatmap_scores_ml_lower(self):
        mapped = [self._make_result("T1547", "ml", 0.55)]
        layer  = self.gen.generate(mapped)
        tech   = next(t for t in layer["techniques"] if t["techniqueID"] == "T1547")
        assert tech["score"] < 70

    def test_pseudo_ids_excluded(self):
        mapped = [
            self._make_result("T1190", "rule_exact"),
            self._make_result("T-KW",  "ml_fallback"),
        ]
        layer = self.gen.generate(mapped)
        ids   = [t["techniqueID"] for t in layer["techniques"]]
        assert "T-KW" not in ids
        assert "T1190" in ids

    def test_navigator_format(self):
        mapped = [self._make_result("T1190", "rule_exact")]
        layer  = self.gen.generate(mapped)
        assert "name"       in layer
        assert "domain"     in layer
        assert "techniques" in layer
        assert "gradient"   in layer
        assert layer["domain"] == "enterprise-attack"
