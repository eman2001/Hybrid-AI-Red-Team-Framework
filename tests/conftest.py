"""
tests/conftest.py — pytest fixtures and configuration
"""
import sys, os
import pytest

# Make project root importable from tests/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def sample_findings():
    return [
        {"host":"192.168.1.100","port":21, "service":"ftp",  "cve":"CVE-2011-2523",
         "severity":"critical","cvss":10.0,"risk_score":95,
         "exploit":"exploit/unix/ftp/vsftpd_234_backdoor","edb_title":"vsftpd backdoor"},
        {"host":"192.168.1.100","port":445,"service":"smb",  "cve":"CVE-2007-2447",
         "severity":"critical","cvss":9.3, "risk_score":88,
         "exploit":"exploit/multi/samba/usermap_script","edb_title":"Samba RCE"},
        {"host":"192.168.1.100","port":22, "service":"ssh",  "cve":"CVE-2008-0166",
         "severity":"high",    "cvss":7.8, "risk_score":52,
         "exploit":"hydra","edb_title":"SSH brute force"},
    ]


@pytest.fixture(scope="session")
def sample_scan_results():
    return {
        "192.168.1.100": {
            "os": "linux",
            "ports": [
                {"port":21, "proto":"tcp","service":"ftp",  "product":"vsftpd", "version":"2.3.4"},
                {"port":22, "proto":"tcp","service":"ssh",  "product":"OpenSSH","version":"4.7p1"},
                {"port":445,"proto":"tcp","service":"smb",  "product":"Samba",  "version":"3.0.20"},
                {"port":80, "proto":"tcp","service":"http", "product":"Apache", "version":"2.2.8"},
            ]
        }
    }


@pytest.fixture(scope="session")
def sample_attack_chain():
    return {
        "1": {"phase_name":"Initial Access",    "tactic":"initial-access",
              "techniques":[{"id":"T1190","name":"Exploit Public-Facing App"}],
              "hosts":["192.168.1.100"],"confidence":0.95,"source":"rule_exact"},
        "2": {"phase_name":"Credential Access", "tactic":"credential-access",
              "techniques":[{"id":"T1003","name":"OS Credential Dumping"}],
              "hosts":["192.168.1.100"],"confidence":0.93,"source":"post_exploit"},
        "3": {"phase_name":"Discovery",         "tactic":"discovery",
              "techniques":[{"id":"T1082","name":"System Info Discovery"}],
              "hosts":["192.168.1.100"],"confidence":0.95,"source":"post_exploit"},
    }
