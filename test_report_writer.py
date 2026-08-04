"""
test_report_writer.py
------------------------
Quick sanity check: does the REAL pipeline (summary_builder -> prompts ->
llm_engine) produce a project-specific report, instead of the generic
one you get from testing the raw Ollama prompt directly?

Run:
    export OLLAMA_HOST="http://192.168.0.103:11434"
    export OLLAMA_MODEL="qwen2.5:3b"
    python3 test_report_writer.py
"""

from engine.modules.llm.report_writer import ReportWriter

# Sample data shaped like your project's real pipeline output
findings = [
    {
        "cve": "N/A",
        "vulnerability": "FTP Anonymous Login",
        "severity": "high",
        "host": "192.168.56.1",
        "port": 21,
        "cvss": 7.5,
        "in_kev": False,
        "remediation": "Disable anonymous FTP access.",
    },
    {
        "cve": "CVE-2021-41773",
        "vulnerability": "SQL Injection",
        "severity": "critical",
        "host": "192.168.56.1",
        "port": 80,
        "cvss": 9.8,
        "in_kev": True,
        "remediation": "Use parameterized queries; apply vendor patch.",
    },
]

mapped_results = [
    {
        "host": "192.168.56.1",
        "layers": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "initial-access",
                "score": 100,
                "confidence": "95%",
                "source": "rule_exact",
            },
            {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": "initial-access",
                "score": 60,
                "confidence": "70%",
                "source": "ml_predicted",
            },
        ],
    }
]

risk_summary = {
    "overall_risk": "CRITICAL",
    "risk_score": 90,
    "total_findings": 2,
    "high_risk_count": 2,
    "kev_count": 1,
    "exploit_success": 1,
    "scope": ["192.168.56.1"],
}

attack_chain = [
    {"phase": "Initial Access", "technique_id": "T1190"},
    {"phase": "Execution", "technique_id": "T1059"},
]

writer = ReportWriter()

print("[*] Checking Ollama availability...")
print("    Available:", writer.llm.is_available())

print("\n[*] Generating full report via the real pipeline...\n")
report = writer.generate_full_report(
    findings=findings,
    mapped_results=mapped_results,
    attack_chain=attack_chain,
    risk_summary=risk_summary,
)

for section, text in report.items():
    print("=" * 60)
    print(section.upper())
    print("=" * 60)
    print(text)
    print()
