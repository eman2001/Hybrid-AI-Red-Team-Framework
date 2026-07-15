"""modules/risk_engine.py"""
from engine.config.constants import KNOWN_CVSS_SCORES


class RiskEngine:

    SERVICE_WEIGHTS = {
        "ftp": 10, "smb": 10, "samba": 10, "microsoft-ds": 10,
        "netbios-ssn": 10, "telnet": 9, "rdp": 9, "vnc": 9,
        "ssh": 8, "mysql": 8, "mssql": 8, "postgresql": 7,
        "http": 7, "https": 7, "irc": 8, "bindshell": 10,
        "java-rmi": 7, "exec": 9, "login": 9,
    }

    EXPOSED_PORTS = {21, 22, 23, 25, 80, 139, 445, 512, 513,
                     1099, 1524, 3306, 5432, 6667, 8180}

    def _cvss_score(self, cve: str, finding_cvss: float) -> float:
        # Priority: cvss_live from TI → KNOWN table → finding cvss → 3.0
        if finding_cvss and finding_cvss > 3.0:
            return finding_cvss
        known = KNOWN_CVSS_SCORES.get(cve, 0)
        if known > 0:
            return known
        if finding_cvss and finding_cvss > 0:
            return finding_cvss
        return 3.0

    def calculate_risk(self, finding: dict) -> dict:
        score = 0

        cvss = self._cvss_score(
            finding.get("cve", ""),
            finding.get("cvss_live", finding.get("cvss", 0)),
        )
        finding["cvss"] = cvss
        score += cvss * 4

        etype = finding.get("type", "")
        if etype == "metasploit": score += 20
        elif etype == "hydra":    score += 15

        if finding.get("port") in self.EXPOSED_PORTS:
            score += 20

        score += round(finding.get("epss", 0.0) * 15)

        if finding.get("in_kev"):
            score += 20

        score += round(finding.get("threat_score", 0) * 0.10)

        svc = finding.get("service", "").lower()
        bonus = next((w*2 for k,w in self.SERVICE_WEIGHTS.items() if k in svc), 0)
        finding["priority_bonus"] = bonus
        score += bonus

        finding["risk_score"] = round(min(score, 100))
        return finding

    def filter_by_risk(self, findings: list, threshold: int = 30) -> list:
        print(f"\n[Risk Engine] Scoring {len(findings)} findings (threshold={threshold})...")
        scored, deferred = [], []
        for f in findings:
            self.calculate_risk(f)
            if f["risk_score"] >= threshold:
                scored.append(f)
            else:
                deferred.append(f)

        scored.sort(key=lambda x: (x["risk_score"], x.get("cvss",0)), reverse=True)
        print(f"  [+] High-risk: {len(scored)}  |  Deferred: {len(deferred)}")
        for i, f in enumerate(scored, 1):
            print(f"  #{i} {f['host']}:{f['port']} | Score={f['risk_score']} "
                  f"CVSS={f.get('cvss','?')} EPSS={f.get('epss',0):.3f}")
        return scored
