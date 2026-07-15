"""
detection/hunt_recommendations.py
------------------------------------
Generates threat hunting recommendations based on uncovered techniques.
"""

HUNT_PLAYBOOKS = {
    "T1003": "Hunt for lsass.exe access, hashdump activity, or Mimikatz signatures.",
    "T1059": "Hunt for suspicious PowerShell executions, encoded commands, or cmd.exe spawned by Office.",
    "T1021": "Hunt for lateral movement via SMB, WinRM, or RDP from unusual source IPs.",
    "T1190": "Hunt for exploitation attempts against public-facing services — web logs, IDS alerts.",
    "T1110": "Hunt for brute-force patterns: repeated failed logins across accounts.",
    "T1547": "Hunt for new registry Run keys or scheduled tasks created outside change windows.",
    "T1068": "Hunt for privilege escalation via kernel exploits or token impersonation.",
    "T1105": "Hunt for unexpected outbound file transfers or tool downloads.",
    "T1082": "Hunt for mass system enumeration commands (systeminfo, wmic) in short time windows.",
}

DEFAULT_HUNT = "Review endpoint telemetry for anomalous process execution and network connections."


class HuntRecommendations:

    def recommend(self, uncovered_techniques: list[str]) -> list[dict]:
        recs = []
        for tid in uncovered_techniques:
            recs.append({
                "technique_id": tid,
                "hunt_action":  HUNT_PLAYBOOKS.get(tid, DEFAULT_HUNT),
                "priority":     "HIGH" if tid in HUNT_PLAYBOOKS else "MEDIUM",
            })
        return recs
