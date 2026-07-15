"""
rule_resolver.py  —  Layer 1: Deterministic Rule-Based MITRE Mapping
Confidence: 0.85 – 0.95
"""

# ── Exact exploit-path → ATT&CK technique table ──────────────────────
EXPLOIT_RULES = {
    # ── Metasploitable2 (الأصلية) ──────────────────────────────────
    "exploit/unix/ftp/vsftpd_234_backdoor":          ("T1190", "Exploit Public-Facing Application", "initial-access",       0.95),
    "exploit/multi/samba/usermap_script":            ("T1210", "Exploitation of Remote Services",   "lateral-movement",     0.95),
    "exploit/unix/irc/unreal_ircd_3281_backdoor":    ("T1190", "Exploit Public-Facing Application", "initial-access",       0.93),
    "exploit/multi/http/apache_mod_cgi_bash_env_exec":("T1190","Exploit Public-Facing Application", "initial-access",       0.92),
    "exploit/multi/http/drupalgeddon2":              ("T1190", "Exploit Public-Facing Application", "initial-access",       0.92),
    "exploit/windows/smb/ms17_010_eternalblue":      ("T1210", "Exploitation of Remote Services",   "lateral-movement",     0.95),
    "exploit/multi/misc/distcc_exec":                ("T1190", "Exploit Public-Facing Application", "initial-access",       0.92),
    "exploit/multi/handler":                         ("T1059", "Command and Scripting Interpreter",  "execution",            0.88),

    # ── Windows — اختراقات حقيقية مشهورة ───────────────────────────
    "exploit/windows/smb/ms08_067_netapi":           ("T1210", "Exploitation of Remote Services",   "lateral-movement",     0.95),
    "exploit/windows/rdp/cve_2019_0708_bluekeep_rce":("T1210", "Exploitation of Remote Services",   "lateral-movement",     0.93),
    "exploit/windows/local/cve_2021_34527_printnightmare":("T1068","Exploitation for Privilege Escalation","privilege-escalation",0.93),
    "exploit/windows/smb/psexec":                    ("T1021", "Remote Services",                   "lateral-movement",     0.92),
    "exploit/windows/local/ms16_032_secondary_logon_handle_privesc":("T1068","Exploitation for Privilege Escalation","privilege-escalation",0.90),
    "exploit/windows/http/icecast_header":           ("T1190", "Exploit Public-Facing Application", "initial-access",       0.88),
    "exploit/windows/dcerpc/ms03_026_dcom":          ("T1210", "Exploitation of Remote Services",   "lateral-movement",     0.92),
    "exploit/windows/smb/ms09_050_smb2_negotiate_func_index":("T1210","Exploitation of Remote Services","lateral-movement",0.90),

    # ── Linux — اختراقات حقيقية مشهورة ─────────────────────────────
    "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec":("T1068","Exploitation for Privilege Escalation","privilege-escalation",0.95),
    "exploit/linux/local/cve_2022_0847_dirtypipe":   ("T1068", "Exploitation for Privilege Escalation","privilege-escalation",  0.94),
    "exploit/linux/http/rconfig_ajaxarchivefiles_rce":("T1190","Exploit Public-Facing Application",  "initial-access",       0.90),
    "exploit/linux/ssh/ssh_x11_forwarding_privesc":  ("T1068", "Exploitation for Privilege Escalation","privilege-escalation",  0.88),
    "exploit/linux/local/cve_2016_5195_dirtycow":    ("T1068", "Exploitation for Privilege Escalation","privilege-escalation",  0.93),

    # ── Web — اختراقات حقيقية مشهورة عالمياً ───────────────────────
    "exploit/multi/http/log4shell_header_injection": ("T1190", "Exploit Public-Facing Application", "initial-access",       0.96),
    "exploit/unix/webapp/joomla_comfields_sqli_rce": ("T1190", "Exploit Public-Facing Application", "initial-access",       0.92),
    "exploit/multi/http/apache_normalize_path_rce":  ("T1190", "Exploit Public-Facing Application", "initial-access",       0.93),
    "exploit/multi/http/struts2_content_type_ognl":  ("T1190", "Exploit Public-Facing Application", "initial-access",       0.93),
    "exploit/multi/http/wp_admin_shell_upload":      ("T1190", "Exploit Public-Facing Application", "initial-access",       0.90),
    "exploit/multi/http/jenkins_script_console":     ("T1059", "Command and Scripting Interpreter",  "execution",            0.91),
    "exploit/unix/webapp/php_cgi_arg_injection":     ("T1190", "Exploit Public-Facing Application", "initial-access",       0.89),
    "exploit/multi/http/spring4shell_rce":           ("T1190", "Exploit Public-Facing Application", "initial-access",       0.94),

    # ── Credential Access / Recon (auxiliary modules) ──────────────
    "auxiliary/scanner/smb/smb_login":               ("T1078", "Valid Accounts",                    "initial-access",       0.90),
    "auxiliary/scanner/ssh/ssh_login":                ("T1078", "Valid Accounts",                    "initial-access",       0.88),
    "auxiliary/scanner/ftp/ftp_login":                ("T1078", "Valid Accounts",                    "initial-access",       0.87),
    "auxiliary/scanner/mysql/mysql_login":            ("T1078", "Valid Accounts",                    "initial-access",       0.86),
    "auxiliary/scanner/rdp/rdp_scanner":               ("T1018", "Remote System Discovery",           "discovery",            0.85),
    "post/multi/recon/local_exploit_suggester":       ("T1068", "Exploitation for Privilege Escalation","privilege-escalation",0.85),
    "post/multi/gather/checkvm":                      ("T1497", "Virtualization/Sandbox Evasion",     "defense-evasion",      0.85),
    "post/windows/gather/credentials/credential_collector":("T1003","OS Credential Dumping",          "credential-access",   0.92),
    "post/linux/gather/hashdump":                     ("T1003", "OS Credential Dumping",              "credential-access",   0.92),

    # ── C2 / Persistence ─────────────────────────────────────────────
    "exploit/multi/script/web_delivery":              ("T1105", "Ingress Tool Transfer",              "command-and-control", 0.88),
    "post/windows/manage/persistence_exe":            ("T1547", "Boot/Logon Autostart Execution",      "persistence",         0.88),
    "post/linux/manage/persistence":                  ("T1547", "Boot/Logon Autostart Execution",      "persistence",         0.87),
}

# ── Service/port fallback rules ───────────────────────────────────────
SERVICE_RULES = {
    "ftp":           ("T1110", "Brute Force",                          "credential-access",     0.87),
    "ssh":           ("T1110", "Brute Force",                          "credential-access",     0.87),
    "telnet":        ("T1110", "Brute Force",                          "credential-access",     0.90),
    "smb":           ("T1021", "Remote Services",                      "lateral-movement",      0.86),
    "microsoft-ds":  ("T1021", "Remote Services",                      "lateral-movement",      0.86),
    "rdp":           ("T1021", "Remote Services",                      "lateral-movement",      0.88),
    "http":          ("T1190", "Exploit Public-Facing Application",    "initial-access",        0.85),
    "https":         ("T1190", "Exploit Public-Facing Application",    "initial-access",        0.85),
    "mysql":         ("T1110", "Brute Force",                          "credential-access",     0.86),
    "mssql":         ("T1110", "Brute Force",                          "credential-access",     0.86),
    "postgresql":    ("T1110", "Brute Force",                          "credential-access",     0.85),
    "irc":           ("T1190", "Exploit Public-Facing Application",    "initial-access",        0.90),
    "distcc":        ("T1190", "Exploit Public-Facing Application",    "initial-access",        0.91),
    "vnc":           ("T1021", "Remote Services",                      "lateral-movement",      0.87),
    "smtp":          ("T1566", "Phishing",                             "initial-access",        0.85),
}

# ── Known CVE prefixes ────────────────────────────────────────────────
CVE_YEAR_RULES = {
    "CVE-2017": ("T1210", "Exploitation of Remote Services",  "lateral-movement", 0.88),
    "CVE-2019": ("T1190", "Exploit Public-Facing Application","initial-access",   0.88),
    "CVE-2011": ("T1190", "Exploit Public-Facing Application","initial-access",   0.90),
    "CVE-2007": ("T1210", "Exploitation of Remote Services",  "lateral-movement", 0.88),
    "CVE-2010": ("T1190", "Exploit Public-Facing Application","initial-access",   0.87),
    "CVE-2008": ("T1110", "Brute Force",                      "credential-access",0.85),
}

# ── Post-exploit session command → technique ─────────────────────────
POST_EXPLOIT_MAP = {
    "hashdump":    ("T1003", "OS Credential Dumping",              "credential-access",     0.95),
    "sysinfo":     ("T1082", "System Information Discovery",       "discovery",             0.95),
    "getuid":      ("T1033", "System Owner/User Discovery",        "discovery",             0.95),
    "getsystem":   ("T1068", "Exploitation for Privilege Escalation","privilege-escalation",0.93),
    "ps":          ("T1057", "Process Discovery",                  "discovery",             0.93),
    "arp":         ("T1016", "System Network Config Discovery",    "discovery",             0.93),
    "route":       ("T1016", "System Network Config Discovery",    "discovery",             0.92),
    "ipconfig":    ("T1016", "System Network Config Discovery",    "discovery",             0.93),
    "ifconfig":    ("T1016", "System Network Config Discovery",    "discovery",             0.93),
    "netstat":     ("T1049", "System Network Connections Discovery","discovery",            0.92),
    "shell":       ("T1059", "Command and Scripting Interpreter",  "execution",             0.90),
    "meterpreter": ("T1059", "Command and Scripting Interpreter",  "execution",             0.90),
    "upload":      ("T1105", "Ingress Tool Transfer",              "command-and-control",   0.88),
    "download":    ("T1005", "Data from Local System",             "collection",            0.88),
    "search":      ("T1083", "File and Directory Discovery",       "discovery",             0.88),
    "keyscan":     ("T1056", "Input Capture",                      "collection",            0.88),
    "screenshare": ("T1113", "Screen Capture",                     "collection",            0.87),
    "persistence": ("T1547", "Boot/Logon Autostart Execution",     "persistence",           0.87),
}


class RuleResolver:
    """
    Layer 1 — Deterministic lookup.
    Returns a dict with keys: technique_id, technique_name, tactic, confidence, source.
    Returns None when no rule matches.
    """

    def resolve(self, context: dict) -> dict | None:
        exploit  = context.get("exploit", "")
        service  = context.get("service", "").lower()
        cve      = context.get("cve", "")
        commands = context.get("post_commands", [])

        # 1. Exact exploit path
        for key, (tid, tname, tactic, conf) in EXPLOIT_RULES.items():
            if key in exploit:
                return self._result(tid, tname, tactic, conf, "rule_exact")

        # 2. Post-exploit commands (highest priority for enrichment)
        for cmd in commands:
            cmd_lower = cmd.lower().strip()
            for kw, (tid, tname, tactic, conf) in POST_EXPLOIT_MAP.items():
                if kw in cmd_lower:
                    return self._result(tid, tname, tactic, conf, "post_exploit")

        # 3. Service name
        if service in SERVICE_RULES:
            tid, tname, tactic, conf = SERVICE_RULES[service]
            return self._result(tid, tname, tactic, conf, "rule_service")

        # 4. CVE year prefix
        for prefix, (tid, tname, tactic, conf) in CVE_YEAR_RULES.items():
            if cve.upper().startswith(prefix):
                return self._result(tid, tname, tactic, conf, "rule_cve")

        return None

    def resolve_post_commands(self, commands: list) -> list[dict]:
        """Map a list of Meterpreter commands to ATT&CK techniques."""
        results = []
        seen = set()
        for cmd in commands:
            cmd_lower = cmd.lower().strip()
            for kw, (tid, tname, tactic, conf) in POST_EXPLOIT_MAP.items():
                if kw in cmd_lower and tid not in seen:
                    results.append(self._result(tid, tname, tactic, conf, "post_exploit"))
                    seen.add(tid)
                    break
        return results

    @staticmethod
    def _result(tid, tname, tactic, conf, source) -> dict:
        return {
            "technique_id":   tid,
            "technique_name": tname,
            "tactic":         tactic,
            "confidence":     conf,
            "source":         source,
        }
