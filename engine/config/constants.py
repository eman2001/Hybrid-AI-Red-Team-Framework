"""
config/constants.py
-------------------
Immutable constants used across the framework.
No logic here — only plain values and lookup tables.
"""

# ══════════════════════════════════════════════════════════════════════
# CVSS Severity Bands
# ══════════════════════════════════════════════════════════════════════
CVSS_NONE     = (0.0, 0.0)
CVSS_LOW      = (0.1, 3.9)
CVSS_MEDIUM   = (4.0, 6.9)
CVSS_HIGH     = (7.0, 8.9)
CVSS_CRITICAL = (9.0, 10.0)

SEVERITY_LABELS = {
    "CRITICAL": CVSS_CRITICAL,
    "HIGH":     CVSS_HIGH,
    "MEDIUM":   CVSS_MEDIUM,
    "LOW":      CVSS_LOW,
    "NONE":     CVSS_NONE,
}

def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "NONE"


# ══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Tactics (Enterprise) — ordered kill-chain
# ══════════════════════════════════════════════════════════════════════
MITRE_TACTICS_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

MITRE_TACTIC_IDS = {
    "Reconnaissance":        "TA0043",
    "Resource Development":  "TA0042",
    "Initial Access":        "TA0001",
    "Execution":             "TA0002",
    "Persistence":           "TA0003",
    "Privilege Escalation":  "TA0004",
    "Defense Evasion":       "TA0005",
    "Credential Access":     "TA0006",
    "Discovery":             "TA0007",
    "Lateral Movement":      "TA0008",
    "Collection":            "TA0009",
    "Command and Control":   "TA0011",
    "Exfiltration":          "TA0010",
    "Impact":                "TA0040",
}

# ══════════════════════════════════════════════════════════════════════
# Common Exploit / Service Port Mapping
# ══════════════════════════════════════════════════════════════════════
WELL_KNOWN_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    4848: "GlassFish",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# ══════════════════════════════════════════════════════════════════════
# Metasploit / Exploit Framework Constants
# ══════════════════════════════════════════════════════════════════════
MSF_PAYLOAD_WINDOWS = "windows/x64/meterpreter/reverse_tcp"
MSF_PAYLOAD_LINUX   = "linux/x64/meterpreter/reverse_tcp"
MSF_DEFAULT_LPORT   = 4444

# Post-exploitation command sets
POST_COMMANDS_WINDOWS = [
    "sysinfo", "getuid", "getsystem", "hashdump",
    "arp", "ipconfig", "ps", "migrate",
]
POST_COMMANDS_LINUX = [
    "sysinfo", "getuid", "shell id",
    "shell uname -a", "shell ifconfig", "shell ps aux",
]

# ══════════════════════════════════════════════════════════════════════
# Risk Score Bands  (composite score 0–100)
# ══════════════════════════════════════════════════════════════════════
RISK_CRITICAL   = 80
RISK_HIGH       = 60
RISK_MEDIUM     = 40
RISK_LOW        = 20

def risk_label(score: float) -> str:
    if score >= RISK_CRITICAL: return "CRITICAL"
    if score >= RISK_HIGH:     return "HIGH"
    if score >= RISK_MEDIUM:   return "MEDIUM"
    if score >= RISK_LOW:      return "LOW"
    return "INFORMATIONAL"

# ══════════════════════════════════════════════════════════════════════
# Supported Operating Systems
# ══════════════════════════════════════════════════════════════════════
OS_WINDOWS = "windows"
OS_LINUX   = "linux"
OS_MACOS   = "macos"
OS_UNKNOWN = "unknown"

OS_KEYWORDS_WINDOWS = ["windows", "microsoft", "win32", "winnt"]
OS_KEYWORDS_LINUX   = ["linux", "ubuntu", "debian", "centos", "rhel", "fedora", "kali"]

# ══════════════════════════════════════════════════════════════════════
# Report Formats
# ══════════════════════════════════════════════════════════════════════
REPORT_FORMAT_JSON = "json"
REPORT_FORMAT_PDF  = "pdf"
REPORT_FORMAT_TXT  = "txt"

# ══════════════════════════════════════════════════════════════════════
# Confidence Resolver Labels
# ══════════════════════════════════════════════════════════════════════
RESOLVER_RULE = "rule"
RESOLVER_STIX = "stix"
RESOLVER_ML   = "ml"

CONFIDENCE_HIGH   = 0.85
CONFIDENCE_MEDIUM = 0.60
CONFIDENCE_LOW    = 0.35

# ══════════════════════════════════════════════════════════════════════
# Service Fallback Attack Map
# (single source of truth — used by vuln_mapper + vuln_correlator)
# ══════════════════════════════════════════════════════════════════════
SERVICE_FALLBACK_MAP = {
    "ftp":     {"exploit": "ftp",     "type": "hydra",      "severity": "medium"},
    "ssh":     {"exploit": "ssh",     "type": "hydra",      "severity": "medium"},
    "telnet":  {"exploit": "telnet",  "type": "hydra",      "severity": "high"},
    "smtp":    {"exploit": "smtp",    "type": "hydra",      "severity": "medium"},
    "mysql":   {"exploit": "mysql",   "type": "hydra",      "severity": "medium"},
    "mssql":   {"exploit": "mssql",   "type": "hydra",      "severity": "medium"},
    "rdp":     {"exploit": "rdp",     "type": "hydra",      "severity": "high"},
    "vnc":     {"exploit": "vnc",     "type": "hydra",      "severity": "high"},
    "http":    {"exploit": "web",     "type": "web",        "severity": "low"},
    "https":   {"exploit": "web",     "type": "web",        "severity": "low"},
    # ← الناقص في vuln_mapper الأصلي
    "smb":             {"exploit": "exploit/multi/samba/usermap_script", "type": "metasploit", "severity": "critical"},
    "microsoft-ds":    {"exploit": "exploit/multi/samba/usermap_script", "type": "metasploit", "severity": "critical"},
    "netbios-ssn":     {"exploit": "exploit/multi/samba/usermap_script", "type": "metasploit", "severity": "critical"},
    "irc":             {"exploit": "exploit/unix/irc/unreal_ircd_3281_backdoor", "type": "metasploit", "severity": "critical"},
    "postgresql":      {"exploit": "postgresql", "type": "hydra", "severity": "medium"},
}

# ══════════════════════════════════════════════════════════════════════
# Known CVE → CVSS table (authoritative — used by risk_engine & cvss_engine)
# ══════════════════════════════════════════════════════════════════════
KNOWN_CVSS_SCORES = {
    "CVE-2011-2523": 10.0,  # vsftpd 2.3.4 backdoor
    "CVE-2007-2447": 9.3,   # Samba usermap_script
    "CVE-2017-0144": 9.3,   # MS17-010 EternalBlue
    "CVE-2021-44228": 10.0, # Log4Shell
    "CVE-2019-0708": 9.8,   # BlueKeep
    "CVE-2014-6271": 9.8,   # Shellshock
    "CVE-2010-2075": 9.8,   # UnrealIRCd backdoor
    "CVE-2009-2446": 8.5,   # MySQL COM_FIELD_LIST
    "CVE-2008-0166": 7.8,   # Debian OpenSSL weak key
    "CVE-2017-7679": 9.8,   # Apache mod_mime
    "BRUTE-FORCE":   5.0,
    "WEB-SCAN":      4.0,
}
