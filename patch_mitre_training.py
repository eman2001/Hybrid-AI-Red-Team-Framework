"""
patch_mitre_training.py
------------------------
يوسّع HANDCRAFTED_DATA بـ train_mitre_model.py بمئات الأمثلة القصيرة
المتنوعة (بنفس شكل ml_classifier._context_text: exploit+service+cve+
post_commands)، ويغيّر min_df من 2 لـ 1 عشان الكلمات القصيرة النادرة
ما تنشال من التمثيل الرقمي.
"""

import re

path = "train_mitre_model.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

# نسخة احتياطية
with open(path + ".bak", "w", encoding="utf-8") as f:
    f.write(content)
print("✅ نسخة احتياطية: train_mitre_model.py.bak")

# ── 1) البيانات الموسّعة (متنوعة ومكرّرة عشان تعدّي min_df) ──────────
NEW_HANDCRAFTED = '''HANDCRAFTED_DATA = [
    # initial-access
    ("vsftpd backdoor remote code execution ftp 21",           "initial-access"),
    ("drupalgeddon web http 80 exploit",                        "initial-access"),
    ("struts ognl injection http 8080 java",                    "initial-access"),
    ("unreal ircd backdoor irc 6667",                           "initial-access"),
    ("distcc exec remote code linux 3632",                      "initial-access"),
    ("web application exploit public facing http",              "initial-access"),
    ("php cgi argument injection web 80",                       "initial-access"),
    ("wordpress admin shell upload http",                       "initial-access"),
    ("phishing spearphishing email smtp link",                  "initial-access"),
    ("apache tomcat manager deploy war http",                   "initial-access"),
    ("exploit public facing application vulnerable service",    "initial-access"),
    ("remote exploit initial foothold service port",            "initial-access"),
    ("valid accounts external remote services http",            "initial-access"),
    ("spearphishing attachment malicious document email",       "initial-access"),
    ("supply chain compromise software update",                 "initial-access"),

    # lateral-movement
    ("samba usermap script smb 445 command injection",         "lateral-movement"),
    ("eternalblue ms17 smb 445 windows",                        "lateral-movement"),
    ("bluekeep rdp 3389 windows remote",                        "lateral-movement"),
    ("java rmi server lateral 1099",                            "lateral-movement"),
    ("ms08 netapi smb 445 windows buffer overflow",             "lateral-movement"),
    ("lateral movement psexec smb windows",                     "lateral-movement"),
    ("remote services ssh linux lateral",                       "lateral-movement"),
    ("pass the hash smb lateral windows",                       "lateral-movement"),
    ("wmi exec remote lateral movement windows",                "lateral-movement"),
    ("pivot internal network smb rdp lateral",                  "lateral-movement"),
    ("remote desktop protocol lateral movement session",        "lateral-movement"),
    ("winrm remote lateral execution windows",                  "lateral-movement"),

    # credential-access
    ("ssh brute force credential 22",                           "credential-access"),
    ("ftp brute force credential 21",                           "credential-access"),
    ("telnet brute force valid accounts 23",                    "credential-access"),
    ("rdp brute force credential 3389",                         "credential-access"),
    ("mysql brute force credential 3306",                       "credential-access"),
    ("hashdump credential dump ntlm windows",                   "credential-access"),
    ("ssh private key credential dump linux",                   "credential-access"),
    ("hydra brute force password login",                        "credential-access"),
    ("hydra service brute credential attempt",                  "credential-access"),
    ("password spray brute force credential access",            "credential-access"),
    ("dump lsass credential windows memory",                    "credential-access"),
    ("mimikatz credential dump windows hash",                   "credential-access"),
    ("cracked hash password credential offline",                "credential-access"),
    ("hydra ssh brute password guessing",                       "credential-access"),
    ("hydra ftp brute password guessing",                       "credential-access"),
    ("hydra http brute password guessing",                      "credential-access"),
    ("credential harvest brute password service",               "credential-access"),

    # privilege-escalation
    ("getsystem privilege escalation windows",                  "privilege-escalation"),
    ("sudo nopasswd privilege escalation linux",                "privilege-escalation"),
    ("local exploit suggester privilege linux windows",         "privilege-escalation"),
    ("getsystem meterpreter privilege escalation session",      "privilege-escalation"),
    ("sudo privilege escalation linux exploit",                 "privilege-escalation"),
    ("privesc kernel exploit local linux",                      "privilege-escalation"),
    ("suid binary privilege escalation linux",                  "privilege-escalation"),
    ("uac bypass privilege escalation windows",                 "privilege-escalation"),
    ("token impersonation privilege escalation windows",        "privilege-escalation"),
    ("scheduled task privilege escalation windows exploit",     "privilege-escalation"),
    ("privesc getsystem sudo escalate local exploit",           "privilege-escalation"),

    # discovery
    ("sysinfo discovery system information",                    "discovery"),
    ("getuid user discovery system owner",                      "discovery"),
    ("arp route network discovery enum",                        "discovery"),
    ("ping sweep remote system discovery network",              "discovery"),
    ("process list discovery ps windows linux",                 "discovery"),
    ("sysinfo getuid discovery system info owner",              "discovery"),
    ("netstat network connection discovery",                    "discovery"),
    ("netstat arp discovery network connections",               "discovery"),
    ("whoami user discovery windows linux",                     "discovery"),
    ("ps process discovery running list",                       "discovery"),
    ("ipconfig ifconfig network discovery interface",           "discovery"),
    ("net view domain discovery windows",                       "discovery"),
    ("sysinfo getuid arp netstat discovery enumeration",        "discovery"),
    ("account discovery user enumeration list",                 "discovery"),
    ("service discovery enum running services",                 "discovery"),
    ("file directory discovery browse system",                  "discovery"),
    ("network service scanning discovery enum",                 "discovery"),

    # execution
    ("meterpreter command shell execution interpreter",         "execution"),
    ("bash shell command scripting interpreter linux",          "execution"),
    ("powershell command scripting windows execution",          "execution"),
    ("jenkins script console http 8080",                        "execution"),
    ("cmd exec shell command windows execution",                "execution"),
    ("shell command interpreter execution linux windows",       "execution"),
    ("remote code execution payload run",                       "execution"),
    ("script interpreter execution powershell bash",            "execution"),

    # persistence
    ("scheduled task persistence cron windows",                 "persistence"),
    ("registry run key persistence windows",                    "persistence"),
    ("cron job persistence linux scheduled",                    "persistence"),
    ("startup folder persistence windows autorun",              "persistence"),
    ("backdoor account persistence create user",                "persistence"),
    ("service persistence windows autorun install",             "persistence"),
    ("ssh key persistence authorized keys linux",                "persistence"),

    # collection
    ("collection files directory discovery",                    "collection"),
    ("screen capture collection data windows",                  "collection"),
    ("clipboard data collection windows",                       "collection"),
    ("keylogger input capture collection",                      "collection"),
    ("archive collected data staged",                            "collection"),

    # impact
    ("impact ransomware encryption data",                       "impact"),
    ("data destruction wipe impact disk",                       "impact"),
    ("denial of service impact availability",                   "impact"),
    ("defacement impact website content",                       "impact"),

    # exfiltration
    ("exfiltration ftp c2 channel data",                        "exfiltration"),
    ("data exfiltration upload transfer c2",                    "exfiltration"),
    ("exfil download all files transfer",                       "exfiltration"),
    ("dns tunneling exfiltration covert channel",               "exfiltration"),
]'''

pattern = re.compile(r"HANDCRAFTED_DATA = \[.*?\n\]", re.DOTALL)
if not pattern.search(content):
    print("❌ ما لقيت HANDCRAFTED_DATA بالشكل المتوقع — لازم تعديل يدوي.")
else:
    content = pattern.sub(NEW_HANDCRAFTED, content, count=1)
    print("✅ تم توسيع HANDCRAFTED_DATA")

# ── 2) تعديل min_df=2 -> min_df=1 ────────────────────────────────────
if "min_df=2" in content:
    content = content.replace("min_df=2", "min_df=1")
    print("✅ تم تعديل min_df=2 -> min_df=1")
else:
    print("⚠️ ما لقيت min_df=2 بالضبط — تحققي يدويًا.")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("\n✅ خلص التعديل. شغّلي الآن: python3 train_mitre_model.py")
