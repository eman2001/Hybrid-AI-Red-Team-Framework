"""
recon/host_discovery.py
-----------------------
Layer 1 — Ping-sweep / host discovery via nmap -sn.
Supports: single IP, CIDR range, hostname/domain
"""
import socket
import subprocess
import nmap

class HostDiscovery:
    def __init__(self, target: str):
        self.target  = self._resolve(target)
        self.scanner = nmap.PortScanner()

    def _resolve(self, target: str) -> str:
        """حوّل domain لـ IP لو لزم"""
        if self._is_ip_or_cidr(target):
            return target
        try:
            ip = socket.gethostbyname(target)
            print(f"  [Recon] Resolved {target} → {ip}")
            return ip
        except Exception:
            return target

    def _is_ip_or_cidr(self, target: str) -> bool:
        import re
        return bool(re.match(r'[\d./]+$', target))

    def discover(self) -> list[str]:
        print(f"[Recon] Ping-sweep → {self.target}")
        try:
            self.scanner.scan(hosts=self.target, arguments="-sn --host-timeout 10s")
            live = [h for h in self.scanner.all_hosts()
                    if self.scanner[h].state() == "up"]
        except Exception:
            live = []

        # Fallback — ping مباشر
        if not live and '/' not in self.target:
            live = self._ping_fallback()

        for host in live:
            print(f"  [+] Live: {host}")
        if not live:
            print("  [-] No live hosts found.")
        return live

    def _ping_fallback(self) -> list[str]:
        """Fallback بـ system ping لو nmap فشل"""
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "2", self.target],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                print(f"  [Recon] Ping fallback → {self.target} is up")
                return [self.target]
        except Exception:
            pass
        return []
