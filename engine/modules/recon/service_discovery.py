"""
recon/service_discovery.py
--------------------------
Layer 2 — Quick port / service banner grab (-sV --open -T4).
Returns a lightweight dict used by the scanner module for deeper analysis.
"""

import nmap


class ServiceDiscovery:

    QUICK_ARGS = "-sV --open -T4 --top-ports 100"

    def __init__(self, host: str):
        self.host    = host
        self.scanner = nmap.PortScanner()

    def probe(self) -> dict:
        """
        Returns
        -------
        {
          "host": str,
          "services": [{"port": int, "protocol": str, "service": str,
                         "product": str, "version": str}, ...]
        }
        """
        print(f"[Recon] Service probe → {self.host}")
        self.scanner.scan(hosts=self.host, arguments=self.QUICK_ARGS)

        services = []
        for host in self.scanner.all_hosts():
            for proto in self.scanner[host].all_protocols():
                for port, data in self.scanner[host][proto].items():
                    services.append({
                        "port":     port,
                        "protocol": proto,
                        "service":  data.get("name", ""),
                        "product":  data.get("product", ""),
                        "version":  data.get("version", ""),
                    })
                    print(f"  [+] {port}/{proto}  {data.get('name', '')}  "
                          f"{data.get('product', '')} {data.get('version', '')}")

        return {"host": self.host, "services": services}
