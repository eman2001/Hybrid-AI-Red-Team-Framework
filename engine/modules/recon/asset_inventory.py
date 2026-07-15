"""
recon/asset_inventory.py
------------------------
Builds a structured asset inventory from discovery + service probe results.
"""

from datetime import datetime


class AssetInventory:

    def __init__(self):
        self.assets: list[dict] = []

    def add(self, host: str, os: str, services: list[dict]) -> dict:
        asset = {
            "host":       host,
            "os":         os,
            "services":   services,
            "port_count": len(services),
            "scanned_at": datetime.now().isoformat(),
        }
        self.assets.append(asset)
        return asset

    def summary(self) -> dict:
        return {
            "total_hosts":    len(self.assets),
            "total_services": sum(a["port_count"] for a in self.assets),
            "assets":         self.assets,
        }

    def to_scan_results(self) -> dict:
        """Convert inventory to the scan_results format expected by VulnMapper."""
        results = {}
        for asset in self.assets:
            results[asset["host"]] = {
                "os":    asset["os"],
                "ports": asset["services"],
            }
        return results
