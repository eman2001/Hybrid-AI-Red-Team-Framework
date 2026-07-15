"""
modules/recon/__init__.py
-------------------------
Public interface — identical to the old recon.py so main.py needs zero changes.
"""

from engine.modules.recon.host_discovery  import HostDiscovery
from engine.modules.recon.service_discovery import ServiceDiscovery
from engine.modules.recon.os_detection    import OsDetection
from engine.modules.recon.asset_inventory import AssetInventory


class ReconModule:

    def __init__(self, target: str):
        self.target    = target
        self._discovery = HostDiscovery(target)
        self._inventory = AssetInventory()

    def discover_hosts(self) -> list[str]:
        print(f"[R0/R1] Starting Reconnaissance on: {self.target}")
        return self._discovery.discover()

    def full_recon(self, live_hosts: list[str]) -> dict:
        """
        Extended recon: service probe + OS detection for every live host.
        Returns asset inventory summary.
        """
        for host in live_hosts:
            sd = ServiceDiscovery(host)
            probe = sd.probe()
            od = OsDetection(host)
            os_name = od.detect()
            self._inventory.add(host, os_name, probe["services"])

        return self._inventory.summary()

    @property
    def inventory(self) -> AssetInventory:
        return self._inventory


__all__ = ["ReconModule", "HostDiscovery", "ServiceDiscovery", "OsDetection", "AssetInventory"]
