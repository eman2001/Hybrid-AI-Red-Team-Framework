"""
os_support/service_profiles.py
--------------------------------
Service-level attack profiles combining OS mapper data with exploit metadata.
"""

from engine.modules.os_support.windows_mapper import WindowsMapper
from engine.modules.os_support.linux_mapper   import LinuxMapper
from engine.config.constants import OS_WINDOWS, OS_LINUX


class ServiceProfiles:

    def __init__(self):
        self._win = WindowsMapper()
        self._lin = LinuxMapper()

    def profile(self, os_type: str, service: str) -> dict:
        mapper = self._win if os_type == OS_WINDOWS else self._lin
        data   = mapper.service_map(service)
        return {
            "os":         os_type,
            "service":    service,
            "techniques": data.get("techniques", []),
            "tools":      data.get("tools", []),
        }

    def post_commands(self, os_type: str) -> list[str]:
        if os_type == OS_WINDOWS:
            return self._win.post_commands()
        return self._lin.post_commands()
