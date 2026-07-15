"""
scanner/json_parser.py
----------------------
Parses saved JSON scan results (e.g. from a previous run) back into
the scan_results format used by VulnMapper.
"""

import json


class JsonParser:

    def parse_file(self, json_path: str) -> dict:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        return self._normalise(data)

    def parse_dict(self, data: dict) -> dict:
        return self._normalise(data)

    def _normalise(self, data: dict) -> dict:
        """
        Accepts either:
          - raw scan_results format  {"ip": {"os": ..., "ports": [...]}}
          - attack_report JSON       {"scan_summary": {"ip": {...}}}
        """
        if "scan_summary" in data:
            return data["scan_summary"]
        return data
