"""
ai/session_feature_engineering.py
-----------------------------------
Builds the 38-feature one-hot + binary vector for the session
action recommender, from a raw session-state dict.
"""

CATEGORICAL_SCHEMA = {
    "os_type":            ["linux", "macos", "windows"],
    "architecture":        ["arm64", "x64", "x86"],
    "privilege_level":     ["high", "low", "medium", "system"],
    "session_type":        ["interactive", "remote", "service"],
    "credential_indicator": ["cached_creds", "none", "plaintext_found", "weak_hashes"],
}

BINARY_COLUMNS = [
    "domain_joined", "multiple_users_logged_in", "high_process_count",
    "suspicious_process_present", "multiple_network_interfaces",
    "active_external_connections", "security_software_present",
    "remote_management_enabled", "unusual_services_present",
    "scheduled_tasks_present", "unusual_scheduled_tasks",
    "sensitive_files_indicator", "system_info_collected",
    "user_info_collected", "process_info_collected",
    "service_info_collected", "network_info_collected",
    "config_info_collected", "security_controls_reviewed",
    "account_info_collected", "risk_assessment_done",
]


class SessionFeatureEngineering:

    def feature_names(self) -> list[str]:
        names = []
        for col, values in CATEGORICAL_SCHEMA.items():
            for v in sorted(values):
                names.append(f"{col}_{v}")
        names.extend(BINARY_COLUMNS)
        return names

    def transform_one(self, row: dict) -> list[float]:
        vec = []
        for col, values in CATEGORICAL_SCHEMA.items():
            row_val = str(row.get(col, "")).strip().lower()
            for v in sorted(values):
                vec.append(1.0 if row_val == v else 0.0)
        for col in BINARY_COLUMNS:
            try:
                vec.append(float(row.get(col, 0)))
            except (TypeError, ValueError):
                vec.append(0.0)
        return vec

    def transform_many(self, rows: list[dict]) -> list[list[float]]:
        return [self.transform_one(r) for r in rows]
