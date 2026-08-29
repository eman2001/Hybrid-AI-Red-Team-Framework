"""
tests/test_session_state_builder.py
--------------------------------------
Unit tests for engine.modules.post_exploitation.session_state_builder.

Covers the two edge cases that matter for an advisory recommender feeding
off partially-populated pipeline data: a completely empty collected_data
dict (must not raise, must return safe defaults), and a fully-populated
one (must reflect the real evidence into the corresponding flags).
"""
import pytest

from engine.modules.post_exploitation.session_state_builder import build_session_state
from engine.modules.ai.session_feature_engineering import (
    CATEGORICAL_SCHEMA,
    BINARY_COLUMNS,
)

EXPECTED_KEYS = set(CATEGORICAL_SCHEMA.keys()) | set(BINARY_COLUMNS)


def test_empty_collected_data_returns_safe_defaults():
    state = build_session_state({})

    # Must not raise, and must cover exactly the schema the recommender expects.
    assert set(state.keys()) == EXPECTED_KEYS

    # Every observed-evidence field should default to "nothing happened yet",
    # not a fabricated positive signal.
    assert state["os_type"] == ""
    assert state["privilege_level"] == "low"
    assert state["credential_indicator"] == "none"
    for col in BINARY_COLUMNS:
        assert state[col] == 0


def test_full_collected_data_reflects_real_evidence():
    collected_data = {
        "os_type": "linux",
        "escalated": True,
        "sysinfo": {"os": "Linux 4.15"},
        "uid": "uid=0(root)",
        "processes": [{"pid": i} for i in range(60)],   # > 50 -> high_process_count
        "arp_hosts": ["10.0.0.1", "10.0.0.2"],           # > 1 -> multiple_network_interfaces
        "hashes": [{"user": "root", "hash": "abc123"}],
        "flags": [{"path": "/root/flag.txt"}],
    }

    state = build_session_state(collected_data)

    assert set(state.keys()) == EXPECTED_KEYS
    assert state["os_type"] == "linux"
    assert state["privilege_level"] == "high"
    assert state["credential_indicator"] == "weak_hashes"
    assert state["high_process_count"] == 1
    assert state["multiple_network_interfaces"] == 1
    assert state["sensitive_files_indicator"] == 1
    assert state["system_info_collected"] == 1
    assert state["user_info_collected"] == 1
    assert state["process_info_collected"] == 1
    assert state["network_info_collected"] == 1
    assert state["account_info_collected"] == 1


def test_categorical_values_are_always_within_the_trained_schema_or_blank():
    """Guards against a future edit accidentally emitting a value the
    recommender's one-hot encoding doesn't recognise (which would silently
    zero out that column instead of raising)."""
    state = build_session_state({"os_type": "linux", "escalated": False, "hashes": []})
    for col, allowed in CATEGORICAL_SCHEMA.items():
        value = state[col]
        assert value == "" or value in allowed, f"{col}={value!r} not in {allowed} or blank"
