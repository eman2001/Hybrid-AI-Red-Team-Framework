import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unittest.mock import MagicMock
from engine.modules.exploiter.msf_session_manager import MsfSessionManager


def test_wait_filters_by_host():
    m = MsfSessionManager("x")
    m.client = MagicMock()
    m.client.sessions.list = {"1": {"session_host": "10.0.0.9"}}
    sid, info = m.wait_for_session("10.0.0.1", timeout=2, poll=1)
    assert sid is None


def test_chain_stops_on_first_success():
    m = MsfSessionManager("x")
    m.client = MagicMock()
    m.stop_foreign_sessions = MagicMock()
    m.wait_for_session = MagicMock(return_value=("5", {"session_host": "t"}))
    chain = [{"module": "a", "opts": {}}, {"module": "b", "opts": {}}]
    ev = m.run_exploit_chain("t", "l", chain, timeout=1)
    assert ev["session"]["id"] == "5"
    assert len(ev["attempts"]) == 1
