from engine.main import run_pipeline

from backend.storage.sessions import save_session
from backend.storage.sessions import sessions


def start_scan(target: str, lhost: str):

    result = run_pipeline(
        target,
        lhost
    )

    save_session(
        result["session_id"],
        result
    )
    
    print("SAVED SESSION:", result["session_id"])
    print("CURRENT SESSIONS:", sessions.keys())

    return {
        "session_id": result["session_id"],
        "target": result["target"],
        "timestamp": result["timestamp"],
        "status": "Completed"
    }
