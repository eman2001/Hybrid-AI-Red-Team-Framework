from threading import Lock


_state = {
    "phase": 0,
    "title": "Waiting",
    "progress": 0,
    "status": "idle"
}


_lock = Lock()


def update(phase, title, progress):

    with _lock:
        _state["phase"] = phase
        _state["title"] = title
        _state["progress"] = progress
        _state["status"] = "running"



def finish():

    with _lock:
        _state["phase"] = 12
        _state["title"] = "Completed"
        _state["progress"] = 100
        _state["status"] = "completed"



def reset():

    with _lock:
        _state["phase"] = 0
        _state["title"] = "Starting"
        _state["progress"] = 0
        _state["status"] = "running"



def get_progress():

    return dict(_state)
