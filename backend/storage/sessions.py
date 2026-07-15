sessions = {}


def save_session(session_id, data):

    sessions[session_id] = data



def get_session(session_id):

    return sessions.get(session_id)



def get_latest_session():

    if not sessions:
        return None

    last_id = list(sessions.keys())[-1]

    return sessions[last_id]
