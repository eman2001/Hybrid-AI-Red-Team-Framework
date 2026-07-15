import json

from backend.storage.sessions import get_session

from backend.llm.ollama_provider import OllamaProvider
from backend.llm.prompts import REPORT_PROMPT



def generate_report(session_id: str):

    session = get_session(session_id)


    if not session:
        return {
            "error": "Session not found"
        }


    prompt = REPORT_PROMPT.format(
        data=json.dumps(
            session,
            indent=4
        )
    )


    llm = OllamaProvider()

    report = llm.generate(prompt)


    return {
        "session_id": session_id,
        "report": report
    }
