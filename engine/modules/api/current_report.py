"""
current_report.py
-----------------
Single source of truth for the latest completed assessment.

The pipeline writes the current session ID to:
    reports/latest_session.txt

API routes use that session's latest JSON report.
"""

import glob
import json
from pathlib import Path


REPORTS_DIR = Path("reports")
LATEST_SESSION_FILE = REPORTS_DIR / "latest_session.txt"


def set_latest_session(session_id: str) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    LATEST_SESSION_FILE.write_text(
        session_id.strip(),
        encoding="utf-8",
    )


def get_latest_session_id() -> str | None:
    if not LATEST_SESSION_FILE.is_file():
        return None

    session_id = LATEST_SESSION_FILE.read_text(
        encoding="utf-8"
    ).strip()

    return session_id or None


def get_latest_report_path(
    extension: str = "json",
) -> Path | None:
    session_id = get_latest_session_id()

    if not session_id:
        return None

    session_dir = REPORTS_DIR / session_id

    matches = glob.glob(
        str(session_dir / f"*.{extension}")
    )

    if not matches:
        return None

    latest = max(
        matches,
        key=lambda path: Path(path).stat().st_mtime,
    )

    return Path(latest)


def load_latest_report() -> dict:
    report_path = get_latest_report_path("json")

    if not report_path:
        return {}

    try:
        with report_path.open(
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        if isinstance(data, dict):
            return data

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"[API] Could not load current report: {error}"
        )

    return {}
