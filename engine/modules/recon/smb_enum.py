"""
recon/smb_enum.py
------------------
Lightweight, read-only SMB anonymous-share enumeration.

Purpose: some targets expose an SMB share with NO authentication
("Anonymous"/"Guest" access). Files on such shares (memos, README,
staff lists, etc.) sometimes leak real employee/user names that are
far more likely Hydra logins than a generic wordlist guess.

This module ONLY lists shares and reads small text files anonymously
-- it never writes, deletes, or authenticates with credentials. If
`smbclient` isn't installed or the host has no anonymous access, it
returns an empty list and the caller falls back to its normal
wordlist-only behaviour.
"""

import re
import shutil
import subprocess
import tempfile
import os

_NAME_RE = re.compile(r"\b[A-Z][a-z]{2,}\b")

# Common English words that are capitalized in normal prose but are
# not plausible usernames -- filtered out so a memo full of sentences
# doesn't flood the candidate list with noise.
_STOPWORDS = {
    "The", "This", "That", "Please", "From", "Best", "Regards", "Thanks",
    "Hello", "Hi", "Dear", "Sincerely", "Team", "Staff", "Notice",
    "Announcement", "Important", "Warning", "Note", "Attention",
}

_TEXT_EXTENSIONS = (".txt", ".md", ".cfg", ".conf", ".ini", ".log")


def _run(cmd: list, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception:
        return ""


def _list_shares(host: str) -> list:
    """Returns share names visible via a NULL (anonymous) session."""
    out = _run(["smbclient", "-L", f"//{host}", "-N", "-g"], timeout=15)
    shares = []
    for line in out.splitlines():
        # -g output format: Disk|SHARENAME|comment
        parts = line.split("|")
        if len(parts) >= 2 and parts[0] == "Disk":
            shares.append(parts[1])
    return shares


def _list_files(host: str, share: str) -> list:
    """Returns filenames in a share's root, anonymous session."""
    out = _run(["smbclient", f"//{host}/{share}", "-N", "-c", "ls"], timeout=15)
    files = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("."):
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        if name.lower().endswith(_TEXT_EXTENSIONS):
            files.append(name)
    return files


def _extract_candidates(text: str) -> set:
    found = set()
    for word in _NAME_RE.findall(text):
        if word in _STOPWORDS:
            continue
        found.add(word.lower())
    return found


def enumerate_anonymous_usernames(host: str, max_files: int = 5) -> list:
    """
    Best-effort: connect anonymously, list shares, read up to
    `max_files` small text files across all shares, extract capitalized
    word candidates as possible usernames.

    Returns a deduplicated list of lowercase candidate usernames
    (possibly empty). Never raises -- any failure just yields [].
    """
    if not shutil.which("smbclient"):
        return []

    try:
        shares = _list_shares(host)
    except Exception:
        return []

    candidates = set()
    files_read = 0

    for share in shares:
        if files_read >= max_files:
            break
        try:
            files = _list_files(host, share)
        except Exception:
            continue

        for fname in files:
            if files_read >= max_files:
                break
            with tempfile.TemporaryDirectory() as tmpdir:
                local_path = os.path.join(tmpdir, "fetched.txt")
                _run(
                    ["smbclient", f"//{host}/{share}", "-N", "-c",
                     f'get "{fname}" "{local_path}"'],
                    timeout=15,
                )
                if os.path.exists(local_path):
                    try:
                        with open(local_path, "r", errors="ignore") as f:
                            text = f.read()
                        candidates |= _extract_candidates(text)
                        files_read += 1
                    except Exception:
                        pass

    return sorted(candidates)
