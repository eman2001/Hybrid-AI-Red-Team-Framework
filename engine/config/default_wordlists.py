"""
Default credentials for Metasploitable / lab environments.
Used as fallback when system wordlists are not installed.
"""
import tempfile, os

# Metasploitable default + common credentials
DEFAULT_USERS = [
    "msfadmin", "root", "admin", "user", "postgres",
    "service", "tomcat", "www-data", "ftp", "anonymous",
]

DEFAULT_PASSWORDS = [
    "msfadmin", "root", "admin", "password", "123456",
    "toor", "service", "postgres", "tomcat", "admin123",
    "", "guest", "test", "pass", "1234",
]

def create_temp_wordlist(words: list) -> str:
    """Write list to temp file and return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                    delete=False, prefix="wl_")
    f.write("\n".join(words))
    f.close()
    return f.name

def get_user_list() -> str:
    """Return path to user wordlist (system or temp)."""
    system = [
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    ]
    for p in system:
        if os.path.isfile(p):
            return p
    return create_temp_wordlist(DEFAULT_USERS)

def get_pass_list() -> str:
    """Return path to password wordlist (system or temp)."""
    system = [
        "/usr/share/wordlists/metasploit/unix_passwords.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/best110.txt",
        "/usr/share/wordlists/rockyou.txt",
    ]
    for p in system:
        if os.path.isfile(p):
            return p
    return create_temp_wordlist(DEFAULT_PASSWORDS)
