"""Version of the running Argus Management panel.

APP_VERSION is the release number a person reads. The checkout's git revision
is appended when it can be read, because two panels can share a release number
while running different code. Linked panels compare the complete string, so a
server that was not updated is called out even inside one release.
"""
import os
import subprocess

APP_VERSION = "1.1.0"
_HERE = os.path.dirname(os.path.abspath(__file__))
_cache = None


def _git_revision():
    try:
        proc = subprocess.run(
            ["git", "-C", _HERE, "rev-parse", "--short=12", "HEAD"],
            capture_output=True, text=True, timeout=3)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def version():
    global _cache
    if _cache is None:
        rev = _git_revision()
        _cache = f"{APP_VERSION}+{rev}" if rev else APP_VERSION
    return _cache
