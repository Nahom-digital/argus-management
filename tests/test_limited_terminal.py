"""The limited terminal, and the files a limited account can browse.

Both are the same question asked twice: a staff member scoped to their own home
should see their own home, and should not be able to walk up out of it. The
terminal half is tested by building the sandbox for a directory and reading back
what the argv says, plus a live run of the shell when this machine has
bubblewrap; the disk half is tested over HTTP.
"""
import os
import pty
import select
import time

import pytest

import panel
import panel_users as pu
import System
from fastapi.testclient import TestClient

STAFF = "pytest_jail_user"
PASSWORD = "J4il!Pass"
HOME = os.path.expanduser("~")


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51042)) as c:
        yield c


@pytest.fixture(scope="module", autouse=True)
def staff(db):
    """A staff row scoped to its own home.

    The grant is written straight onto the row rather than passed to
    create_user, because creating one that way provisions an OS account with
    useradd, which needs root. The account this points at is whoever is running
    the tests, so the sandbox root is a home directory that really exists.
    """
    import getpass
    import json
    conn = db.get_connection()
    try:
        pu.delete_user(conn, STAFF)
        pu.create_user(conn, STAFF, PASSWORD, {}, "admin")
        grants = pu.normalize_grants({"disk_scope": pu.DISK_OWN})
        cur = conn.cursor()
        cur.execute("UPDATE panel_user SET grants = %s, os_username = %s "
                    "WHERE username = %s",
                    (json.dumps(grants), getpass.getuser(), STAFF))
        conn.commit()
        cur.close()
        panel._forget_user_epoch(STAFF)
        yield
        pu.delete_user(conn, STAFF)
    finally:
        db.release_connection(conn)


def as_user(client, name):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(name))


# --- the sandbox the shell runs in ------------------------------------------ #

def test_the_sandbox_binds_their_home_and_nothing_else_of_anybody_s():
    argv = System._jail_command("/home/someone", "/run/argus/jail.bashrc")
    joined = " ".join(argv)
    # Their own home is the only writable bind.
    assert "--bind /home/someone /home/someone" in joined
    # /home itself is replaced, so no other account's directory is even a name.
    assert "--tmpfs /home" in joined
    assert joined.index("--tmpfs /home") < joined.index("--bind /home/someone")
    # Nothing binds the whole filesystem, and nothing binds root's home.
    assert "--ro-bind / /" not in joined
    assert "/root" not in joined
    # What is left is read-only.
    for path in ("/usr", "/etc"):
        assert f"--ro-bind {path} {path}" in joined


def test_the_shell_profile_is_only_writable_by_root():
    """It is sourced by the jailed user's shell, so anybody who could write it
    would be running code in their session. That rules out /tmp."""
    assert System.JAIL_RC_PATH.startswith("/run/")
    assert "/tmp" not in System.JAIL_RC_PATH


def test_a_session_with_no_os_account_is_not_pretended_to_be_jailed():
    """jail only means something with an account to confine. Without one there
    is nothing to bind, and claiming otherwise would be a lie in the logs."""
    assert System.PtySession(run_as=None, jail=True).jail is False
    assert System.PtySession(run_as="somebody", jail=True).jail is True


@pytest.mark.skipif(not System.jail_available(),
                    reason="bubblewrap is not installed on this machine")
def test_a_real_jailed_shell_cannot_walk_out_of_its_home(tmp_path):
    """The end of the argument. Type at a real pty and read what comes back.

    The cd guard lives in an rcfile, which only an interactive shell reads, so
    this has to be a pty session and not a `bash -c`. The profile is written
    into the test's own directory because the real one lives under /run, which
    only root may write, and these tests do not run as root.
    """
    rc = tmp_path / "jail.bashrc"
    rc.write_text(System._JAIL_RC, encoding="utf-8")
    argv = System._jail_command(HOME, str(rc))
    pid, fd = pty.fork()
    if pid == 0:                                   # pragma: no cover, child
        env = dict(os.environ, TERM="dumb", HOME=HOME,
                   PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        try:
            os.execvpe(argv[0], argv, env)
        finally:
            os._exit(127)

    typed = ["cd ..", "pwd", "ls /home", "ls -a /root", "touch /etc/argus-escape",
             "exit"]
    chunks = []
    deadline = time.time() + 25
    last = 0.0
    while time.time() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.4)
        if readable:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data.decode("utf-8", "replace"))
        elif typed and time.time() - last > 0.3:
            os.write(fd, (typed.pop(0) + "\n").encode())
            last = time.time()
        elif not typed:
            break
    out = "".join(chunks)

    assert "is the top of your area" in out, out[-600:]
    # cd .. is refused, and the shell is still in their home afterwards.
    assert "nowhere above it to go" in out, out[-600:]
    assert f"\n{HOME}\r\n" in out or HOME in out
    # Every other home, and root's, are not in the filesystem it can see.
    assert "cannot access '/root'" in out, out[-600:]
    # And nothing outside their home can be written.
    assert "Read-only file system" in out, out[-600:]
    assert not os.path.exists("/etc/argus-escape")


# --- the disk browser ------------------------------------------------------- #

def test_a_scoped_account_asking_for_nothing_gets_its_own_directory(client):
    """The browser used to ask for "/" first, which a scoped account is not
    allowed to see, so pressing Disk showed a refusal instead of their files."""
    as_user(client, STAFF)
    d = client.get("/api/system/files").json()
    if d.get("error", "").startswith("There is no home directory"):
        pytest.skip("this staff row has no OS account on this machine")
    assert d["path"].startswith("/home/")
    assert d["parent"] is None, "the top of the sandbox must not offer a way up"
    assert "error" not in d or not d["error"]


def test_the_browser_no_longer_starts_at_the_root_of_the_filesystem():
    """Pinned in the markup, because the fix was one character of JavaScript and
    the symptom was a whole feature looking broken."""
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "static_mgmt", "management.js"), encoding="utf-8") as fh:
        js = fh.read()
    assert "_fbPath=''" in js
    assert "_fbPath='/'" not in js


def test_a_scoped_account_still_cannot_ask_for_somewhere_else(client):
    as_user(client, STAFF)
    for path in ("/", "/etc", "/root", "/home", "/etc/../etc/passwd"):
        d = client.get(f"/api/system/files?path={path}").json()
        assert d.get("error"), f"{path} was listed"
        assert not d.get("entries")
