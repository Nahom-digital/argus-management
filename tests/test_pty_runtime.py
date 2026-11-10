"""Runtime behaviour of the PTY sessions.

Three things are covered here: what a limited shell inherits from the panel
process, that browser input never blocks the caller when the shell has stopped
reading, and that closing a session really reaps its child. The child in the
last two tests is `sleep`, which holds the pty but never reads it.
"""
import os
import time

import System


class _SleepingSession(System.PtySession):
    """A session whose child never reads the pty, like a wedged raw-mode app."""

    SHELL = ["sleep", "60"]


def _wait_gone(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not os.path.exists(f"/proc/{pid}"):
            return True
        time.sleep(0.02)
    return False


def test_a_limited_shell_gets_none_of_the_panel_secrets(monkeypatch):
    """.env is loaded into the panel's os.environ, so a staff shell that
    inherited it could just run `env` and read the database password."""
    monkeypatch.setenv("DB_PASSWORD", "hunter2")
    monkeypatch.setenv("DB_USER", "elink")
    monkeypatch.setenv("MGMT_SECRET", "panel-secret")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setenv("PATH", "/root/private/bin:/usr/bin:/bin")

    env = System.PtySession(run_as="staff").child_env(home="/home/staff")

    for name in ("DB_PASSWORD", "DB_USER", "MGMT_SECRET", "SSH_AUTH_SOCK",
                 "AWS_SECRET_ACCESS_KEY"):
        assert name not in env, f"{name} leaked into the limited shell"
    assert env["HOME"] == "/home/staff"
    assert env["USER"] == "staff"
    assert env["LOGNAME"] == "staff"
    assert env["SHELL"] == "/bin/bash"
    assert env["TERM"] == "xterm-256color"
    assert env["LANG"] == "en_US.UTF-8"
    assert env["TZ"] == "UTC"
    assert System._PROJECT_DIR not in env["PATH"]
    assert "/root/private/bin" not in env["PATH"]


def test_explicit_session_overrides_still_apply_to_a_limited_shell():
    sess = System.PtySession(run_as="staff", env={"ARGUS_TEST_FLAG": "1"})
    env = sess.child_env(home="/home/staff", base={"PATH": "/usr/bin:/bin"})
    assert env["ARGUS_TEST_FLAG"] == "1"
    assert env["HOME"] == "/home/staff"


def test_an_admin_shell_keeps_the_environment_it_had(monkeypatch):
    """Only run_as sessions were narrowed; the admin terminal is unchanged."""
    monkeypatch.setenv("DB_PASSWORD", "hunter2")
    env = System.PtySession(run_as=None).child_env()
    assert env["DB_PASSWORD"] == "hunter2"
    assert env["PATH"].startswith(System._PROJECT_DIR + os.pathsep)


def test_set_winsize_reports_success_and_failure():
    """The resize path needs to know whether the pty accepted the size, so a
    missing or invalid fd is False instead of a silent success."""
    sess = System.PtySession()
    assert sess.set_winsize(24, 80) is False
    sess.fd = -1
    assert sess.set_winsize(24, 80) is False
    sess.fd = None

    live = _SleepingSession()
    try:
        live.spawn(rows=24, cols=80)
        assert live.set_winsize(40, 120) is True
    finally:
        live.close()


def test_a_write_to_a_shell_that_is_not_reading_returns_immediately():
    sess = _SleepingSession()
    try:
        sess.spawn(rows=24, cols=80)
        assert sess.fd is not None
        start = time.monotonic()
        sess.write(b"x" * (1024 * 1024))
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"write blocked for {elapsed:.2f}s"
    finally:
        sess.close()


def test_closing_a_session_reaps_its_shell():
    sess = _SleepingSession()
    sess.spawn(rows=24, cols=80)
    pid = sess.pid
    assert pid and os.path.exists(f"/proc/{pid}")

    start = time.monotonic()
    sess.close()
    assert time.monotonic() - start < 2.0

    assert _wait_gone(pid), f"pid {pid} was not reaped within 5s"
    # A reaped child gives ChildProcessError; a zombie would still be waitable.
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        wpid = pid
    assert wpid == pid
