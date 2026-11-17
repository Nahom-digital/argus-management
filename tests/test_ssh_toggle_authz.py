"""Changing SSH state is an admin action, not just a signed-in one."""
import types

import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_ssh_staff"
PASSWORD = "Ssh!Staff1"


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51040)) as c:
        yield c


def _sign_in_as(client, username):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(username))


def _staff_with(conn, grants):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, grants, "admin")
    panel._forget_user_epoch(STAFF)


def test_a_read_only_staff_session_cannot_toggle_ssh(client, conn, monkeypatch):
    _staff_with(conn, {})

    def forbidden(*args, **kwargs):
        raise AssertionError("systemctl must not run for a non-admin session")

    monkeypatch.setattr(panel.subprocess, "run", forbidden)
    try:
        _sign_in_as(client, STAFF)
        r = client.post("/api/system/ssh-toggle", json={"enable": False})
        assert r.status_code == 403
        assert r.json() == {"error": "Not permitted."}
    finally:
        pu.delete_user(conn, STAFF)
        panel._forget_user_epoch(STAFF)


def test_an_admin_session_passes_the_guard(client, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="active\n", stderr="")

    monkeypatch.setattr(panel.subprocess, "run", fake_run)
    _sign_in_as(client, "admin")
    r = client.post("/api/system/ssh-toggle", json={"enable": True})
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ok", "active": True, "enable": True}
    assert ["systemctl", "enable", "ssh"] in calls
    assert ["systemctl", "start", "ssh"] in calls
    assert ["systemctl", "is-active", "ssh"] in calls
