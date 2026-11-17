"""The DB editor's write routes are admin-only.

GET /api/config/db/tables reports write for the admin role only, so a staff
account must never reach a write route even when it holds db_write.
"""
import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_dbedit_user"
PASSWORD = "Db3ditor!Pass"

WRITE_ROUTES = [
    ("POST", "/api/config/db/table/admin/row",
     {"values": {"username": "pytest", "password_hash": "x"}}),
    ("PUT", "/api/config/db/table/admin/row",
     {"pk_column": "id", "pk_value": 1, "values": {"username": "pytest"}}),
    ("DELETE", "/api/config/db/table/admin/row",
     {"pk_column": "id", "pk_value": 1}),
    ("POST", "/api/config/db/table/panel_user/column",
     {"name": "pytest_col", "type": "TEXT"}),
]

HELPER_NAMES = ("_db_insert_row", "_db_update_row", "_db_delete_row", "_db_add_column")


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51058)) as c:
        yield c


def _sign_in_as(client, username):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(username))


def _staff_with(conn, grants):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, grants, "admin")
    panel._forget_user_epoch(STAFF)


@pytest.fixture
def helpers_must_not_run(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("a DB write helper ran for a staff request")

    for name in HELPER_NAMES:
        monkeypatch.setattr(panel, name, fail)


def test_staff_with_db_write_is_refused_by_every_write_route(client, conn, helpers_must_not_run):
    _staff_with(conn, {"db_read": True, "db_write": True})
    try:
        _sign_in_as(client, STAFF)
        tables = client.get("/api/config/db/tables")
        assert tables.status_code == 200
        assert tables.json()["write"] is False, "staff must not be offered write controls"
        for method, url, body in WRITE_ROUTES:
            r = client.request(method, url, json=body)
            assert r.status_code == 403, f"{method} {url}: {r.status_code} {r.text}"
            assert r.json() == {"error": "Not permitted."}
    finally:
        pu.delete_user(conn, STAFF)


def test_admin_reaches_every_write_route(client, monkeypatch):
    calls = []

    def record(*args):
        calls.append(args)
        return 1

    for name in HELPER_NAMES:
        monkeypatch.setattr(panel, name, record)
    monkeypatch.setattr(panel, "write_log", lambda *args, **kwargs: None)
    _sign_in_as(client, "admin")
    for method, url, body in WRITE_ROUTES:
        r = client.request(method, url, json=body)
        assert r.status_code == 200, f"{method} {url}: {r.status_code} {r.text}"
    assert len(calls) == len(WRITE_ROUTES)
