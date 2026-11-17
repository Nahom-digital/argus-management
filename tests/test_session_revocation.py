"""Deleting a staff account must revoke that person's sessions immediately.

A token is only a signature over the name and the epochs it was minted under,
so removing the row used to leave the token looking current: a missing row read
as epoch 0, exactly what a fresh account was minted with. The tombstone left by
delete_user closes that gap without disturbing anybody else.
"""
import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_revoke_user"
PASSWORD = "Rev0ke!Pass"
NEW_PASSWORD = "Rev0ke!Again"


def _clean(conn, name):
    pu.delete_user(conn, name)
    cur = conn.cursor()
    cur.execute("DELETE FROM panel_user_revoked WHERE username = %s", (name,))
    conn.commit()
    cur.close()
    panel._forget_user_epoch(name)


@pytest.fixture
def staff(conn):
    _clean(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"svc_status": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        yield conn
    finally:
        _clean(conn, STAFF)


def test_deleting_a_user_revokes_their_token_and_leaves_the_admin_alone(staff):
    with TestClient(panel.app, client=("127.0.0.1", 51101)) as admin, \
         TestClient(panel.app, client=("127.0.0.1", 51102)) as user:
        admin.cookies.set("session", panel._create_session_token("admin"))
        user.cookies.set("session", panel._create_session_token(STAFF))

        assert user.get("/api/services").status_code == 200
        r = admin.delete(f"/api/config/users/{STAFF}")
        assert r.status_code == 200, r.text

        assert user.get("/api/services").status_code == 401, \
            "the deleted account's token must stop working immediately"
        # The background epoch refresh must not drop the tombstone and make the
        # deleted name look like epoch 0 again.
        panel._refresh_epoch_cache()
        assert user.get("/api/services").status_code == 401, \
            "the deleted account's token must stay revoked after a refresh"
        assert admin.get("/api/system/stats").status_code == 200, \
            "deleting a staff member must not sign the admin out"


def test_recreating_the_name_clears_the_tombstone_and_lets_a_new_login_in(staff):
    with TestClient(panel.app, client=("127.0.0.1", 51103)) as admin, \
         TestClient(panel.app, client=("127.0.0.1", 51104)) as old:
        admin.cookies.set("session", panel._create_session_token("admin"))
        old.cookies.set("session", panel._create_session_token(STAFF))

        assert admin.delete(f"/api/config/users/{STAFF}").status_code == 200
        assert old.get("/api/services").status_code == 401

        r = admin.post("/api/config/users", json={
            "username": STAFF, "password": NEW_PASSWORD,
            "grants": {"svc_status": True}})
        assert r.status_code == 200, r.text

        with TestClient(panel.app, client=("127.0.0.1", 51105)) as fresh:
            login = fresh.post("/api/login", json={
                "username": STAFF, "password": NEW_PASSWORD})
            assert login.status_code == 200, login.text
            assert fresh.get("/api/services").status_code == 200

        assert old.get("/api/services").status_code == 401, \
            "the old token must not come back with the recreated name"

        cur = staff.cursor()
        cur.execute("SELECT 1 FROM panel_user_revoked WHERE username = %s", (STAFF,))
        assert cur.fetchone() is None, "creation must clear the tombstone"
        cur.close()
