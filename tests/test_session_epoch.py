"""Session revocation has to be surgical.

Resetting one staff member's password must evict that person and nobody else.
The panel used to carry a single global epoch, which would have signed the
admin out of their own session every time they reset a staff password.
"""
import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_epoch_user"
PASSWORD = "Ep0ch!Pass"


@pytest.fixture
def clients(conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"svc_status": True}, "admin")
    panel._forget_user_epoch(STAFF)
    with TestClient(panel.app, client=("127.0.0.1", 51001)) as admin, \
         TestClient(panel.app, client=("127.0.0.1", 51002)) as staff:
        admin.cookies.set("session", panel._create_session_token("admin"))
        staff.cookies.set("session", panel._create_session_token(STAFF))
        try:
            yield admin, staff
        finally:
            pu.delete_user(conn, STAFF)


def test_both_sessions_start_valid(clients):
    admin, staff = clients
    assert admin.get("/api/system/stats").status_code == 200
    assert staff.get("/api/services").status_code == 200


def test_resetting_staff_password_evicts_only_the_staff_session(clients, conn):
    admin, staff = clients
    r = admin.post(f"/api/config/users/{STAFF}", json={"password": "Br4nd!NewOne"})
    assert r.status_code == 200, r.text

    assert staff.get("/api/services").status_code == 401, \
        "the staff token was minted under the old epoch and must be dead"
    assert admin.get("/api/system/stats").status_code == 200, \
        "the admin reset somebody else's password and must stay signed in"


def test_narrowing_grants_evicts_the_staff_session(clients, conn):
    admin, staff = clients
    # svc_status is being taken away, so any live session must be re-evaluated.
    r = admin.post(f"/api/config/users/{STAFF}", json={"grants": {"logs_access": True}})
    assert r.status_code == 200, r.text
    assert staff.get("/api/services").status_code == 401
    assert admin.get("/api/system/stats").status_code == 200


def test_widening_grants_leaves_the_staff_session_alone(clients, conn):
    admin, staff = clients
    r = admin.post(f"/api/config/users/{STAFF}",
                   json={"grants": {"svc_status": True, "logs_access": True}})
    assert r.status_code == 200, r.text
    assert staff.get("/api/services").status_code == 200
    assert staff.get("/api/system/log-counts").status_code == 200


def test_a_forged_token_for_another_user_is_rejected(clients):
    admin, staff = clients
    with TestClient(panel.app, client=("127.0.0.1", 51003)) as forger:
        forger.cookies.set("session", panel._create_session_token(STAFF) + "x")
        assert forger.get("/api/services").status_code == 401
