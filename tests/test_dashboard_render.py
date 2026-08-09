"""What each role actually sees when the page renders.

Hiding a control is a courtesy, not a boundary (the matrix test covers the
boundary). These assert the courtesy is applied correctly: staff must not be
shown admin machinery, and must be shown their own account.
"""
import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_render_user"
PASSWORD = "R3nder!Pass"


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51010)) as c:
        yield c


def _page_as(client, username):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(username))
    r = client.get("/dashboard")
    assert r.status_code == 200, r.status_code
    return r.text


def test_admin_sees_every_config_card(client):
    page = _page_as(client, "admin")
    for key in ("users", "server", "service", "database", "proxy"):
        assert f'data-cfgnav="{key}"' in page, key
    assert 'data-cfgnav="account"' not in page


def test_staff_sees_only_their_account_card_by_default(client, conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        assert 'data-cfgnav="account"' in page
        for key in ("users", "server", "database", "proxy", "service"):
            assert f'data-cfgnav="{key}"' not in page, key
        # The admin machinery must not be in the document at all, not merely
        # hidden: markup that is present can be un-hidden from the console.
        assert "Add a user" not in page
        assert "nu-grants" not in page
    finally:
        pu.delete_user(conn, STAFF)


def test_staff_config_cards_follow_their_grants(client, conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD,
                   {"db_read": True, "svc_status": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        assert 'data-cfgnav="account"' in page
        assert 'data-cfgnav="database"' in page
        assert 'data-cfgnav="service"' in page
        assert 'data-cfgnav="users"' not in page
        assert 'data-cfgnav="proxy"' not in page
    finally:
        pu.delete_user(conn, STAFF)


def test_the_nav_attribute_this_suite_asserts_on_is_real(client):
    """Guards the two tests below from passing vacuously if the markup
    changes: they look for data-nav, so data-nav has to exist."""
    page = _page_as(client, "admin")
    for key in ("server", "config", "terminal", "logs"):
        assert f'data-nav="{key}"' in page, key


def test_logs_and_terminal_tabs_are_absent_without_the_grant(client, conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"db_read": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        assert 'data-nav="logs"' not in page
        assert 'data-nav="terminal"' not in page
        assert 'data-nav="config"' in page
    finally:
        pu.delete_user(conn, STAFF)


def test_logs_tab_appears_once_the_grant_is_given(client, conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"logs_access": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        assert 'data-nav="logs"' in page
    finally:
        pu.delete_user(conn, STAFF)


def test_the_client_perms_blob_carries_every_grant(client):
    page = _page_as(client, "admin")
    for key in pu.GRANT_KEYS:
        assert f'"{key}"' in page, f"{key} missing from window.MGMT_PERMS"


def test_no_em_dash_reaches_the_rendered_page(client):
    page = _page_as(client, "admin")
    for bad in ("—", "–", "&mdash;", "&ndash;"):
        assert bad not in page, f"{bad!r} found in the rendered dashboard"
