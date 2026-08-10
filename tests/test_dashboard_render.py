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


# ---------------------------------------------------------------- proxy form
def test_the_proxy_form_offers_every_incoming_scheme(client):
    page = _page_as(client, "admin")
    for value in ("http", "https", "tcp", "udp"):
        assert f'name="px-listen" value="{value}"' in page, value


def test_the_proxy_form_carries_every_flag_the_renderer_knows(client):
    """The form and nginx_proxy have to agree on the field names, or a toggle
    silently does nothing. Reading the list from the module makes drift a
    failure rather than a surprise."""
    import nginx_proxy
    page = _page_as(client, "admin")
    for flag in nginx_proxy.TLS_FLAGS + nginx_proxy.BEHAVIOUR_FLAGS:
        assert f'data-px="{flag}"' in page, flag


def test_the_proxy_form_has_a_certificate_picker_and_a_manual_path(client):
    page = _page_as(client, "admin")
    for el in ("px-cert-pick", "px-cert-path", "px-key-pick", "px-key-path"):
        assert f'id="{el}"' in page, el


def test_the_proxy_form_has_somewhere_to_put_custom_locations(client):
    page = _page_as(client, "admin")
    assert 'id="px-locations"' in page
    assert 'id="px-add-location"' in page


def test_firewall_settings_are_absent_without_the_grant(client, conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"net_proxy": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        assert 'data-cfgsub="proxy"' in page, "the proxy page itself should be there"
        assert 'id="px-fw-in"' not in page, \
            "firewall settings must not render without firewall_manage"
    finally:
        pu.delete_user(conn, STAFF)


def test_firewall_settings_appear_with_the_grant(client, conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD,
                   {"net_proxy": True, "firewall_manage": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        for el in ("px-fw-in", "px-fw-out", "px-fw-blocks", "px-fw-port"):
            assert f'id="{el}"' in page, el
    finally:
        pu.delete_user(conn, STAFF)


def test_the_proxy_page_is_absent_without_net_proxy(client, conn):
    """The firewall used to be a card inside the proxy page, so this grant on its
    own led to a Config with nothing in it. It has its own page now: no proxy,
    but the firewall the grant names is there."""
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"firewall_manage": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        page = _page_as(client, STAFF)
        assert 'data-cfgsub="proxy"' not in page
        assert 'id="proxy-list"' not in page
        assert 'data-cfgsub="firewall"' in page
        assert 'id="px-fw-in"' in page
    finally:
        pu.delete_user(conn, STAFF)
