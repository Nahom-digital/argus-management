"""What each role actually sees when the page renders.

Hiding a control is a courtesy, not a boundary (the matrix test covers the
boundary). These assert the courtesy is applied correctly: staff must not be
shown admin machinery, and must be shown their own account.
"""
from pathlib import Path

import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_render_user"
PASSWORD = "R3nder!Pass"
ROOT = Path(__file__).resolve().parent.parent


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


def test_the_proxy_form_always_asks_for_a_listen_port(client):
    """Every incoming scheme asks for a port. Stream hosts always needed one;
    a web host gets the same field, with the scheme default when it is empty."""
    page = _page_as(client, "admin")
    assert 'id="px-listen-port"' in page
    assert 'id="px-listen-port-row" hidden' not in page


def test_the_proxy_form_carries_every_flag_the_renderer_knows(client):
    """The form and nginx_proxy have to agree on the field names, or a toggle
    silently does nothing. Reading the list from the module makes drift a
    failure rather than a surprise."""
    import nginx_proxy
    page = _page_as(client, "admin")
    for flag in nginx_proxy.TLS_FLAGS + nginx_proxy.BEHAVIOUR_FLAGS:
        assert f'data-px="{flag}"' in page, flag


def test_the_proxy_form_does_not_ask_for_a_certificate(client):
    """The certificate pickers are gone, but the HTTPS toggles stay."""
    page = _page_as(client, "admin")
    for el in ("px-cert-pick", "px-cert-path", "px-key-pick", "px-key-path"):
        assert f'id="{el}"' not in page, el
    for flag in ("force_ssl", "http2", "hsts", "hsts_subdomains"):
        assert f'data-px="{flag}"' in page, flag


def test_the_apps_own_assets_always_revalidate(client):
    """The app's js and css are served with no-cache. A cached copy from before
    a release silently pairs with new markup, and that pairing once made the
    Add proxy host button do nothing."""
    for fname in ("management.js", "dash.css"):
        r = client.get(f"/static/{fname}")
        assert r.status_code == 200, fname
        assert r.headers.get("cache-control") == "no-cache", fname


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


# ---------------------------------------------------------------- device card
def test_the_device_card_is_grouped_for_reading(client):
    """The section used to be one flat key/value grid. It now has an identity
    header and three panels, so the facts keep their context instead of all
    competing for attention. This pins the structure the renderer targets."""
    page = _page_as(client, "admin")
    assert 'class="device-card-head"' in page
    assert "Hardware, network and runtime at a glance." in page
    assert 'class="device-grid" id="device-grid"' in page
    assert "Live hardware" in page

    js = (ROOT / "static_mgmt" / "management.js").read_text(encoding="utf-8")
    assert "function renderDeviceInfo(d)" in js
    assert "function devIp(" in js
    assert "grid.innerHTML=renderDeviceInfo(d)" in js
    assert "data-copy" in js
    assert "dev-item" not in js
    assert "dev-val" not in js
    start = js.index("function renderDeviceInfo(d)")
    end = js.index("async function loadServerStatic", start)
    block = js[start:end]
    for text in ("Hardware", "Network", "System", "Processor", "Memory",
                 "Temperature", "Battery", "Cores", "Max clock",
                 "Private", "Public", "OS detail", "Kernel", "Process"):
        assert text in block, text
    for cls in ("dev-hero", "dev-groups", "dev-group", "dev-details"):
        assert cls in block, cls
    for helper in ("devFact(", "devIp("):
        assert helper in block, helper
    assert 'class="dev-fact' in js
    assert 'class="dev-ip' in js

    css = (ROOT / "static_mgmt" / "dash.css").read_text(encoding="utf-8")
    for cls in (".device-card-head", ".dev-hero", ".dev-groups",
                ".dev-group", ".dev-details", ".dev-fact", ".dev-ip",
                ".dev-fact.cores", ".dev-fact.clock"):
        assert cls in css, cls


def test_the_network_detail_has_live_per_socket_rates():
    """The overview card shows interface totals; the detail adds a direction for
    each established socket. These names tie the JS renderer to the backend
    fields and to the two-second sampler it relies on."""
    js = (ROOT / "static_mgmt" / "management.js").read_text(encoding="utf-8")
    start = js.index("function netRateCell(")
    end = js.index("/* A long name must not eat the extension.", start)
    block = js[start:end]
    for text in ("rate_in", "rate_out", "bytes_in", "bytes_out",
                 "Established only", "Live every 2s", "sampling…",
                 "?established=1", "setNetEstablishedOnly"):
        assert text in block, text
    assert "function renderNetDetail(silent)" in js
    assert "renderNetDetail(true)" in js
    assert "stopNetDetailPoll()" in js
    assert "setInterval(" in js
    assert "function fmtRate(" in js

    css = (ROOT / "static_mgmt" / "dash.css").read_text(encoding="utf-8")
    for cls in (".net-tools", ".net-filter", ".net-live", ".net-intro",
                ".net-warn", ".net-legend", ".net-rate"):
        assert cls in css, cls


def test_the_terminal_has_a_fullscreen_toggle():
    """Fullscreen is an explicit enter/exit control, not F11: the browser
    Fullscreen API is used where available and a fixed-position fallback keeps
    embedded webviews working. Escape exits the fallback."""
    js = (ROOT / "static_mgmt" / "management.js").read_text(encoding="utf-8")
    for text in ("termToggleFullscreen", "termSyncFullscreenButton",
                 "t-full", "ic-maximize-2", "requestFullscreen",
                 "fullscreenchange", "Exit fullscreen", "term-fs"):
        assert text in js, text
    assert "document.addEventListener('keydown'" in js

    css = (ROOT / "static_mgmt" / "dash.css").read_text(encoding="utf-8")
    for cls in (".term-wrap:fullscreen", ".term-wrap.term-fs",
                "body.term-fs-open", ".term-clear.t-full"):
        assert cls in css, cls


def test_the_network_endpoint_forwards_the_established_filter(client, monkeypatch):
    """The detail view defaults to established sockets; the query has to reach
    System.net_connections or the filter is only cosmetic."""
    import System

    seen = {}

    def fake_connections(established_only=False):
        seen["established_only"] = established_only
        return {"connections": []}

    monkeypatch.setattr(System, "net_connections", fake_connections)
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token("admin"))
    r = client.get("/api/system/connections?established=1")
    assert r.status_code == 200, r.status_code
    assert seen["established_only"] is True
