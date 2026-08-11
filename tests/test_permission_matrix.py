"""The permission matrix.

For every grant, sign in as a staff account holding only that grant and call
every gated endpoint. The endpoint it unlocks must not answer 403, and every
other endpoint must. This is the only construction that catches an endpoint
somebody forgot to gate, or gated on the wrong key.
"""
import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_matrix_user"
PASSWORD = "M4trix!Pass"

# One representative request per grant. A grant with several endpoints only
# needs one here: they all share the same check, and the negative half of the
# matrix is what does the real work.
PROBES = {
    "cpumem_detail": ("GET", "/api/system/processes"),
    "net_detail":    ("GET", "/api/system/connections"),
    "disk_download": ("GET", "/api/system/download?path=/etc/hostname"),
    "disk_delete":   ("DELETE", "/api/system/delete"),
    "db_read":       ("GET", "/api/config/db/tables"),
    "db_write":      ("POST", "/api/config/db/table/system_settings/column"),
    "net_proxy":     ("GET", "/api/config/proxy/hosts"),
    "svc_status":    ("GET", "/api/services"),
    # A name _norm_service rejects, so the grant check still runs but systemctl
    # never does. With a plausible name these two probes each spent 25 seconds
    # waiting on a real "systemctl restart" of a unit that does not exist.
    "svc_restart":   ("POST", "/api/services/not%20a%20unit/restart"),
    "svc_stop":      ("POST", "/api/services/not%20a%20unit/stop"),
    "logs_access":   ("GET", "/api/system/log-counts"),
    "firewall_manage": ("GET", "/api/config/firewall"),
    "tunnel_manage":   ("GET", "/api/config/tunnel"),
    "telegram_manage": ("GET", "/api/config/telegram"),
}

# Grants with no endpoint of their own: terminal is a websocket, disk_scope is a
# modifier the disk probes carry, and db_log has no reader until phase 6.
NO_HTTP_PROBE = {"terminal", "disk_scope", "db_log"}

ADMIN_ONLY = [
    "/api/config/users",
    "/api/config/ssh/status",
    "/api/system/config",
    "/api/account/recovery-status",
]


@pytest.fixture(scope="module")
def client():
    # The Cloudflare ingress gate is left switched on, so these tests run
    # through the same front door production does. TestClient's default peer is
    # the literal string "testclient", which is not an address at all and would
    # be refused, so give it loopback, which nginx would also present.
    with TestClient(panel.app, client=("127.0.0.1", 51000)) as c:
        yield c


def test_ingress_gate_refuses_a_peer_that_is_neither_local_nor_cloudflare():
    with TestClient(panel.app, client=("203.0.113.7", 51000)) as outsider:
        outsider.cookies.set("session", panel._create_session_token("admin"))
        assert outsider.get("/api/system/stats").status_code == 403


def _sign_in_as(client, username):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(username))


def _staff_with(conn, grants):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, grants, "admin")
    panel._forget_user_epoch(STAFF)


def _call(client, method, url):
    return client.request(method, url, json={} if method in ("POST", "PUT", "DELETE") else None)


@pytest.mark.parametrize("grant", sorted(PROBES))
def test_grant_unlocks_only_its_own_endpoint(client, conn, grant):
    # disk_scope has to come along for the disk probes: the download and delete
    # grants are meaningless without something to browse.
    grants = {grant: True, "disk_scope": "full"} if grant.startswith("disk_") else {grant: True}
    _staff_with(conn, grants)
    try:
        _sign_in_as(client, STAFF)
        method, url = PROBES[grant]
        assert _call(client, method, url).status_code != 403, \
            f"{grant} should have opened {url}"
        for other, (m, u) in PROBES.items():
            if other == grant or (grant.startswith("disk_") and other.startswith("disk_")):
                continue
            assert _call(client, m, u).status_code == 403, \
                f"a staff account holding only {grant} must not reach {u}"
    finally:
        pu.delete_user(conn, STAFF)


def test_every_grant_has_a_probe_or_a_documented_exemption():
    assert set(PROBES) | NO_HTTP_PROBE == set(pu.GRANT_KEYS)


def test_admin_only_endpoints_reject_every_staff_grant(client, conn):
    everything = {k: True for k in pu.GRANT_KEYS if k not in pu.CHOICE_KEYS}
    everything["disk_scope"] = "full"
    _staff_with(conn, everything)
    try:
        _sign_in_as(client, STAFF)
        for url in ADMIN_ONLY:
            assert client.get(url).status_code == 403, f"{url} must stay admin-only"
    finally:
        pu.delete_user(conn, STAFF)


def test_a_staff_account_with_nothing_reaches_nothing(client, conn):
    _staff_with(conn, {})
    try:
        _sign_in_as(client, STAFF)
        for method, url in PROBES.values():
            assert _call(client, method, url).status_code == 403, url
        for url in ADMIN_ONLY:
            assert client.get(url).status_code == 403, url
    finally:
        pu.delete_user(conn, STAFF)


def test_admin_reaches_everything(client):
    _sign_in_as(client, "admin")
    for grant, (method, url) in PROBES.items():
        assert _call(client, method, url).status_code != 403, \
            f"the admin must never be refused {url}"
    for url in ADMIN_ONLY:
        assert client.get(url).status_code != 403, url


def test_unsupported_service_action_is_refused_before_systemctl(client, conn):
    _staff_with(conn, {"svc_stop": True, "svc_restart": True})
    try:
        _sign_in_as(client, STAFF)
        assert client.post("/api/services/ssh/mask", json={}).status_code == 400
    finally:
        pu.delete_user(conn, STAFF)


def test_grant_registry_endpoint_matches_the_registry(client):
    _sign_in_as(client, "admin")
    body = client.get("/api/config/grants").json()
    assert {g["key"] for g in body["grants"]} == set(pu.GRANT_KEYS)
    assert [g["key"] for g in body["groups"]] == list(pu.GROUP_ORDER)


def test_signed_out_requests_are_not_merely_unpermitted(client):
    client.cookies.clear()
    r = client.get("/api/system/processes")
    assert r.status_code in (401, 403)


# The matrix above uses one probe per grant, which proves the grant is wired to
# the right check. These two lists go the other way: every route in the proxy and
# firewall groups, so a new endpoint added without a check is caught even though
# its grant already has a probe.
PROXY_ROUTES = [
    ("GET", "/api/config/proxy/hosts"),
    ("GET", "/api/config/proxy/certificates"),
    ("POST", "/api/config/proxy/hosts"),
    ("PUT", "/api/config/proxy/hosts/pytest-nothing.conf"),
    ("DELETE", "/api/config/proxy/hosts/pytest-nothing.conf"),
]
FIREWALL_ROUTES = [
    ("GET", "/api/config/firewall"),
    ("POST", "/api/config/firewall/rule"),
    ("DELETE", "/api/config/firewall/rule"),
    ("POST", "/api/config/firewall/block"),
]
# The tunnel endpoints connect a Cloudflare account and publish a hostname on
# the internet, so an account without the grant must not reach any of them,
# not even the read that would tell it whether an account is connected.
TUNNEL_ROUTES = [
    ("GET", "/api/config/tunnel"),
    ("GET", "/api/config/tunnel/login"),
    ("POST", "/api/config/tunnel/login"),
    ("POST", "/api/config/tunnel/disconnect"),
    ("POST", "/api/config/tunnel/create"),
    ("POST", "/api/config/tunnel/active"),
    ("POST", "/api/config/tunnel/route"),
    ("POST", "/api/config/tunnel/service"),
    ("DELETE", "/api/config/tunnel/pytest-nothing"),
    ("DELETE", "/api/config/tunnel/route/pytest-nothing.example.com"),
]


def test_every_proxy_route_is_gated_on_net_proxy(client, conn):
    _staff_with(conn, {"firewall_manage": True})
    try:
        _sign_in_as(client, STAFF)
        for method, url in PROXY_ROUTES:
            assert _call(client, method, url).status_code == 403, \
                f"{method} {url} is reachable without net_proxy"
    finally:
        pu.delete_user(conn, STAFF)


def test_every_tunnel_route_is_gated_on_tunnel_manage(client, conn):
    _staff_with(conn, {"net_proxy": True, "firewall_manage": True})
    try:
        _sign_in_as(client, STAFF)
        for method, url in TUNNEL_ROUTES:
            assert _call(client, method, url).status_code == 403, \
                f"{method} {url} is reachable without tunnel_manage"
    finally:
        pu.delete_user(conn, STAFF)


def test_every_firewall_route_is_gated_on_firewall_manage(client, conn):
    _staff_with(conn, {"net_proxy": True})
    try:
        _sign_in_as(client, STAFF)
        for method, url in FIREWALL_ROUTES:
            assert _call(client, method, url).status_code == 403, \
                f"{method} {url} is reachable without firewall_manage"
    finally:
        pu.delete_user(conn, STAFF)


def test_the_proxy_and_firewall_routes_listed_here_actually_exist():
    """A typo in a URL above would make both tests pass for the wrong reason:
    a route that does not exist answers 404, never 403."""
    known = set()
    for route in panel.app.routes:
        for method in getattr(route, "methods", ()) or ():
            known.add((method, getattr(route, "path", "")))
    placeholders = {"pytest-nothing.conf": "{filename}",
                    "pytest-nothing": "{name}",
                    "pytest-nothing.example.com": "{hostname}"}
    for method, url in PROXY_ROUTES + FIREWALL_ROUTES + TUNNEL_ROUTES:
        path = url.split("?")[0]
        last = path.rsplit("/", 1)[-1]
        if last in placeholders:
            path = path.rsplit("/", 1)[0] + "/" + placeholders[last]
        assert (method, path) in known, f"{method} {path} is not a real route"


def test_the_service_probes_reach_the_grant_check_without_running_systemctl():
    """The two service probes use a name the validator refuses. If that stopped
    being refused they would start shelling out to systemctl, which is both slow
    and a real state change from a test run."""
    import panel
    assert panel._norm_service("not a unit") == "", \
        "the service probes rely on this name being rejected"
    ok, message = panel.control_service("not a unit", "restart")
    assert ok is False and "invalid" in message
