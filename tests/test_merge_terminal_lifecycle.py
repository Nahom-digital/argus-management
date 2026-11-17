"""Lifecycle edges of the linked-server terminal proxy.

An outgoing linked terminal is a browser socket plus an outbound socket to the
peer. An incoming one is a root PTY owned by another panel. These tests pin the
places where an approval, a delete, a key change, or a browser leaving must not
leave either side running.
"""
import asyncio
import json
import threading
import time
import uuid
from urllib.parse import parse_qs, quote, urlparse

import pytest
import websockets
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import panel
import panel_users as pu

SERVER = {
    "id": "srv1",
    "approved": True,
    "host": "127.0.0.1",
    "port": 9,
    "scheme": "http",
    "base_path": "",
    "server_uid": "issuerK",
}


class _FakeBrowser:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


class _FakeRemote:
    def __init__(self, messages=()):
        self.sent = []
        self.closed = False
        self.messages = list(messages)

    async def send(self, data):
        self.sent.append(data)

    async def close(self):
        self.closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.messages:
            return self.messages.pop(0)
        raise StopAsyncIteration


class _FakeTerm:
    instances = []

    def __init__(self, sid, persist, rows, cols, owner="", run_as=None, jail=False):
        self.sid = sid
        self.persist = bool(persist)
        self.owner = owner
        self.run_as = run_as
        self.jail = bool(jail)
        self.rows, self.cols = rows, cols
        self.buffer = bytearray()
        self.subscribers = set()
        self.dead = False
        self.closed = False
        self.created = 0
        self.writes = []
        _FakeTerm.instances.append(self)

    def resize(self, rows, cols):
        self.rows, self.cols = rows, cols

    def write(self, data):
        self.writes.append(data)

    def close(self):
        self.closed = True
        self.dead = True
        for q in list(self.subscribers):
            try:
                q.put_nowait(None)
            except Exception:
                pass
        self.subscribers.clear()


@pytest.fixture(scope="module")
def client(db):
    with TestClient(panel.app, client=("127.0.0.1", 51061)) as c:
        yield c
    panel._TERMS.clear()
    panel._MERGE_LIVE.clear()


@pytest.fixture(autouse=True)
def clean_merge_state():
    panel._TERMS.clear()
    panel._MERGE_LIVE.clear()
    panel._MERGE_REVOKE_GEN.clear()
    _FakeTerm.instances = []
    yield
    panel._TERMS.clear()
    panel._MERGE_LIVE.clear()
    panel._MERGE_REVOKE_GEN.clear()


def _as(client, name="alice"):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(name))


def _admin_perms():
    return {"role": "admin", "username": "ignored", "os_username": None,
            "terminal": pu.TERMINAL_ROOT}


def _next_frame(ws, timeout=5.0):
    box = {}

    def run():
        try:
            box["message"] = ws.receive()
        except BaseException as e:  # noqa: BLE001 - re-raised on the test thread
            box["error"] = e

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pytest.fail("the websocket was not closed", pytrace=False)
    if "error" in box:
        raise box["error"]
    return box["message"]


def _wait_closed(term, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not term.closed and time.monotonic() < deadline:
        time.sleep(0.01)
    assert term.closed


def _wait_write(term, text, timeout=5.0):
    deadline = time.monotonic() + timeout
    while text not in term.writes and time.monotonic() < deadline:
        time.sleep(0.005)
    assert text in term.writes


def _inbound_identity(monkeypatch, issuer):
    async def identity():
        return {"key": "local-key", "server_uid": "local"}

    claims = {"purpose": "api", "iss": issuer, "sub": "alice",
              "role": "admin", "scopes": ["terminal"]}
    monkeypatch.setattr(panel, "_merge_local_identity", identity)
    monkeypatch.setattr(panel.merge_servers, "verify_token",
                        lambda token, key: dict(claims))
    # The newer verifier returns (claims, error); keep this test valid on both.
    monkeypatch.setattr(panel.merge_servers, "verify_incoming",
                        lambda *args, **kwargs: (dict(claims), None),
                        raising=False)
    monkeypatch.setattr(panel.merge_servers, "request_status",
                        lambda uid: "allowed")


def test_sid_separators_are_refused_and_the_dial_url_is_encoded(
        client, monkeypatch):
    _as(client)
    monkeypatch.setattr(panel, "_resolve_permissions", lambda name: _admin_perms())
    monkeypatch.setattr(panel.merge_servers, "make_server_token",
                        lambda *args, **kwargs: "test-token")

    async def fake_db_run(fn, *args, **kwargs):
        if fn is panel.merge_servers.get_server:
            return dict(SERVER)
        if fn is panel._resolve_permissions:
            return fn(*args, **kwargs)
        raise AssertionError(f"unexpected DB call: {fn}")

    monkeypatch.setattr(panel.DB, "run", fake_db_run)
    dials = []

    async def fake_connect(url, **kwargs):
        live = [(p.server_id, p.owner)
                for proxies in panel._MERGE_LIVE.values() for p in proxies]
        dials.append((url, kwargs, live))
        return _FakeRemote()

    monkeypatch.setattr(websockets, "connect", fake_connect)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
                "/ws/merge-terminal?server=srv1&sid=" +
                quote("bad&token=stolen")):
            pass
    assert exc.value.code == 1008
    assert dials == []

    with client.websocket_connect(
            "/ws/merge-terminal?server=srv1&sid=abc&persist=1") as ws:
        assert _next_frame(ws)["type"] == "websocket.close"

    assert len(dials) == 1
    url, kwargs, live = dials[0]
    query = parse_qs(urlparse(url).query)
    assert query["sid"] == ["mt_abc"]
    assert query["persist"] == ["0"]
    assert "token" not in query
    assert kwargs["max_size"] == panel._MERGE_WS_MAX
    assert live == [("srv1", "alice")], "the proxy must exist before dialing"
    assert panel._MERGE_LIVE == {}


def test_a_server_removed_after_accept_self_closes_before_the_dial(
        client, monkeypatch):
    _as(client)
    monkeypatch.setattr(panel, "_resolve_permissions", lambda name: _admin_perms())
    monkeypatch.setattr(panel.merge_servers, "make_server_token",
                        lambda *args, **kwargs: "test-token")
    reads = []
    dials = []

    async def fake_db_run(fn, *args, **kwargs):
        if fn is panel.merge_servers.get_server:
            reads.append(args)
            return dict(SERVER) if len(reads) == 1 else None
        if fn is panel._resolve_permissions:
            return fn(*args, **kwargs)
        raise AssertionError(f"unexpected DB call: {fn}")

    async def fake_connect(url, **kwargs):
        dials.append(url)
        return _FakeRemote()

    monkeypatch.setattr(panel.DB, "run", fake_db_run)
    monkeypatch.setattr(websockets, "connect", fake_connect)

    with client.websocket_connect("/ws/merge-terminal?server=srv1&sid=gone") as ws:
        assert "removed" in ws.receive_text()
        assert _next_frame(ws)["code"] == 1008

    assert dials == []
    assert panel._MERGE_LIVE == {}


def test_deleting_an_account_closes_only_that_accounts_linked_proxies(
        client, monkeypatch):
    _as(client, "admin")
    monkeypatch.setattr(panel, "_resolve_permissions", lambda name: _admin_perms())

    async def fake_db_run(fn, *args, **kwargs):
        if fn is panel._delete_panel_user:
            return True
        if fn is panel.merge_servers.delete_user_access:
            return None
        if fn is panel._forget_user_epoch:
            return None
        if fn is panel._resolve_permissions:
            return _admin_perms()
        raise AssertionError(f"unexpected DB call: {fn}")

    monkeypatch.setattr(panel.DB, "run", fake_db_run)

    alice_browser = _FakeBrowser()
    alice = panel._merge_proxy_open("srv1", alice_browser, "sid1", owner="alice")
    alice.remote = _FakeRemote()
    bob_browser = _FakeBrowser()
    bob = panel._merge_proxy_open("srv2", bob_browser, "sid2", owner="bob")
    bob.remote = _FakeRemote()

    r = client.delete("/api/config/users/alice")
    assert r.status_code == 200, r.text

    assert alice.remote.closed and alice_browser.closed
    assert json.loads(alice.remote.sent[0]) == {"kill": True, "force": True}
    assert not bob.remote.closed and not bob_browser.closed


def test_a_linked_terminal_ignores_persist_and_ends_with_its_browser(
        client, monkeypatch):
    _inbound_identity(monkeypatch, "issuerP")
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)

    with client.websocket_connect("/ws/merge/terminal?sid=keep&persist=1") as ws:
        hello = json.loads(ws.receive_text())
        assert hello == {"sid": "mr_keep", "persist": False}
        term = panel._TERMS["mr_keep"]
        assert term.persist is False
        ws.send_text(json.dumps({"persist": True}))
        ws.send_text("PING")
        _wait_write(term, "PING")
        assert term.persist is False

    _wait_closed(term)
    assert "mr_keep" not in panel._TERMS


class _BumpingTerm(_FakeTerm):
    def __init__(self, sid, persist, rows, cols, owner="", run_as=None, jail=False):
        super().__init__(sid, persist, rows, cols, owner, run_as, jail)
        panel._merge_revoke_bump("issuerR")


def test_a_revocation_during_accept_closes_the_new_pty(client, monkeypatch):
    _inbound_identity(monkeypatch, "issuerR")
    monkeypatch.setattr(panel, "_ManagedTerm", _BumpingTerm)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/merge/terminal?sid=race") as ws:
            ws.receive_text()
    assert exc.value.code == 1008
    assert _BumpingTerm.instances[0].closed
    assert "mr_race" not in panel._TERMS


def test_denying_a_request_bumps_the_issuer_generation(client, monkeypatch):
    _as(client, "admin")

    async def fake_db_run(fn, *args, **kwargs):
        if fn is panel.merge_servers.decide_request:
            return True
        if fn is panel._resolve_permissions:
            return _admin_perms()
        raise AssertionError(f"unexpected DB call: {fn}")

    monkeypatch.setattr(panel.DB, "run", fake_db_run)
    term = _FakeTerm("mr_bound", False, 24, 80,
                     owner="merge:issuerD:alice")
    panel._TERMS["mr_bound"] = term
    before = panel._merge_revoke_gen("issuerD")

    r = client.post("/api/config/servers/requests/issuerD",
                    json={"action": "deny"})
    assert r.status_code == 200, r.text
    assert panel._merge_revoke_gen("issuerD") == before + 1
    assert term.closed and "mr_bound" not in panel._TERMS


def test_replacing_a_linked_key_bumps_and_ends_live_proxies(
        client, monkeypatch):
    _as(client, "admin")

    async def fake_db_run(fn, *args, **kwargs):
        if fn is panel.merge_servers.get_server:
            return dict(SERVER)
        if fn is panel.merge_servers.replace_server_key:
            return True
        if fn is panel.merge_servers.handshake:
            return {"status": "pending"}
        if fn is panel._resolve_permissions:
            return _admin_perms()
        raise AssertionError(f"unexpected DB call: {fn}")

    monkeypatch.setattr(panel.DB, "run", fake_db_run)
    proxy = panel._merge_proxy_open("srv1", _FakeBrowser(), "sid1", owner="alice")
    proxy.remote = _FakeRemote()
    before = panel._merge_revoke_gen("issuerK")

    r = client.post("/api/config/servers/srv1/key", json={"key": "k" * 32})
    assert r.status_code == 200, r.text
    assert panel._merge_revoke_gen("issuerK") == before + 1
    assert proxy.remote.closed
    assert json.loads(proxy.remote.sent[0]) == {"kill": True, "force": True}


def test_inbound_terminal_uses_the_real_per_peer_verifier(client, db, monkeypatch):
    """The other inbound tests fake verification. This one drives the real
    verifier and proves the bound peer key, the admin role and the terminal
    scope are all required at the WebSocket edge."""
    uid = "pytest-ws-" + uuid.uuid4().hex
    peer_key = "pytest-ws-key-" + uuid.uuid4().hex
    panel.merge_servers.record_request(uid, "ws-peer", "127.0.0.1",
                                       link_key=peer_key)
    panel.merge_servers.decide_request(uid, True, "pytest")
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    ident = panel.merge_servers.ensure_local_identity()

    def token(key, role="admin", scopes=("terminal",)):
        return panel.merge_servers.sign_token(key, {
            "iss": uid, "aud": ident["server_uid"], "sub": "alice",
            "role": role, "scopes": list(scopes), "purpose": "api"})

    try:
        with client.websocket_connect(
                "/ws/merge/terminal?sid=realauth&token=" + token(peer_key)) as ws:
            assert json.loads(ws.receive_text())["sid"] == "mr_realauth"

        # The receiver's own key must not authenticate a bound peer's data.
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                    "/ws/merge/terminal?sid=badkey&token="
                    + token(ident["key"])) as ws:
                ws.receive_text()
        assert exc.value.code == 1008

        # A valid peer key is not enough without the admin role.
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                    "/ws/merge/terminal?sid=staff&token="
                    + token(peer_key, role="staff")) as ws:
                ws.receive_text()
        assert exc.value.code == 1008

        # Nor without the terminal scope.
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                    "/ws/merge/terminal?sid=noscope&token="
                    + token(peer_key, scopes=("overview",))) as ws:
                ws.receive_text()
        assert exc.value.code == 1008
    finally:
        conn = db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM merge_request WHERE server_uid=%s", (uid,))
            conn.commit()
            cur.close()
        finally:
            db.release_connection(conn)


def test_changing_server_access_closes_that_accounts_linked_proxies(
        client, monkeypatch):
    _as(client, "admin")
    monkeypatch.setattr(panel, "_resolve_permissions", lambda name: _admin_perms())

    async def fake_db_run(fn, *args, **kwargs):
        if fn is panel._resolve_permissions:
            return _admin_perms()
        if fn is panel.merge_servers.set_user_access:
            return None
        if fn is panel._forget_user_epoch:
            return None
        raise AssertionError(f"unexpected DB call: {fn}")

    monkeypatch.setattr(panel.DB, "run", fake_db_run)

    alice_browser = _FakeBrowser()
    alice = panel._merge_proxy_open("srv1", alice_browser, "sid1", owner="alice")
    alice.remote = _FakeRemote()
    bob_browser = _FakeBrowser()
    bob = panel._merge_proxy_open("srv2", bob_browser, "sid2", owner="bob")
    bob.remote = _FakeRemote()

    r = client.post("/api/config/users/alice", json={"servers": []})
    assert r.status_code == 200, r.text

    assert alice.remote.closed and alice_browser.closed
    assert not bob.remote.closed and not bob_browser.closed
