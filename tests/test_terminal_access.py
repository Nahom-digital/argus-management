"""Who may see, attach to, and keep a local terminal session.

These are the access-control edges around the PTY: another account's sid is
refused instead of silently replaced, a narrowed grant cannot reattach to the
privileged shell it used to have, and the session list only shows the caller's
own live local tabs.
"""
import asyncio
import json
import threading
import time

import pytest

import panel
import panel_users as pu
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

STAFF = "pytest_term_grants"
PASSWORD = "T3rm!Grants"


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
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51057)) as c:
        yield c
    panel._TERMS.clear()


@pytest.fixture(autouse=True)
def clean_terms():
    panel._TERMS.clear()
    _FakeTerm.instances = []
    yield
    panel._TERMS.clear()


@pytest.fixture
def staff_account(conn):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"svc_status": True}, "admin")
    panel._forget_user_epoch(STAFF)
    try:
        yield STAFF
    finally:
        pu.delete_user(conn, STAFF)
        panel._forget_user_epoch(STAFF)


def _as(client, name):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(name))


def _perms(terminal=pu.TERMINAL_ROOT, os_username=None):
    return {"role": "admin", "username": "ignored", "os_username": os_username,
            "terminal": terminal}


def _expect_close(ws, code=1008):
    with pytest.raises(WebSocketDisconnect) as exc:
        ws.receive_text()
    assert exc.value.code == code


def test_the_list_shows_only_my_live_local_sessions(client, monkeypatch):
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    mine = _FakeTerm("mine", True, 24, 80, owner="alice")
    dead = _FakeTerm("dead", False, 24, 80, owner="alice")
    dead.dead = True
    theirs = _FakeTerm("theirs", False, 24, 80, owner="bob")
    inbound = _FakeTerm("inbound", False, 24, 80, owner="merge:iss:alice")
    panel._TERMS.update({"mine": mine, "dead": dead,
                         "theirs": theirs, "inbound": inbound})

    r = client.get("/api/system/terminals")
    assert r.status_code == 200, r.text
    assert [s["id"] for s in r.json()["sessions"]] == ["mine"]
    assert panel._TERMS["mine"] is mine


def test_the_list_needs_more_than_a_session(client, monkeypatch):
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_NONE))
    _as(client, "alice")
    _FakeTerm("mine", False, 24, 80, owner="alice")
    assert client.get("/api/system/terminals").status_code == 403


def test_a_limited_terminal_without_an_os_account_is_refused(client, monkeypatch):
    """No OS account means there is nothing to jail, so this used to fall back
    to an unconfined shell as the panel process user."""
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_LIMITED, None))
    _as(client, "alice")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/terminal?sid=blocked"):
            pass
    assert exc.value.code == 1008
    assert panel._TERMS == {}


@pytest.mark.parametrize("name", ["alice", "admin"])
def test_another_accounts_terminal_is_refused_not_replaced(client, monkeypatch, name):
    """The admin is not special here: a sid belongs to the account that opened it."""
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, name)
    old = _FakeTerm("bound", False, 24, 80, owner="bob")
    panel._TERMS["bound"] = old

    with client.websocket_connect("/ws/terminal?sid=bound") as ws:
        _expect_close(ws)

    assert panel._TERMS.get("bound") is old
    assert not old.closed
    assert _FakeTerm.instances == [old]


def test_narrowed_access_replaces_a_privileged_shell_under_the_same_sid(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel.System, "jail_available", lambda: True)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_LIMITED, "aliceos"))
    _as(client, "alice")
    old = _FakeTerm("sid1", True, 24, 80, owner="alice", run_as=None, jail=False)
    panel._TERMS["sid1"] = old

    with client.websocket_connect("/ws/terminal?sid=sid1&persist=1&rows=30&cols=100") as ws:
        assert json.loads(ws.receive_text())["sid"] == "sid1"
        new = panel._TERMS["sid1"]
        assert new is not old
        assert old.closed
        assert new.run_as == "aliceos" and new.jail is True
        assert (new.rows, new.cols) == (30, 100)

    assert _FakeTerm.instances == [old, new]


def test_a_matching_grant_reattaches_to_the_existing_shell(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel.System, "jail_available", lambda: True)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_LIMITED, "aliceos"))
    _as(client, "alice")
    old = _FakeTerm("sid1", False, 24, 80, owner="alice", run_as="aliceos", jail=True)
    panel._TERMS["sid1"] = old

    with client.websocket_connect("/ws/terminal?sid=sid1&rows=31&cols=101") as ws:
        assert json.loads(ws.receive_text())["sid"] == "sid1"
        assert panel._TERMS["sid1"] is old
        assert not old.closed

    assert _FakeTerm.instances == [old]


def test_terminal_dimensions_are_clamped_before_they_reach_the_pty():
    assert panel._clamp_term_dims(None, None) == (24, 80)
    assert panel._clamp_term_dims("abc", "def") == (24, 80)
    assert panel._clamp_term_dims(0, 0) == (1, 1)
    assert panel._clamp_term_dims(-40, -1) == (1, 1)
    assert panel._clamp_term_dims(99999, 99999) == (panel._TERM_ROWS_MAX,
                                                    panel._TERM_COLS_MAX)


def test_an_absurd_query_size_is_clamped_for_a_new_shell(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")

    with client.websocket_connect("/ws/terminal?sid=big&rows=99999&cols=-5") as ws:
        assert json.loads(ws.receive_text())["sid"] == "big"
        term = panel._TERMS["big"]
        assert (term.rows, term.cols) == (panel._TERM_ROWS_MAX,
                                          panel._TERM_COLS_MIN)


def test_a_resize_message_is_clamped(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("sized", False, 24, 80, owner="alice")
    panel._TERMS["sized"] = term

    with client.websocket_connect("/ws/terminal?sid=sized&persist=0") as ws:
        assert json.loads(ws.receive_text())["sid"] == "sized"
        _subscribed(term)
        ws.send_text(json.dumps({"resize": [5000, -3]}))
        deadline = time.monotonic() + 5.0
        while term.rows != panel._TERM_ROWS_MAX and time.monotonic() < deadline:
            time.sleep(0.01)
        assert (term.rows, term.cols) == (panel._TERM_ROWS_MAX,
                                          panel._TERM_COLS_MIN)


def test_attaching_does_not_resize_a_pty_another_view_is_using(client, monkeypatch):
    """The connecting browser is not the only viewer. Its grid must not be
    applied to a pty that is already drawing someone else's screen."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("shared", True, 24, 80, owner="alice")
    other = asyncio.Queue()
    term.subscribers.add(other)
    panel._TERMS["shared"] = term

    with client.websocket_connect(
            "/ws/terminal?sid=shared&persist=1&rows=50&cols=200") as ws:
        assert json.loads(ws.receive_text())["sid"] == "shared"
        assert len(_subscribed(term)) == 2
        assert (term.rows, term.cols) == (24, 80)

    assert not term.closed
    assert panel._TERMS.get("shared") is term


def test_attaching_without_other_viewers_takes_the_connecting_size(
        client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("solo", False, 24, 80, owner="alice")
    panel._TERMS["solo"] = term

    with client.websocket_connect("/ws/terminal?sid=solo&rows=40&cols=120") as ws:
        assert json.loads(ws.receive_text())["sid"] == "solo"
        assert (term.rows, term.cols) == (40, 120)


def _subscribed(term, timeout=2.0):
    """The handler adds its queue just after the sid message; wait for it."""
    deadline = time.monotonic() + timeout
    while not term.subscribers and time.monotonic() < deadline:
        time.sleep(0.01)
    return list(term.subscribers)


def _next_frame(ws, timeout=5.0):
    """Read one frame, failing rather than hanging if no close ever arrives."""
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
        pytest.fail("the websocket was not closed after the shell exited",
                    pytrace=False)
    if "error" in box:
        raise box["error"]
    return box["message"]


def test_an_exited_local_shell_closes_the_websocket(client, monkeypatch):
    """The reader queues None when the shell exits. Without a close the handler
    stays parked in websocket.receive() and the fd and buffer live on until the
    tab is closed."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")

    with client.websocket_connect("/ws/terminal?sid=gone&persist=0") as ws:
        assert json.loads(ws.receive_text())["sid"] == "gone"
        term = panel._TERMS["gone"]
        subs = _subscribed(term)
        assert subs, "the handler never subscribed to the pty"
        for q in subs:
            q.put_nowait(None)
        assert b"session ended" in ws.receive_bytes()
        closed = _next_frame(ws)
        assert closed["type"] == "websocket.close"
        assert closed["code"] == 1000

    assert term.closed
    assert "gone" not in panel._TERMS


def _linked_token(issuer="issuerA"):
    """A decodable token for the linked-terminal tests. Their verification is
    monkeypatched, but the handler still has to read the issuer from the token
    before it can look up the peer."""
    return panel.merge_servers.sign_token(
        "test-key-that-is-long-enough", {"iss": issuer, "purpose": "api"})


def test_an_exited_linked_shell_closes_the_websocket(client, monkeypatch):
    """The receiving side of a linked terminal has the same pump and must close
    too, so the local proxy sees EOF and the browser gets onclose."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)

    async def identity():
        return {"key": "local-key", "server_uid": "local"}

    monkeypatch.setattr(panel, "_merge_local_identity", identity)
    monkeypatch.setattr(panel.merge_servers, "verify_token",
                        lambda token, key: {"purpose": "api", "iss": "issuerA",
                                            "aud": "local", "sub": "alice",
                                            "role": "admin",
                                            "scopes": ["terminal"]})
    monkeypatch.setattr(panel.merge_servers, "request_record",
                        lambda issuer: {"status": "allowed",
                                        "has_peer_key": True,
                                        "peer_key": "local-key"})

    with client.websocket_connect(
            "/ws/merge/terminal?sid=dead&token=" + _linked_token()) as ws:
        assert json.loads(ws.receive_text())["sid"] == "mr_dead"
        term = panel._TERMS["mr_dead"]
        subs = _subscribed(term)
        assert subs, "the handler never subscribed to the pty"
        for q in subs:
            q.put_nowait(None)
        assert b"session ended" in ws.receive_bytes()
        closed = _next_frame(ws)
        assert closed["type"] == "websocket.close"
        assert closed["code"] == 1000

    assert term.closed
    assert "mr_dead" not in panel._TERMS


def test_a_linked_sid_owned_by_another_peer_is_refused(client, monkeypatch):
    old = _FakeTerm("mr_bound", False, 24, 80,
                    owner="merge:issuerA:alice")
    panel._TERMS["mr_bound"] = old

    async def identity():
        return {"key": "local-key", "server_uid": "local"}

    monkeypatch.setattr(panel, "_merge_local_identity", identity)
    monkeypatch.setattr(panel.merge_servers, "verify_token",
                        lambda token, key: {"purpose": "api", "iss": "issuerB",
                                            "aud": "local", "sub": "bob",
                                            "role": "admin",
                                            "scopes": ["terminal"]})
    monkeypatch.setattr(panel.merge_servers, "request_record",
                        lambda issuer: {"status": "allowed",
                                        "has_peer_key": True,
                                        "peer_key": "local-key"})

    with client.websocket_connect(
            "/ws/merge/terminal?sid=bound&token="
            + _linked_token("issuerB")) as ws:
        _expect_close(ws)

    assert panel._TERMS.get("mr_bound") is old
    assert not old.closed
    assert _FakeTerm.instances == [old]


def test_a_linked_terminal_clamps_its_size_and_leaves_other_views_alone(
        client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)

    async def identity():
        return {"key": "local-key", "server_uid": "local"}

    monkeypatch.setattr(panel, "_merge_local_identity", identity)
    monkeypatch.setattr(panel.merge_servers, "verify_token",
                        lambda token, key: {"purpose": "api", "iss": "issuerA",
                                            "aud": "local", "sub": "alice",
                                            "role": "admin",
                                            "scopes": ["terminal"]})
    monkeypatch.setattr(panel.merge_servers, "request_record",
                        lambda issuer: {"status": "allowed",
                                        "has_peer_key": True,
                                        "peer_key": "local-key"})

    term = _FakeTerm("mr_shared", True, 24, 80,
                     owner="merge:issuerA:alice")
    other = asyncio.Queue()
    term.subscribers.add(other)
    panel._TERMS["mr_shared"] = term

    with client.websocket_connect(
            "/ws/merge/terminal?sid=shared&persist=1&rows=50&cols=200&token="
            + _linked_token()) as ws:
        assert json.loads(ws.receive_text())["sid"] == "mr_shared"
        assert len(_subscribed(term)) == 2
        assert (term.rows, term.cols) == (24, 80)

    with client.websocket_connect(
            "/ws/merge/terminal?sid=big&rows=99999&cols=-9&token="
            + _linked_token()) as ws:
        assert json.loads(ws.receive_text())["sid"] == "mr_big"
        big = panel._TERMS["mr_big"]
        assert (big.rows, big.cols) == (panel._TERM_ROWS_MAX,
                                        panel._TERM_COLS_MIN)


def test_closing_local_terminals_leaves_other_accounts_and_inbound_alone():
    alice = _FakeTerm("a", True, 24, 80, owner="alice")
    bob = _FakeTerm("b", True, 24, 80, owner="bob")
    inbound = _FakeTerm("m", True, 24, 80, owner="merge:iss:bob")
    panel._TERMS.update({"a": alice, "b": bob, "m": inbound})

    panel._close_local_terminals("alice")
    assert alice.closed and "a" not in panel._TERMS
    assert not bob.closed and not inbound.closed

    panel._close_local_terminals()
    assert bob.closed and "b" not in panel._TERMS
    assert not inbound.closed and "m" in panel._TERMS


def test_unchanged_or_widened_grants_do_not_close_live_terminals(
        client, monkeypatch, staff_account):
    calls = []
    monkeypatch.setattr(panel, "_close_local_terminals",
                        lambda username=None: calls.append(username))
    _as(client, "admin")

    same = client.post(f"/api/config/users/{staff_account}",
                       json={"grants": {"svc_status": True}})
    assert same.status_code == 200, same.text
    wider = client.post(f"/api/config/users/{staff_account}",
                        json={"grants": {"svc_status": True, "logs_access": True}})
    assert wider.status_code == 200, wider.text
    assert calls == []


def test_narrowed_grants_close_live_terminals(client, monkeypatch, staff_account):
    calls = []
    monkeypatch.setattr(panel, "_close_local_terminals",
                        lambda username=None: calls.append(username))
    _as(client, "admin")

    r = client.post(f"/api/config/users/{staff_account}", json={"grants": {}})
    assert r.status_code == 200, r.text
    assert calls == [staff_account]


def test_attaching_with_stay_off_does_not_turn_off_a_kept_session(client, monkeypatch):
    """A second window attaching with Stay off is not evidence that the first
    window turned Stay off. Only an explicit persist control may do that."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    old = _FakeTerm("sid1", True, 24, 80, owner="alice")
    panel._TERMS["sid1"] = old

    with client.websocket_connect("/ws/terminal?sid=sid1&persist=0") as ws:
        hello = json.loads(ws.receive_text())
        assert hello["persist"] is True
        assert old.persist is True

    assert panel._TERMS.get("sid1") is old
    assert not old.closed


def test_closing_one_of_two_views_does_not_end_the_shared_shell(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("shared", False, 24, 80, owner="alice")
    other = asyncio.Queue()
    term.subscribers.add(other)
    panel._TERMS["shared"] = term

    with client.websocket_connect("/ws/terminal?sid=shared&persist=0") as ws:
        assert json.loads(ws.receive_text())["sid"] == "shared"
        assert len(_subscribed(term)) == 2
        ws.send_text(json.dumps({"kill": True}))
        # The handler drops this view's queue but keeps the shell for the other.
        deadline = time.monotonic() + 5.0
        while len(term.subscribers) > 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert term.subscribers == {other}
        assert not term.closed

    assert not term.closed
    assert panel._TERMS.get("shared") is term


def test_kill_from_the_last_view_ends_the_shell(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("solo", False, 24, 80, owner="alice")
    panel._TERMS["solo"] = term

    with client.websocket_connect("/ws/terminal?sid=solo&persist=0") as ws:
        assert json.loads(ws.receive_text())["sid"] == "solo"
        assert len(_subscribed(term)) == 1
        ws.send_text(json.dumps({"kill": True}))
        deadline = time.monotonic() + 5.0
        while not term.closed and time.monotonic() < deadline:
            time.sleep(0.01)
        assert term.closed
        assert "solo" not in panel._TERMS


def test_an_old_handler_does_not_close_a_recreated_session(client, monkeypatch):
    """A reconnect can respawn a session under the same sid (narrowed grant).
    The old handler's finally must close by identity, not by sid."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    old = _FakeTerm("sid1", False, 24, 80, owner="alice")
    panel._TERMS["sid1"] = old

    with client.websocket_connect("/ws/terminal?sid=sid1&persist=0") as ws:
        assert json.loads(ws.receive_text())["sid"] == "sid1"
        _subscribed(old)
        replacement = _FakeTerm("sid1", False, 24, 80, owner="alice")
        panel._TERMS["sid1"] = replacement

    assert not replacement.closed
    assert panel._TERMS.get("sid1") is replacement


def test_an_existing_scrollback_is_replayed_once(client, monkeypatch):
    """The replay in the handshake is the snapshot, not something the live
    queue also has to deliver a second time."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("kept", True, 24, 80, owner="alice")
    term.buffer += b"hello\r\n"
    panel._TERMS["kept"] = term

    with client.websocket_connect("/ws/terminal?sid=kept&persist=1") as ws:
        assert json.loads(ws.receive_text())["sid"] == "kept"
        assert ws.receive_bytes() == b"hello\r\n"
        queues = _subscribed(term)
        assert len(queues) == 1
        assert queues[0].empty(), "the replayed buffer must not also be queued"


class _FakeRemote:
    def __init__(self):
        self.sent = []
        self.closed = False

    async def send(self, data):
        self.sent.append(data)

    async def close(self):
        self.closed = True


def test_deleting_a_linked_server_ends_its_live_proxies():
    """The row is gone, so nothing can reattach; the remote shell must not keep
    running behind the deleted server."""
    try:
        proxy = panel._merge_proxy_open("srv1", object(), "sid1")
        remote = _FakeRemote()
        proxy.remote = remote
        other = panel._merge_proxy_open("srv2", object(), "sid2")
        other.remote = _FakeRemote()

        asyncio.run(panel._end_merge_proxies("srv1"))

        assert remote.closed
        assert json.loads(remote.sent[0]) == {"kill": True, "force": True}
        assert panel._MERGE_LIVE.get("srv2") == [other]
        assert panel._MERGE_LIVE.get("srv1") == [proxy]
        panel._merge_proxy_done(proxy)
        assert "srv1" not in panel._MERGE_LIVE
    finally:
        panel._MERGE_LIVE.clear()


def test_a_proxy_still_opening_is_ended_when_its_server_is_deleted():
    try:
        proxy = panel._merge_proxy_open("srv3", object(), "sid3")
        asyncio.run(panel._end_merge_proxies("srv3"))
        assert proxy.gone is True

        remote = _FakeRemote()
        proxy.remote = remote
        asyncio.run(panel._end_merge_proxy(proxy))
        assert remote.closed
    finally:
        panel._MERGE_LIVE.clear()


class _FakeReaderLoop:
    """Only the reader and call_soon surface _ManagedTerm uses."""

    def __init__(self):
        self.readers = {}
        self.scheduled = []

    def add_reader(self, fd, callback):
        self.readers[fd] = callback

    def remove_reader(self, fd):
        self.readers.pop(fd, None)
        return True

    def call_soon(self, fn, *args):
        self.scheduled.append((fn, args))

    def run_scheduled(self):
        while self.scheduled:
            fn, args = self.scheduled.pop(0)
            fn(*args)


class _FakePty:
    def __init__(self):
        self.fd = 77
        self.closed = False
        self.writes = []

    def spawn(self, rows=24, cols=80):
        pass

    def write(self, data):
        self.writes.append(data)

    def set_winsize(self, rows, cols):
        pass

    def close(self):
        self.closed = True


def _managed(monkeypatch, sid, read):
    loop = _FakeReaderLoop()
    pty = _FakePty()
    monkeypatch.setattr(panel.asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(panel.System, "PtySession", lambda **kw: pty)
    monkeypatch.setattr(panel.os, "read", read)
    term = panel._ManagedTerm(sid, False, 24, 80, owner="alice")
    panel._TERMS[sid] = term
    return loop, pty, term


def test_a_stalled_subscriber_is_capped_instead_of_growing(monkeypatch):
    """A browser that stops reading must not make its queue grow with the
    shell's output. It gets one end sentinel and is dropped; a healthy viewer
    keeps receiving the whole time."""
    limit = panel._TERM_QUEUE_MAX_CHUNKS
    reads = limit + 10
    loop, pty, term = _managed(monkeypatch, "slow", lambda fd, size: b"x" * 1024)
    stalled = asyncio.Queue()
    healthy = asyncio.Queue()
    term.subscribers.update({stalled, healthy})

    delivered = 0
    for _ in range(reads):
        loop.readers[pty.fd]()
        while not healthy.empty():
            healthy.get_nowait()
            delivered += 1

    assert delivered == reads, "the healthy subscriber must keep receiving"
    assert stalled.qsize() <= limit + 1
    assert stalled._term_overflowed is True

    items = []
    while not stalled.empty():
        items.append(stalled.get_nowait())
    assert items[-1] is None, "the pump needs the normal end sentinel"
    assert items.count(None) == 1

    # Later reads must not keep growing an overflowed queue.
    for _ in range(5):
        loop.readers[pty.fd]()
    assert stalled.qsize() == 0


def test_resize_only_remembers_a_size_the_pty_accepted(monkeypatch):
    """A rejected ioctl must not leave the panel reporting a grid the shell
    never got, so rows/cols only move on success."""
    loop, pty, term = _managed(monkeypatch, "sized", lambda fd, size: b"x")
    pty.set_winsize = lambda rows, cols: False
    term.resize(40, 120)
    assert (term.rows, term.cols) == (24, 80)

    pty.set_winsize = lambda rows, cols: True
    term.resize(40, 120)
    assert (term.rows, term.cols) == (40, 120)


def test_a_detached_shell_that_exits_is_released(monkeypatch):
    """With no subscribers no pump sees the exit, so the session has to free
    its fd and child itself instead of sitting in _TERMS until a reconnect."""
    loop, pty, term = _managed(monkeypatch, "gone", lambda fd, size: b"")
    loop.readers[pty.fd]()

    assert term.dead
    assert pty.fd not in loop.readers
    assert len(loop.scheduled) == 1

    loop.run_scheduled()
    assert pty.closed
    assert "gone" not in panel._TERMS


def test_the_exit_cleanup_leaves_a_respawned_session_alone(monkeypatch):
    """The scheduled close is identity-checked: a session recreated with the
    same sid before the callback runs must not be closed by it."""
    loop, pty, term = _managed(monkeypatch, "gone", lambda fd, size: b"")
    loop.readers[pty.fd]()

    replacement = _FakeTerm("gone", True, 24, 80, owner="alice")
    panel._TERMS["gone"] = replacement

    loop.run_scheduled()
    assert not replacement.closed
    assert panel._TERMS.get("gone") is replacement


def test_a_forced_kill_ends_a_shared_shell(client, monkeypatch):
    """Deleting a linked server must end its remote shell even when more than
    one view is attached, so the force flag bypasses the detach-only rule."""
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("shared", True, 24, 80, owner="alice")
    other = asyncio.Queue()
    term.subscribers.add(other)
    panel._TERMS["shared"] = term

    with client.websocket_connect("/ws/terminal?sid=shared&persist=1") as ws:
        assert json.loads(ws.receive_text())["sid"] == "shared"
        assert len(_subscribed(term)) == 2
        ws.send_text(json.dumps({"kill": True, "force": True}))
        deadline = time.monotonic() + 5.0
        while not term.closed and time.monotonic() < deadline:
            time.sleep(0.01)
        assert term.closed
        assert "shared" not in panel._TERMS


def test_a_shutting_down_loop_still_releases_the_exited_session(monkeypatch):
    """If call_soon is refused (the loop is closing), the session is closed
    directly instead of leaving an unhandled callback error and a live fd."""
    loop, pty, term = _managed(monkeypatch, "gone", lambda fd, size: b"")

    def refuse(*args, **kwargs):
        raise RuntimeError("Event loop is closed")

    loop.call_soon = refuse
    loop.readers[pty.fd]()

    assert pty.closed
    assert "gone" not in panel._TERMS


def _wait_subscribers(term, count, timeout=2.0):
    deadline = time.monotonic() + timeout
    while len(term.subscribers) < count and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(term.subscribers) >= count


def _wait_write(term, text, timeout=5.0):
    """A non-JSON text frame is written to the pty once every earlier control
    in the same websocket has been handled, so it orders the assertion."""
    deadline = time.monotonic() + timeout
    while text not in term.writes and time.monotonic() < deadline:
        time.sleep(0.005)
    assert text in term.writes


def test_an_initial_resize_is_ignored_when_the_shell_is_shared(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("shared", True, 30, 100, owner="alice")
    term.subscribers.add(asyncio.Queue())
    panel._TERMS["shared"] = term

    with client.websocket_connect("/ws/terminal?sid=shared&persist=1&rows=30&cols=100") as ws:
        assert json.loads(ws.receive_text())["sid"] == "shared"
        _wait_subscribers(term, 2)
        ws.send_text(json.dumps({"resize": [40, 120], "initial": True}))
        ws.send_text("PING")
        _wait_write(term, "PING")
        assert (term.rows, term.cols) == (30, 100)


def test_an_initial_resize_is_applied_to_the_only_view(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("solo", True, 30, 100, owner="alice")
    panel._TERMS["solo"] = term

    with client.websocket_connect("/ws/terminal?sid=solo&persist=1&rows=30&cols=100") as ws:
        assert json.loads(ws.receive_text())["sid"] == "solo"
        _subscribed(term)
        ws.send_text(json.dumps({"resize": [40, 120], "initial": True}))
        ws.send_text("PING")
        _wait_write(term, "PING")
        assert (term.rows, term.cols) == (40, 120)


def test_an_untagged_resize_still_applies_to_a_shared_shell(client, monkeypatch):
    monkeypatch.setattr(panel, "_ManagedTerm", _FakeTerm)
    monkeypatch.setattr(panel, "_resolve_permissions",
                        lambda username: _perms(pu.TERMINAL_ROOT))
    _as(client, "alice")
    term = _FakeTerm("shared2", True, 30, 100, owner="alice")
    term.subscribers.add(asyncio.Queue())
    panel._TERMS["shared2"] = term

    with client.websocket_connect("/ws/terminal?sid=shared2&persist=1&rows=30&cols=100") as ws:
        assert json.loads(ws.receive_text())["sid"] == "shared2"
        _wait_subscribers(term, 2)
        ws.send_text(json.dumps({"resize": [40, 120]}))
        ws.send_text("PING")
        _wait_write(term, "PING")
        assert (term.rows, term.cols) == (40, 120)
