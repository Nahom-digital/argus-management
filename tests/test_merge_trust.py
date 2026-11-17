"""Who may speak for whom over a linked panel.

A link used to trust one shared key: the receiving panel checked every token
with its own key, so any peer that had ever been given that key could mint a
token for another peer's uid. These tests pin the per-peer model: an allowed
peer is bound to the key it presented in its handshake, only that key signs its
data calls, and only the handshake and status poll may use the receiver's key.
"""
import uuid

import pytest

import DB
import merge_servers
import panel
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51058)) as c:
        yield c


@pytest.fixture(autouse=True)
def clean_replay():
    merge_servers._reset_replay_cache()
    yield
    merge_servers._reset_replay_cache()


@pytest.fixture
def identity(db):
    return merge_servers.ensure_local_identity()


def _drop_request(uid):
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM merge_request WHERE server_uid=%s", (uid,))
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)


@pytest.fixture
def peer(db, identity):
    """An allowed peer bound to its own key, removed afterwards."""
    uid = "pytest-peer-" + uuid.uuid4().hex
    key = "peer-link-key-" + uuid.uuid4().hex
    try:
        merge_servers.record_request(uid, "pytest-peer", "127.0.0.1", link_key=key)
        merge_servers.decide_request(uid, True, "pytest")
        yield {"uid": uid, "key": key}
    finally:
        _drop_request(uid)


def _token(uid, identity, purpose="api", scopes=None, key=""):
    return merge_servers.sign_token(key or identity["key"], {
        "iss": uid,
        "aud": identity["server_uid"],
        "sub": "admin",
        "role": "admin",
        "scopes": list(scopes or []),
        "purpose": purpose,
    })


def _auth(token):
    return {"Authorization": "Bearer " + token}


def test_a_bound_peer_is_trusted_only_with_its_own_key(client, identity, peer):
    good = _token(peer["uid"], identity, scopes=["overview"], key=peer["key"])
    resp = client.get("/api/merge/static", headers=_auth(good))
    assert resp.status_code == 200

    # The same claims signed with the receiver's key must not pass once the
    # peer is bound, even though that key verified every call before.
    borrowed = _token(peer["uid"], identity, scopes=["overview"],
                      key=identity["key"])
    resp = client.get("/api/merge/static", headers=_auth(borrowed))
    assert resp.status_code == 401


def test_a_denied_peer_can_handshake_but_cannot_read_data(client, identity, peer):
    uid = "pytest-denied-" + uuid.uuid4().hex
    peer_key = "denied-link-key-" + uuid.uuid4().hex
    try:
        merge_servers.record_request(uid, "denied-peer", "10.0.0.9")
        merge_servers.decide_request(uid, False, "pytest")

        # Bootstrap calls may use the receiver's key, which is how this peer
        # introduces itself, and they bind the key it presents.
        hs = _token(uid, identity, purpose="handshake", key=identity["key"])
        resp = client.post("/api/merge/handshake", headers=_auth(hs),
                           json={"hostname": "denied-peer", "link_key": peer_key})
        assert resp.status_code == 200
        assert resp.json()["status"] == "denied"
        assert resp.json()["key_bound"] is True

        st = _token(uid, identity, purpose="status", key=identity["key"])
        resp = client.get("/api/merge/status", headers=_auth(st))
        assert resp.status_code == 200
        assert resp.json()["status"] == "denied"

        # Its own key authenticates it, but the denial still stops every route.
        own = _token(uid, identity, scopes=["overview"], key=peer_key)
        assert client.get("/api/merge/static",
                          headers=_auth(own)).status_code == 401

        # Holding the receiver's key does not let it act as itself or as the
        # allowed peer above.
        grabbed = _token(uid, identity, scopes=["overview"],
                         key=identity["key"])
        assert client.get("/api/merge/static",
                          headers=_auth(grabbed)).status_code == 401
        stolen = _token(peer["uid"], identity, scopes=["overview"],
                        key=identity["key"])
        assert client.get("/api/merge/static",
                          headers=_auth(stolen)).status_code == 401
    finally:
        _drop_request(uid)


def test_a_peer_cannot_replace_another_peers_bound_key(client, identity, peer):
    attacker_key = "attacker-key-" + uuid.uuid4().hex
    with pytest.raises(merge_servers.PeerKeyConflict):
        merge_servers.record_request(peer["uid"], "attacker", "10.0.0.7",
                                     link_key=attacker_key)

    hs = _token(peer["uid"], identity, purpose="handshake", key=identity["key"])
    resp = client.post("/api/merge/handshake", headers=_auth(hs),
                       json={"link_key": attacker_key})
    assert resp.status_code == 409
    assert resp.json()["code"] == "link_key_mismatch"

    record = merge_servers.request_record(peer["uid"])
    assert record["has_peer_key"] is True
    assert record["peer_key"] == peer["key"]

    good = _token(peer["uid"], identity, scopes=["overview"], key=peer["key"])
    assert client.get("/api/merge/static", headers=_auth(good)).status_code == 200


def test_a_legacy_allowed_link_requires_one_reapproval(client, identity):
    uid = "pytest-legacy-" + uuid.uuid4().hex
    peer_key = "legacy-link-key-" + uuid.uuid4().hex
    try:
        # A link allowed before per-peer keys: the row has no bound key.
        merge_servers.record_request(uid, "legacy-peer", "10.0.0.5")
        merge_servers.decide_request(uid, True, "pytest")
        assert merge_servers.request_record(uid)["has_peer_key"] is False

        legacy = _token(uid, identity, scopes=["overview"], key=identity["key"])
        resp = client.get("/api/merge/static", headers=_auth(legacy))
        assert resp.status_code == 401
        assert resp.json()["code"] == "link_key_required"

        st = _token(uid, identity, purpose="status", key=identity["key"])
        resp = client.get("/api/merge/status", headers=_auth(st))
        assert resp.status_code == 200
        assert resp.json()["link_key_required"] is True

        # Binding a key to a link that was allowed under the old shared-key
        # model moves it back to pending. The admin re-approves once; nobody
        # who merely holds the old shared key inherits the approval.
        hs = _token(uid, identity, purpose="handshake", key=identity["key"])
        resp = client.post("/api/merge/handshake", headers=_auth(hs),
                           json={"link_key": peer_key})
        assert resp.status_code == 200
        assert resp.json()["key_bound"] is True
        assert resp.json()["status"] == "pending"

        good = _token(uid, identity, scopes=["overview"], key=peer_key)
        assert client.get("/api/merge/static", headers=_auth(good)).status_code == 401

        merge_servers.decide_request(uid, True, "pytest")

        # Data now needs the peer's key, and never falls back to ours.
        good = _token(uid, identity, scopes=["overview"], key=peer_key)
        assert client.get("/api/merge/static", headers=_auth(good)).status_code == 200
        fallback = _token(uid, identity, scopes=["overview"], key=identity["key"])
        assert client.get("/api/merge/static",
                          headers=_auth(fallback)).status_code == 401

        st = _token(uid, identity, purpose="status", key=identity["key"])
        resp = client.get("/api/merge/status", headers=_auth(st))
        assert resp.json()["status"] == "allowed"
        assert resp.json()["link_key_required"] is False
    finally:
        _drop_request(uid)


def test_denying_keeps_the_bound_key_and_refuses_a_different_one(client, identity):
    """A denial must not turn the binding into an empty slot: every peer holds
    this panel's bootstrap key, so clearing it would let one of them bind the
    denied uid and inherit an eventual re-allow."""
    uid = "pytest-rebind-" + uuid.uuid4().hex
    first = "first-link-key-" + uuid.uuid4().hex
    second = "second-link-key-" + uuid.uuid4().hex
    try:
        merge_servers.record_request(uid, "rebind-peer", "10.0.0.6",
                                     link_key=first)
        merge_servers.decide_request(uid, True, "pytest")
        assert client.get("/api/merge/static", headers=_auth(
            _token(uid, identity, scopes=["overview"], key=first))).status_code == 200

        merge_servers.decide_request(uid, False, "pytest")
        record = merge_servers.request_record(uid)
        assert record["status"] == "denied"
        assert record["has_peer_key"] is True
        assert record["peer_key"] == first

        hs = _token(uid, identity, purpose="handshake", key=identity["key"])
        resp = client.post("/api/merge/handshake", headers=_auth(hs),
                           json={"link_key": second})
        assert resp.status_code == 409
        assert resp.json()["code"] == "link_key_mismatch"

        merge_servers.decide_request(uid, True, "pytest")
        assert client.get("/api/merge/static", headers=_auth(
            _token(uid, identity, scopes=["overview"], key=first))).status_code == 200
        assert client.get("/api/merge/static", headers=_auth(
            _token(uid, identity, scopes=["overview"], key=second))).status_code == 401
    finally:
        _drop_request(uid)


def test_a_handshake_must_present_a_usable_link_key(client, identity):
    uid = "pytest-badkey-" + uuid.uuid4().hex
    try:
        for bad in ("short", "x" * 20 + "\n", "x" * 201):
            hs = _token(uid, identity, purpose="handshake", key=identity["key"])
            resp = client.post("/api/merge/handshake", headers=_auth(hs),
                               json={"link_key": bad})
            assert resp.status_code == 400
            assert resp.json()["code"] == "link_key_invalid"
        assert merge_servers.request_record(uid)["status"] is None
    finally:
        _drop_request(uid)


def test_a_replayed_token_is_rejected_within_its_ttl(client, identity, peer):
    token = _token(peer["uid"], identity, scopes=["overview"], key=peer["key"])
    assert client.get("/api/merge/static", headers=_auth(token)).status_code == 200
    resp = client.get("/api/merge/static", headers=_auth(token))
    assert resp.status_code == 401
    assert "already used" in resp.json()["error"]


def test_refresh_status_binds_a_legacy_link_with_one_handshake(db, monkeypatch):
    """The status poll is the first call an existing link makes. When it says
    the key is missing, the poll itself must run the idempotent handshake so the
    admin does not have to remove and re-add the panel."""
    remote_key = "status-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest refresh", "127.0.0.1", 80, "", remote_key)
    calls = []

    def fake_call(server, path, token, method="GET", body=None, timeout=10):
        calls.append({"path": path, "token": token, "body": body})
        if path == "/api/merge/status":
            first = sum(1 for c in calls if c["path"] == path) == 1
            return 200, {"status": "allowed", "server_uid": "remote-uid",
                         "hostname": "remote-host", "version": "",
                         "link_key_required": first}, ""
        if path == "/api/merge/handshake":
            return 200, {"status": "allowed", "server_uid": "remote-uid",
                         "hostname": "remote-host", "key_bound": True,
                         "version": ""}, ""
        return 404, {"error": "unexpected"}, "unexpected"

    monkeypatch.setattr(merge_servers, "http_call", fake_call)
    try:
        merge_servers.update_server(server_id, server_uid="remote-uid")
        result = merge_servers.refresh_status(server_id)
        assert [c["path"] for c in calls] == [
            "/api/merge/status", "/api/merge/handshake", "/api/merge/status"]
        local_key = merge_servers.ensure_local_identity()["key"]
        for call in calls:
            # Both bootstrap calls are signed with the receiving panel's key,
            # not with this panel's own data key.
            assert merge_servers.verify_token(call["token"], remote_key)
            assert merge_servers.verify_token(call["token"], local_key) is None
        link_key = merge_servers.get_server(server_id, True)["link_key"]
        assert link_key and link_key != local_key
        assert calls[1]["body"]["link_key"] == link_key
        assert result["ok"] is True
        assert result["status"] == "connected"
    finally:
        merge_servers.delete_server(server_id)


def test_a_data_token_must_name_this_panel_as_its_audience(client, identity, peer):
    token = merge_servers.sign_token(peer["key"], {
        "iss": peer["uid"], "sub": "admin", "role": "admin",
        "scopes": ["overview"], "purpose": "api"})
    assert client.get("/api/merge/static",
                      headers=_auth(token)).status_code == 401
