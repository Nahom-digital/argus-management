"""Unit coverage for the parts of panel linking that must not drift.

The network side is exercised by hand between two installs; these pin the
parsing, the token format and the one-directional approval rule that keeps a
pending or allowed incoming request from silently approving an outgoing link.
"""
import time
import uuid

import pytest

import merge_servers


def test_normalize_target_accepts_a_bare_host_and_port():
    got = merge_servers.normalize_target("example.com:8443")
    assert got == {"scheme": "http", "host": "example.com",
                   "port": 8443, "base_path": ""}


def test_normalize_target_accepts_a_full_url_and_its_path():
    got = merge_servers.normalize_target("https://panel.example.com/management/")
    assert got == {"scheme": "https", "host": "panel.example.com",
                   "port": 443, "base_path": "/management"}


def test_normalize_target_brackets_ipv6_in_urls():
    got = merge_servers.normalize_target("http://[::1]:9000/management")
    assert got["host"] == "::1"
    assert got["port"] == 9000
    assert merge_servers.server_url(got, "/api/merge/status") == \
        "http://[::1]:9000/management/api/merge/status"


def test_normalize_target_uses_the_separate_port_and_base_path():
    got = merge_servers.normalize_target("example.com", "8443", "/panel/")
    assert got == {"scheme": "http", "host": "example.com",
                   "port": 8443, "base_path": "/panel"}


def test_a_bare_host_defaults_to_https():
    got = merge_servers.normalize_target("panel.example.com")
    assert got == {"scheme": "https", "host": "panel.example.com",
                   "port": 443, "base_path": ""}


def test_a_bare_host_on_443_uses_https():
    got = merge_servers.normalize_target("panel.example.com", "443")
    assert got == {"scheme": "https", "host": "panel.example.com",
                   "port": 443, "base_path": ""}


def test_a_full_url_path_wins_over_the_separate_path_field():
    got = merge_servers.normalize_target(
        "https://panel.example.com/from-url", None, "/from-field")
    assert got["base_path"] == "/from-url"


def test_a_signed_token_verifies_and_a_changed_one_does_not():
    key = "test-key-that-is-long-enough"
    token = merge_servers.sign_token(
        key, {"iss": "panel-a", "aud": "panel-b", "purpose": "api"}, ttl=60)
    data = merge_servers.verify_token(token, key)
    assert data and data["iss"] == "panel-a" and data["purpose"] == "api"
    # Change a character at the start of the signature, where every bit counts.
    # Flipping the final base64 character can decode to the same bytes because
    # its low bits are padding, which made this assertion intermittent.
    head, payload, sig = token.split(".", 2)
    changed = "A" if sig[0] != "A" else "B"
    assert merge_servers.verify_token(
        head + "." + payload + "." + changed + sig[1:], key) is None
    assert merge_servers.verify_token(token, key + "-wrong") is None


def test_an_expired_token_is_refused():
    token = merge_servers.sign_token("test-key", {"iss": "panel-a"}, ttl=-1)
    assert merge_servers.verify_token(token, "test-key") is None


def test_make_server_token_still_works_after_get_server_strips_the_key(db):
    """Route handlers deliberately read a server without its key. The bootstrap
    token (handshake and status) has to look the key up instead of assuming the
    field is present, while a data token uses this panel's own key."""
    key = "stripped-row-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest linked", "127.0.0.1", 80, "", key)
    try:
        row = merge_servers.get_server(server_id, False)
        assert "key" not in row and "key_cipher" not in row
        token = merge_servers.make_server_token(row, subject="admin",
                                                bootstrap=True)
        data = merge_servers.verify_token(token, key)
        assert data and data["sub"] == "admin"
        assert data["version"] == merge_servers.panel_version()

        own = merge_servers.make_server_token(row, subject="admin")
        local_key = merge_servers.ensure_local_identity()["key"]
        link_key = merge_servers.get_server(server_id, True)["link_key"]
        assert link_key and link_key != local_key
        assert merge_servers.verify_token(own, link_key)
        assert merge_servers.verify_token(own, local_key) is None
        assert merge_servers.verify_token(own, key) is None
    finally:
        merge_servers.delete_server(server_id)


def test_version_state_calls_out_a_different_panel():
    """A version difference must not look like a broken link, but it has to be
    visible with both sides named so the admin can match them."""
    local = merge_servers.panel_version()
    other = merge_servers.version_state("0.0.1-old")
    assert other["local_version"] == local
    assert other["remote_version"] == "0.0.1-old"
    assert other["version_mismatch"] is True
    assert other["version_unknown"] is False

    same = merge_servers.version_state(local)
    assert same["version_mismatch"] is False
    assert same["version_unknown"] is False

    unknown = merge_servers.version_state("")
    assert unknown["version_mismatch"] is False
    assert unknown["version_unknown"] is True


def test_a_version_difference_does_not_hide_a_connected_server(db):
    """Version mismatch is a warning, not a permission decision. The server
    still has to appear in the list with its status intact."""
    key = "version-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest versioned", "127.0.0.1", 80, "", key)
    try:
        merge_servers.update_server(
            server_id, approved=True, status="connected",
            remote_version="0.0.1-old")
        rows = [s for s in merge_servers.list_servers() if s["id"] == server_id]
        assert rows and rows[0]["status"] == "connected"
        assert rows[0]["version_mismatch"] is True
        assert rows[0]["remote_version"] == "0.0.1-old"
    finally:
        merge_servers.delete_server(server_id)


def test_a_handshake_records_the_remote_version_and_still_connects(db, monkeypatch):
    """The response carries the other panel's version. It is stored for the
    Config page and the Server page, and an approval still wins over a
    mismatch: the link is connected, with a warning attached."""
    key = "handshake-version-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest handshake version", "127.0.0.1", 80, "", key)
    seen = {}

    def fake_call(server, path, token, method="GET", body=None, timeout=10):
        seen["path"] = path
        seen["token"] = token
        return 200, {"status": "allowed", "server_uid": "remote-uid",
                     "hostname": "remote-host", "version": "0.0.1-old"}, ""

    monkeypatch.setattr(merge_servers, "http_call", fake_call)
    try:
        result = merge_servers.handshake(server_id)
        assert seen["path"] == "/api/merge/handshake"
        claims = merge_servers.verify_token(seen["token"], key)
        assert claims["version"] == merge_servers.panel_version()
        assert result["ok"] is True
        assert result["status"] == "connected"
        assert result["remote_version"] == "0.0.1-old"
        assert result["version_mismatch"] is True
        row = merge_servers.get_server(server_id)
        assert row["status"] == "connected"
        assert row["approved"] is True
        assert row["remote_version"] == "0.0.1-old"
    finally:
        merge_servers.delete_server(server_id)


def test_allowing_an_incoming_request_does_not_approve_an_outgoing_link(db):
    """Approval is one-directional. If this panel also added the other panel,
    allowing the other panel's request must not mark our outgoing link allowed:
    that link still needs the other side's approval."""
    remote_uid = "pytest-" + uuid.uuid4().hex
    key = "outgoing-link-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest outgoing", "127.0.0.1", 80, "", key)
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        try:
            cur.execute("UPDATE merge_server SET server_uid=%s WHERE id=%s",
                        (remote_uid, server_id))
            cur.execute("DELETE FROM merge_request WHERE server_uid=%s", (remote_uid,))
            merge_servers.record_request(remote_uid, "remote-panel", "10.0.0.9")
            assert merge_servers.decide_request(remote_uid, True, "pytest")
            assert merge_servers.request_status(remote_uid) == "allowed"
            row = merge_servers.get_server(server_id)
            assert row["approved"] is False
            assert row["status"] == "pending"
        finally:
            cur.execute("DELETE FROM merge_request WHERE server_uid=%s", (remote_uid,))
            cur.close()
    finally:
        db.release_connection(conn)
        merge_servers.delete_server(server_id)


def test_replacing_a_linked_key_clears_the_old_approval(db):
    old_key = "old-key-" + uuid.uuid4().hex
    new_key = "new-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest rekey", "127.0.0.1", 80, "", old_key)
    try:
        merge_servers.update_server(server_id, approved=True, status="connected",
                                    server_uid="remote-uid", remote_hostname="remote")
        assert merge_servers.replace_server_key(server_id, new_key)
        row = merge_servers.get_server(server_id, include_key=True)
        assert row["key"] == new_key
        assert row["approved"] is False
        assert row["status"] == "pending"
        assert row["server_uid"] in (None, "")
    finally:
        merge_servers.delete_server(server_id)


def test_staff_see_only_linked_servers_an_admin_granted(db):
    key = "visibility-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest visible", "127.0.0.1", 80, "", key)
    username = "pytest-staff-" + uuid.uuid4().hex[:8]
    try:
        merge_servers.update_server(server_id, approved=True, status="connected")
        assert merge_servers.servers_for_user(username, "staff") == []
        merge_servers.set_user_access(username, [{
            "server_id": server_id, "permissions": {"cpu": True}}])
        visible = merge_servers.servers_for_user(username, "staff")
        assert [s["id"] for s in visible] == [server_id]
        assert visible[0]["scopes"]["cpu"] is True
        assert visible[0]["scopes"]["disk"] is False
        assert merge_servers.scopes_for(username, "staff", visible[0]) == ["cpu"]
    finally:
        merge_servers.delete_user_access(username)
        merge_servers.delete_server(server_id)


def test_access_alone_grants_the_overview_but_no_metrics(db):
    key = "overview-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest overview", "127.0.0.1", 80, "", key)
    username = "pytest-overview-" + uuid.uuid4().hex[:8]
    try:
        merge_servers.update_server(server_id, approved=True, status="connected")
        merge_servers.set_user_access(username, [{
            "server_id": server_id, "permissions": {}}])
        visible = merge_servers.servers_for_user(username, "staff")
        assert [s["id"] for s in visible] == [server_id]
        assert not any(visible[0]["scopes"].values())
        has_access, scopes = merge_servers.access_for_user(
            username, "staff", visible[0])
        assert has_access is True and scopes == []
        assert merge_servers.scopes_for(username, "staff", visible[0]) == []
    finally:
        merge_servers.delete_user_access(username)
        merge_servers.delete_server(server_id)


def test_a_long_base_path_is_rejected_before_a_key_is_stored(db):
    merge_servers.ensure_schema()
    name = "pytest-long-path-" + uuid.uuid4().hex
    key = "long-path-key-" + uuid.uuid4().hex
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        try:
            with pytest.raises(ValueError):
                merge_servers.create_server(
                    name, "127.0.0.1", 80, "/" + "a" * 200, key)
            cur.execute(
                "SELECT COUNT(*) FROM merge_serverkey WHERE label=%s", (name,))
            assert cur.fetchone()[0] == 0
            cur.execute(
                "SELECT COUNT(*) FROM merge_server WHERE name=%s", (name,))
            assert cur.fetchone()[0] == 0
        finally:
            cur.execute("DELETE FROM merge_serverkey WHERE label=%s", (name,))
            cur.execute("DELETE FROM merge_server WHERE name=%s", (name,))
            cur.close()
    finally:
        db.release_connection(conn)


def test_create_server_rolls_back_the_key_when_the_server_insert_fails(db):
    merge_servers.ensure_schema()
    name = "pytest-atomic-" + uuid.uuid4().hex
    key = "atomic-key-" + uuid.uuid4().hex
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        try:
            with pytest.raises(Exception):
                merge_servers.create_server(
                    name, "127.0.0.1", 80, "", key, created_by="x" * 101)
            cur.execute(
                "SELECT COUNT(*) FROM merge_serverkey WHERE label=%s", (name,))
            assert cur.fetchone()[0] == 0
            cur.execute(
                "SELECT COUNT(*) FROM merge_server WHERE name=%s", (name,))
            assert cur.fetchone()[0] == 0
        finally:
            cur.execute("DELETE FROM merge_serverkey WHERE label=%s", (name,))
            cur.execute("DELETE FROM merge_server WHERE name=%s", (name,))
            cur.close()
    finally:
        db.release_connection(conn)


class _BigResponse:
    status = 200

    def __init__(self, body):
        self.body = body
        self.offset = 0

    def read(self, size=-1):
        end = len(self.body)
        if size is not None and size >= 0:
            end = min(end, self.offset + size)
        chunk = self.body[self.offset:end]
        self.offset = end
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_a_truncated_http_body_is_an_error_not_a_success(monkeypatch):
    body = b"x" * (5_000_000 + 1)
    monkeypatch.setattr(
        merge_servers, "_open_request", lambda *args, **kwargs: _BigResponse(body))
    server = {"scheme": "http", "host": "127.0.0.1", "port": 80,
              "base_path": ""}
    code, data, err = merge_servers.http_call(
        server, "/api/merge/list", "token")
    assert code == 502
    assert isinstance(data, dict)
    assert data.get("error")
    assert "raw" not in data
    assert err


@pytest.mark.parametrize("body", [b"", b'{"status"', b"[]"])
def test_a_short_or_non_object_http_body_is_an_error(monkeypatch, body):
    monkeypatch.setattr(
        merge_servers, "_open_request", lambda *args, **kwargs: _BigResponse(body))
    server = {"scheme": "http", "host": "127.0.0.1", "port": 80,
              "base_path": ""}
    code, data, err = merge_servers.http_call(server, "/api/merge/status", "token")
    assert code == 502, body
    assert isinstance(data, dict) and data.get("error")
    assert err


def test_refresh_all_status_checks_servers_concurrently(monkeypatch):
    servers = [{"id": f"pytest-refresh-{i}", "server_uid": f"uid-{i}"}
               for i in range(5)]
    prune_calls = []

    def slow_refresh(server_id, timeout=4):
        time.sleep(0.2)
        return {"ok": True, "status": "connected"}

    monkeypatch.setattr(merge_servers, "list_servers", lambda: servers)
    monkeypatch.setattr(merge_servers, "prune_requests",
                        lambda: prune_calls.append(1))
    monkeypatch.setattr(merge_servers, "refresh_status", slow_refresh)
    started = time.monotonic()
    out = merge_servers.refresh_all_status(timeout=2)
    elapsed = time.monotonic() - started
    assert elapsed < 1
    assert list(out) == [s["id"] for s in servers]
    assert all(row["ok"] for row in out.values())
    assert len(prune_calls) == 1


def test_refresh_all_status_honors_an_overall_deadline(monkeypatch):
    servers = [{"id": f"pytest-deadline-{i}", "server_uid": f"uid-{i}"}
               for i in range(3)]

    def slow_refresh(server_id, timeout=4):
        time.sleep(0.5)
        return {"ok": True, "status": "connected"}

    monkeypatch.setattr(merge_servers, "list_servers", lambda: servers)
    monkeypatch.setattr(merge_servers, "prune_requests", lambda: 0)
    monkeypatch.setattr(merge_servers, "refresh_status", slow_refresh)
    monkeypatch.setattr(merge_servers, "update_server", lambda *a, **k: None)
    started = time.monotonic()
    out = merge_servers.refresh_all_status(timeout=0.1)
    elapsed = time.monotonic() - started
    assert elapsed < 0.5
    assert list(out) == [s["id"] for s in servers]
    assert all(not row["ok"] and row["status"] == "down"
               for row in out.values())


def test_prune_requests_removes_only_old_pending_and_denied(db):
    merge_servers.ensure_schema()
    prefix = "pytest-prune-old-" + uuid.uuid4().hex[:8] + "-"
    old_pending = prefix + "old-pending"
    old_denied = prefix + "old-denied"
    old_allowed = prefix + "old-allowed"
    recent_pending = prefix + "recent-pending"
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM merge_request WHERE server_uid LIKE %s",
                        (prefix + "%",))
            cur.executemany(
                """INSERT INTO merge_request
                       (server_uid, status, requested_at, last_seen)
                   VALUES (%s, %s, now() - interval '31 days',
                           now() - interval '31 days')""",
                [(old_pending, "pending"), (old_denied, "denied"),
                 (old_allowed, "allowed")])
            cur.execute(
                """INSERT INTO merge_request (server_uid, status)
                   VALUES (%s, 'pending')""", (recent_pending,))
            merge_servers.prune_requests(prefix)
            cur.execute(
                "SELECT server_uid FROM merge_request WHERE server_uid LIKE %s",
                (prefix + "%",))
            left = {row[0] for row in cur.fetchall()}
            assert old_pending not in left
            assert old_denied not in left
            assert old_allowed in left
            assert recent_pending in left
        finally:
            cur.execute("DELETE FROM merge_request WHERE server_uid LIKE %s",
                        (prefix + "%",))
            cur.close()
    finally:
        db.release_connection(conn)


def test_prune_requests_keeps_the_newest_200_pending(db):
    merge_servers.ensure_schema()
    prefix = "pytest-prune-cap-" + uuid.uuid4().hex[:8] + "-"
    uids = [prefix + f"{i:03d}" for i in range(205)]
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM merge_request WHERE server_uid LIKE %s",
                        (prefix + "%",))
            cur.executemany(
                """INSERT INTO merge_request
                       (server_uid, status, requested_at, last_seen)
                   VALUES (%s, 'pending',
                           now() + interval '1 day' + (%s * interval '1 second'),
                           now() + interval '1 day' + (%s * interval '1 second'))""",
                [(uid, i, i) for i, uid in enumerate(uids)])
            merge_servers.prune_requests(prefix)
            cur.execute(
                "SELECT server_uid FROM merge_request WHERE server_uid LIKE %s",
                (prefix + "%",))
            left = {row[0] for row in cur.fetchall()}
            assert len(left) == 200
            assert not any(uid in left for uid in uids[:5])
            assert all(uid in left for uid in uids[5:])
        finally:
            cur.execute("DELETE FROM merge_request WHERE server_uid LIKE %s",
                        (prefix + "%",))
            cur.close()
    finally:
        db.release_connection(conn)


def test_a_legacy_server_row_without_a_link_key_still_uses_the_old_key(db):
    """Rows created before per-link keys must keep working: their data calls
    fall back to the local identity key, which the peer already bound."""
    key = "legacy-row-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest legacy row", "127.0.0.1", 80, "", key)
    try:
        conn = db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE merge_server SET link_key_cipher='' WHERE id=%s",
                        (server_id,))
            conn.commit()
            cur.close()
        finally:
            db.release_connection(conn)
        row = merge_servers.get_server(server_id, True)
        assert row["link_key"] == ""
        token = merge_servers.make_server_token(row, subject="admin")
        assert merge_servers.verify_token(
            token, merge_servers.ensure_local_identity()["key"])
    finally:
        merge_servers.delete_server(server_id)
