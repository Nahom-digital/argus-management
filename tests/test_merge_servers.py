"""Unit coverage for the parts of panel linking that must not drift.

The network side is exercised by hand between two installs; these pin the
parsing, the token format and the one-directional approval rule that keeps a
pending or allowed incoming request from silently approving an outgoing link.
"""
import uuid

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
    assert merge_servers.verify_token(token[:-1] + ("A" if token[-1] != "A" else "B"),
                                      key) is None
    assert merge_servers.verify_token(token, key + "-wrong") is None


def test_an_expired_token_is_refused():
    token = merge_servers.sign_token("test-key", {"iss": "panel-a"}, ttl=-1)
    assert merge_servers.verify_token(token, "test-key") is None


def test_make_server_token_still_works_after_get_server_strips_the_key(db):
    """Route handlers deliberately read a server without its key. Minting a
    token has to look the key up instead of assuming the field is present."""
    key = "stripped-row-key-" + uuid.uuid4().hex
    server_id = merge_servers.create_server(
        "pytest linked", "127.0.0.1", 80, "", key)
    try:
        row = merge_servers.get_server(server_id, False)
        assert "key" not in row and "key_cipher" not in row
        token = merge_servers.make_server_token(row, subject="admin")
        data = merge_servers.verify_token(token, key)
        assert data and data["sub"] == "admin"
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
