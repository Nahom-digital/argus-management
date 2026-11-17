"""Authorization checks for the receiving side of a linked-server upload.

The role in the signed token decides whether the root-owned upload path uses
the staff blocklist. A staff account an admin gave the disk scope must not be
able to write into /etc just because the request arrives over a server link.
"""
import os
import uuid

import pytest
from fastapi.testclient import TestClient

import panel
import System


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51058)) as c:
        yield c


def _incoming(data):
    async def fake(request, required_scope=None, purpose="api",
                   allow_pending=False):
        assert required_scope == "disk"
        return data, None
    return fake


def _spy_resolver(monkeypatch):
    seen = []
    real = System.resolve_upload

    def spy(path, name, root=None, staff=False):
        seen.append((path, name, root, staff))
        return real(path, name, root, staff)

    monkeypatch.setattr(System, "resolve_upload", spy)
    return seen


def _name():
    return "argus-pytest-merge-" + uuid.uuid4().hex


def test_the_resolver_refuses_a_staff_upload_into_protected_directories():
    name = _name()
    for path in ("/etc", "/usr", "/root", "/var/spool/cron"):
        assert System.resolve_upload(path, name, None, staff=True) == \
            (None, None, "blocked"), path


def _protected_dir(monkeypatch, tmp_path):
    """Use a temporary protected prefix instead of writing near real /etc.

    The production prefix tuple is tested separately (without writing); this
    keeps the route test honest and safe on every machine.
    """
    guarded = tmp_path / "guarded"
    guarded.mkdir()
    monkeypatch.setattr(
        System, "_UPLOAD_STAFF_DENY_PREFIXES",
        System._real_prefixes((str(guarded),)))
    return guarded


def test_a_staff_disk_token_cannot_upload_into_a_protected_directory(
        client, monkeypatch, tmp_path):
    guarded = _protected_dir(monkeypatch, tmp_path)
    seen = _spy_resolver(monkeypatch)
    monkeypatch.setattr(panel, "_merge_incoming",
                        _incoming({"role": "staff", "scopes": ["disk"]}))
    name = _name()
    r = client.post("/api/merge/upload",
                    params={"path": str(guarded), "name": name},
                    content=b"payload")
    assert r.status_code == 403, r.text
    assert seen == [(str(guarded), name, None, True)]
    assert not os.path.lexists(os.path.join(str(guarded), name))


def test_a_token_without_a_role_is_treated_as_staff(client, monkeypatch,
                                                     tmp_path):
    guarded = _protected_dir(monkeypatch, tmp_path)
    seen = _spy_resolver(monkeypatch)
    monkeypatch.setattr(panel, "_merge_incoming",
                        _incoming({"scopes": ["disk"]}))
    name = _name()
    r = client.post("/api/merge/upload",
                    params={"path": str(guarded), "name": name},
                    content=b"payload")
    assert r.status_code == 403, r.text
    assert seen == [(str(guarded), name, None, True)]
    assert not os.path.lexists(os.path.join(str(guarded), name))


def test_an_admin_token_still_uses_the_unrestricted_upload_policy(
        client, monkeypatch, tmp_path):
    seen = _spy_resolver(monkeypatch)
    monkeypatch.setattr(panel, "_merge_incoming",
                        _incoming({"role": "admin", "scopes": ["disk"]}))
    name = _name()
    r = client.post("/api/merge/upload",
                    params={"path": str(tmp_path), "name": name},
                    content=b"payload")
    assert r.status_code == 200, r.text
    assert seen == [(str(tmp_path), name, None, False)]
    assert (tmp_path / name).read_bytes() == b"payload"


def test_a_real_signed_staff_token_cannot_upload_into_a_protected_directory(
        client, db, monkeypatch, tmp_path):
    """End-to-end: the role comes from a token the real verifier accepts, not
    from a stubbed _merge_incoming. A staff claim keeps the blocklist."""
    uid = "pytest-upload-" + uuid.uuid4().hex
    peer_key = "pytest-upload-key-" + uuid.uuid4().hex
    panel.merge_servers.record_request(uid, "upload-peer", "127.0.0.1",
                                       link_key=peer_key)
    panel.merge_servers.decide_request(uid, True, "pytest")
    ident = panel.merge_servers.ensure_local_identity()
    token = panel.merge_servers.sign_token(peer_key, {
        "iss": uid, "aud": ident["server_uid"], "sub": "bob",
        "role": "staff", "scopes": ["disk"], "purpose": "api"})
    guarded = tmp_path / "guarded"
    guarded.mkdir()
    monkeypatch.setattr(
        System, "_UPLOAD_STAFF_DENY_PREFIXES",
        System._real_prefixes((str(guarded),)))
    name = _name()
    try:
        r = client.post("/api/merge/upload",
                        params={"path": str(guarded), "name": name},
                        content=b"payload",
                        headers={"Authorization": "Bearer " + token})
        assert r.status_code == 403, r.text
        assert not (guarded / name).exists()
    finally:
        conn = db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM merge_request WHERE server_uid=%s", (uid,))
            conn.commit()
            cur.close()
        finally:
            db.release_connection(conn)
