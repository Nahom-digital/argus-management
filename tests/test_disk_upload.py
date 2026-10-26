"""The upload endpoint and the disk upload grant.

Uploads write as the panel user, so the tests exercise the two boundaries that
matter: the grant itself, and the path check that keeps a scoped account inside
its own tree. The bytes go to pytest's temporary directory, never a real home.
"""
import os

import pytest

import panel
import panel_users as pu
import System
from fastapi.testclient import TestClient

STAFF = "pytest_upload_user"
PASSWORD = "Upl04d!Pass"


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51056)) as c:
        yield c


def _staff_with(conn, grants):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, grants, "admin")
    panel._forget_user_epoch(STAFF)


def _sign_in(client, username):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(username))


def _drop(conn):
    pu.delete_user(conn, STAFF)
    panel._forget_user_epoch(STAFF)


def _upload(client, folder, name, data=b"hello"):
    return client.post("/api/system/upload",
                       params={"path": str(folder), "name": name},
                       content=data)


def test_upload_is_refused_without_the_upload_grant(client, conn, tmp_path):
    _staff_with(conn, {"disk_scope": "full"})
    try:
        _sign_in(client, STAFF)
        r = _upload(client, tmp_path, "nope.txt")
        assert r.status_code == 403, r.text
        assert not (tmp_path / "nope.txt").exists()
    finally:
        _drop(conn)


def test_upload_writes_the_file_into_the_current_folder(client, conn, tmp_path):
    _staff_with(conn, {"disk_scope": "full", "disk_upload": True})
    try:
        _sign_in(client, STAFF)
        r = _upload(client, tmp_path, "hello.txt", b"hello world")
        assert r.status_code == 200, r.text
        assert (tmp_path / "hello.txt").read_bytes() == b"hello world"
        assert r.json()["size"] == 11
    finally:
        _drop(conn)


def test_upload_never_replaces_an_existing_file(client, conn, tmp_path):
    target = tmp_path / "keep.txt"
    target.write_text("original", encoding="utf-8")
    _staff_with(conn, {"disk_scope": "full", "disk_upload": True})
    try:
        _sign_in(client, STAFF)
        r = _upload(client, tmp_path, "keep.txt", b"replacement")
        assert r.status_code == 409, r.text
        assert target.read_text(encoding="utf-8") == "original"
    finally:
        _drop(conn)


def test_upload_refuses_a_name_with_a_path_in_it(client, conn, tmp_path):
    _staff_with(conn, {"disk_scope": "full", "disk_upload": True})
    try:
        _sign_in(client, STAFF)
        r = _upload(client, tmp_path, "../escape.txt")
        assert r.status_code == 400, r.text
        assert not (tmp_path.parent / "escape.txt").exists()
    finally:
        _drop(conn)


def test_upload_enforces_the_size_limit_before_writing(client, conn, tmp_path, monkeypatch):
    monkeypatch.setattr(System, "MAX_UPLOAD_BYTES", 4)
    _staff_with(conn, {"disk_scope": "full", "disk_upload": True})
    try:
        _sign_in(client, STAFF)
        r = _upload(client, tmp_path, "big.bin", b"12345")
        assert r.status_code == 413, r.text
        assert not (tmp_path / "big.bin").exists()
    finally:
        _drop(conn)


def test_upload_target_must_stay_inside_the_sandbox(tmp_path):
    sandbox = tmp_path / "home" / "argus_someone"
    sandbox.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    directory, dest, reason = System.resolve_upload(
        str(outside), "x.txt", root=str(sandbox))
    assert (directory, dest, reason) == (None, None, "blocked")
    (sandbox / "escape").symlink_to(outside, target_is_directory=True)
    directory, dest, reason = System.resolve_upload(
        str(sandbox / "escape"), "x.txt", root=str(sandbox))
    assert (directory, dest, reason) == (None, None, "blocked")


def test_upload_refuses_names_that_would_escape_the_directory(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    for name in ("", ".", "..", "a/b.txt", "a\\b.txt", "x" * 256):
        directory, dest, reason = System.resolve_upload(
            str(sandbox), name, root=str(sandbox))
        assert directory is None and dest is None
        assert reason in ("bad_name", "name_too_long"), name


def test_an_existing_symlink_is_not_followed_or_replaced(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (sandbox / "link.txt").symlink_to(outside)
    directory, dest, reason = System.resolve_upload(
        str(sandbox), "link.txt", root=str(sandbox))
    assert (directory, dest, reason) == (None, None, "exists")


def test_finish_upload_never_overwrites(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("keep", encoding="utf-8")
    staging = tmp_path / ".argus-upload-test"
    staging.write_text("new", encoding="utf-8")
    ok, reason = System.finish_upload(str(staging), str(target))
    assert ok is False and reason == "exists"
    assert target.read_text(encoding="utf-8") == "keep"


def test_a_staff_upload_cannot_target_root_or_a_system_tree():
    for path in ("/root", "/etc"):
        directory, dest, reason = System.resolve_upload(
            path, "argus-pytest-upload", staff=True)
        assert (directory, dest, reason) == (None, None, "blocked"), path


def test_admin_can_use_the_system_paths_a_staff_account_cannot():
    """The guard is about the panel writing as root for staff, not about
    restricting the admin, who already has a root terminal."""
    if not os.path.isdir("/root"):
        pytest.skip("this machine has no readable /root")
    directory, dest, reason = System.resolve_upload(
        "/root", f"argus-pytest-{os.getpid()}", staff=False)
    assert reason is None, reason
    assert dest == f"/root/argus-pytest-{os.getpid()}"


def test_the_dashboard_has_an_upload_button_left_of_refresh(client):
    _sign_in(client, "admin")
    page = client.get("/").text
    assert 'id="srv-upload-btn"' in page
    assert 'id="fb-upload-input"' in page
    assert page.index('id="srv-upload-btn"') < \
        page.index('onclick="refreshServerDetail()"')


def test_the_file_browser_keeps_the_suffix_visible():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "static_mgmt", "management.js"),
              encoding="utf-8") as fh:
        js = fh.read()
    with open(os.path.join(root, "static_mgmt", "dash.css"),
              encoding="utf-8") as fh:
        css = fh.read()
    assert "fb-stem" in js and "fb-ext" in js
    assert ".fb-stem" in css and "text-overflow:ellipsis" in css
