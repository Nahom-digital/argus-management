"""Download blocklist: panel install tree, PostgreSQL data, and host keys.

The merge download route resolves paths with no sandbox, so these checks are
what stops a linked peer from reading the vault key or raw database files.
"""
import os

import pytest

import System

INSTALL = os.path.dirname(os.path.abspath(System.__file__))


def test_vault_key_is_blocked():
    assert System._download_blocked(os.path.join(INSTALL, ".vault_key"))
    assert System._download_blocked("/home/someone/.vault_key")


def test_install_directory_is_blocked_as_a_tree():
    assert System._download_blocked(os.path.join(INSTALL, ".env"))
    assert System._download_blocked(os.path.join(INSTALL, "static_mgmt", "dash.css"))
    assert not System._download_blocked(INSTALL + "-other" + os.sep + "notes.txt")


@pytest.mark.parametrize("path", [
    "/var/lib/postgresql/16/main/base/1/2610",
    "/var/lib/pgsql/data/base/1/2610",
    "/var/db/postgres/data/base/1/2610",
    "/usr/local/pgsql/data/base/1/2610",
])
def test_database_data_directories_are_blocked(path):
    assert System._download_blocked(path)


@pytest.mark.parametrize("path", [
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
])
def test_ssh_host_private_keys_are_blocked(path):
    assert System._download_blocked(path)


@pytest.mark.parametrize("name", [".pgpass", ".netrc", "authorized_keys"])
def test_extra_credential_files_are_blocked(tmp_path, name):
    assert System._download_blocked(str(tmp_path / name))


def test_an_ordinary_file_is_still_allowed(tmp_path):
    target = tmp_path / "report.txt"
    target.write_text("public", encoding="utf-8")
    full, reason = System.resolve_download(str(target))
    assert reason is None
    assert full == os.path.realpath(str(target))


def test_a_symlink_to_the_vault_key_is_blocked(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    vault = real / ".vault_key"
    vault.write_text("fernet-key", encoding="utf-8")
    link = tmp_path / "innocent.txt"
    os.symlink(vault, link)
    full, reason = System.resolve_download(str(link))
    assert full is None
    assert reason == "blocked"


def test_the_linked_download_route_actually_applies_the_blocklist(
        tmp_path, monkeypatch):
    """The helper tests above are only useful if the route calls them."""
    from fastapi.testclient import TestClient
    import panel

    secret = tmp_path / ".vault_key"
    secret.write_text("fernet-key", encoding="utf-8")
    normal = tmp_path / "report.txt"
    normal.write_text("public", encoding="utf-8")

    async def fake_incoming(request, required_scope=None, purpose="api",
                            allow_pending=False):
        return {"iss": "pytest", "scopes": ["disk"], "role": "admin"}, None

    monkeypatch.setattr(panel, "_merge_incoming", fake_incoming)
    with TestClient(panel.app, client=("127.0.0.1", 51061)) as client:
        blocked = client.get("/api/merge/download",
                             params={"path": str(secret)})
        assert blocked.status_code == 403, blocked.text
        allowed = client.get("/api/merge/download",
                             params={"path": str(normal)})
        assert allowed.status_code == 200, allowed.text
        assert allowed.content == b"public"


def test_install_tree_blocks_even_a_normal_named_file():
    # deploy.json has no blocked extension or name, so only the tree rule can
    # stop it. This proves the install-directory prefix is doing the work.
    assert System._download_blocked(os.path.join(INSTALL, "deploy.json"))


def test_a_symlink_inside_the_install_tree_is_blocked(tmp_path):
    link = tmp_path / "notes.txt"
    os.symlink(os.path.join(INSTALL, "deploy.json"), link)
    full, reason = System.resolve_download(str(link))
    assert full is None and reason == "blocked"


def test_a_sibling_of_the_database_directory_is_not_blocked():
    assert not System._download_blocked("/var/lib/postgresql2/notes.txt")


@pytest.mark.parametrize("name", [
    ".vault_key.bak", ".pgpass.old", ".netrc.bak", "authorized_keys2",
    "ssh_host_rsa_key.old", "id_rsa.bak",
])
def test_backups_of_credential_files_are_blocked(tmp_path, name):
    assert System._download_blocked(str(tmp_path / name))
