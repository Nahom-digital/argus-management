"""Secret files must stay private, and replacing the Argus SSH key must not
leave the old one authorized."""
import os
import stat

import panel
import ssh_vault

USER_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIuserkey"
            " user@example\n")
OLD_ARGUS = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIoldargus"
             " argus-management\n")
NEW_ARGUS = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInewargus"
             " argus-management\n")


def test_existing_secret_is_tightened_and_kept(tmp_path, monkeypatch):
    path = tmp_path / ".session_secret"
    path.write_text("existing-secret\n")
    os.chmod(path, 0o644)
    monkeypatch.setattr(panel, "_PROJECT_DIR", str(tmp_path))

    assert panel._load_jwt_secret() == "existing-secret"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_new_secret_is_created_private(tmp_path, monkeypatch):
    path = tmp_path / ".session_secret"
    monkeypatch.setattr(panel, "_PROJECT_DIR", str(tmp_path))

    secret = panel._load_jwt_secret()

    assert path.read_text() == secret
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_read_only_chmod_failure_still_returns_the_secret(tmp_path, monkeypatch):
    path = tmp_path / ".session_secret"
    path.write_text("existing-secret")
    os.chmod(path, 0o644)
    monkeypatch.setattr(panel, "_PROJECT_DIR", str(tmp_path))

    def refuse(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(os, "chmod", refuse)

    assert panel._load_jwt_secret() == "existing-secret"


def test_strip_managed_keys_removes_only_the_argus_line():
    text = USER_KEY + "\n" + OLD_ARGUS + "ssh-rsa AAAAB3Nza user argus-management-extra\n"

    cleaned = ssh_vault._strip_managed_keys(text)

    assert cleaned == (USER_KEY + "\n"
                       + "ssh-rsa AAAAB3Nza user argus-management-extra\n")


def test_strip_managed_keys_is_idempotent_and_keeps_line_endings():
    text = USER_KEY.replace("\n", "\r\n") + OLD_ARGUS.rstrip("\n") + "\r\n"

    once = ssh_vault._strip_managed_keys(text)

    assert once == USER_KEY.replace("\n", "\r\n")
    assert ssh_vault._strip_managed_keys(once) == once


def test_new_key_replaces_the_old_argus_key_but_not_user_keys(tmp_path, monkeypatch):
    home = tmp_path / "home"
    auth_dir = home / ".ssh"
    auth_dir.mkdir(parents=True)
    auth_file = auth_dir / "authorized_keys"
    original = USER_KEY + "\n" + OLD_ARGUS
    auth_file.write_text(original)
    monkeypatch.setattr(ssh_vault, "_target_home", lambda username="root": (str(home), 0, 0))
    monkeypatch.setattr(ssh_vault, "ensure_key_login_possible",
                        lambda username="root": (True, ""))
    monkeypatch.setattr(ssh_vault, "verify_key_login",
                        lambda username="root": (True, "verified"))

    report = ssh_vault.install_public_key(NEW_ARGUS.strip())

    assert auth_file.read_text() == USER_KEY + "\n" + NEW_ARGUS
    assert "key was already authorized" not in report["steps"]
    assert report["installed"] is True


def test_current_argus_key_is_left_alone(tmp_path, monkeypatch):
    home = tmp_path / "home"
    auth_dir = home / ".ssh"
    auth_dir.mkdir(parents=True)
    auth_file = auth_dir / "authorized_keys"
    auth_file.write_text(USER_KEY + NEW_ARGUS)
    os.chmod(auth_file, 0o644)
    monkeypatch.setattr(ssh_vault, "_target_home", lambda username="root": (str(home), 0, 0))
    monkeypatch.setattr(ssh_vault, "ensure_key_login_possible",
                        lambda username="root": (True, ""))
    monkeypatch.setattr(ssh_vault, "verify_key_login",
                        lambda username="root": (True, "verified"))

    before = auth_file.stat().st_mtime_ns
    report = ssh_vault.install_public_key(NEW_ARGUS.strip())

    assert auth_file.read_text() == USER_KEY + NEW_ARGUS
    assert auth_file.stat().st_mtime_ns == before
    assert "key was already authorized" in report["steps"]
