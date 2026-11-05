"""`--upgrade` must work from a copied install and from a root-run checkout.

The upgrade path used to assume the directory was a clone and that Git was
willing to read it. A copy without `.git` and a checkout owned by the user who
cloned it (but run by root) both produced a misleading "not a git checkout"
error. These tests pin down the safe-directory bypass and the in-place
conversion.
"""
import os
import shutil
import subprocess

import pytest

import management


GIT = shutil.which("git")


def test_git_commands_trust_only_this_install_directory(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=600):
        calls.append((cmd, timeout))
        return 0, "true\n", ""

    monkeypatch.setattr(management, "run", fake_run)
    rc, out, _ = management.git("rev-parse", "--is-inside-work-tree", timeout=7)

    assert rc == 0
    assert out == "true\n"
    assert calls == [(
        [
            "git",
            "-c",
            f"safe.directory={os.path.realpath(management.HERE)}",
            "-C",
            management.HERE,
            "rev-parse",
            "--is-inside-work-tree",
        ],
        7,
    )]


def test_is_git_checkout_requires_this_directory_to_be_the_repo_root(
        tmp_path, monkeypatch):
    install = tmp_path / "install"
    parent = tmp_path / "parent"
    monkeypatch.setattr(management, "HERE", str(install))
    monkeypatch.setattr(management, "git",
                        lambda *args, **kwargs: (0, f"{parent}\n", ""))

    assert management.is_git_checkout() is False

    monkeypatch.setattr(management, "git",
                        lambda *args, **kwargs: (0, f"{install}\n", ""))
    assert management.is_git_checkout() is True


def test_upgrade_attempts_to_adopt_a_copied_install(monkeypatch):
    adopted = []
    monkeypatch.setattr(management.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(management, "is_git_checkout", lambda: False)
    monkeypatch.setattr(management, "_has_git_metadata", lambda: False)
    monkeypatch.setattr(management, "adopt_git_checkout",
                        lambda: adopted.append(True) or False)

    assert management.upgrade_mode() == 1
    assert adopted == [True]


def _run_git(cwd, *args):
    return subprocess.run(
        ["git", "-C", str(cwd)] + list(args),
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.mark.skipif(not GIT, reason="git is required for the upgrade path")
def test_adopt_copied_install_keeps_deployment_files(tmp_path, monkeypatch):
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(["git", "init", "-q", str(origin)], check=True)
    _run_git(origin, "symbolic-ref", "HEAD", "refs/heads/main")
    (origin / "management.py").write_text("# new upstream version\n")
    (origin / "new_file.py").write_text("new upstream file\n")
    _run_git(origin, "add", "-A")
    _run_git(origin, "-c", "user.name=Test", "-c", "user.email=test@example.com",
             "commit", "-q", "-m", "upstream")
    upstream_head = _run_git(origin, "rev-parse", "HEAD").strip()

    copied = tmp_path / "copied"
    copied.mkdir()
    (copied / "management.py").write_text("# old copied version\n")
    (copied / "local_only.py").write_text("local source edit\n")
    (copied / "deploy.json").write_text('{"db_name": "argus"}\n')
    (copied / ".env").write_text("DB_PASSWORD=do-not-touch\n")

    monkeypatch.setattr(management, "HERE", str(copied))
    monkeypatch.setattr(management, "UPGRADE_REPO_URL", str(origin))
    monkeypatch.setattr(management, "UPGRADE_REPO_BRANCH", "main")

    assert management.adopt_git_checkout() is True

    # The source is now the upstream tree, with local-only source removed.
    assert (copied / "management.py").read_text() == "# new upstream version\n"
    assert (copied / "new_file.py").read_text() == "new upstream file\n"
    assert not (copied / "local_only.py").exists()

    # Deployment state is excluded from the snapshot and survives the reset.
    assert (copied / "deploy.json").read_text() == '{"db_name": "argus"}\n'
    assert (copied / ".env").read_text() == "DB_PASSWORD=do-not-touch\n"

    assert management.is_git_checkout()
    assert _run_git(copied, "rev-parse", "HEAD").strip() == upstream_head
    assert _run_git(copied, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"
    assert _run_git(
        copied, "rev-parse", "--verify",
        f"{management.UPGRADE_BACKUP_BRANCH}^{{commit}}",
    ).strip()
