"""The destructive half of management.py, tested without touching the host.

The real `--delete` path removes the configured PostgreSQL database, the
service and the checkout. These tests use recording fakes and temporary
directories so the SQL shape, the protected databases and the file cleanup are
pinned without giving the suite a way to erase the machine it runs on.
"""
import management


class FakeChannel:
    user = "postgres"

    def __init__(self, exists=True):
        self.exists = exists
        self.queries = []
        self.executed = []

    def query(self, sql, db=None):
        self.queries.append(sql)
        if "SELECT 1 FROM pg_database WHERE datname" in sql:
            return [[1]] if self.exists else []
        return []

    def execute(self, sql, db=None):
        self.executed.append(sql)
        if sql.startswith("DROP DATABASE"):
            self.exists = False


class FakeRoleChannel:
    user = "postgres"

    def __init__(self, is_super=False, owned=()):
        self.is_super = is_super
        self.owned = list(owned)
        self.queries = []
        self.executed = []

    def query(self, sql, db=None):
        self.queries.append(sql)
        if "SELECT rolsuper FROM pg_roles" in sql:
            return [[self.is_super]]
        if "SELECT datname FROM pg_database WHERE datdba" in sql:
            return [[name] for name in self.owned]
        return []

    def execute(self, sql, db=None):
        self.executed.append(sql)


def test_drop_database_terminates_sessions_and_drops_it():
    channel = FakeChannel()
    ok, detail = management._drop_configured_database(channel, "argus")
    assert ok is True
    assert "database 'argus' removed" in detail
    assert any("pg_terminate_backend" in sql for sql in channel.executed)
    assert any(sql.startswith('DROP DATABASE IF EXISTS "argus"')
               for sql in channel.executed)
    assert channel.exists is False


def test_drop_database_never_drops_a_postgres_system_database():
    channel = FakeChannel()
    ok, detail = management._drop_configured_database(channel, "postgres")
    assert ok is True
    assert "left alone" in detail
    assert channel.executed == []


def test_drop_database_is_idempotent_when_it_is_already_gone():
    channel = FakeChannel(exists=False)
    ok, detail = management._drop_configured_database(channel, "argus")
    assert ok is True
    assert "already gone" in detail
    assert channel.executed == []


def test_drop_role_skips_a_role_that_owns_another_database():
    channel = FakeRoleChannel(owned=("argus", "somebody_else"))
    ok, detail = management._drop_configured_role(channel, "argus", "argus")
    assert ok is True
    assert "shared role" in detail
    assert channel.executed == []


def test_drop_role_refuses_a_superuser():
    channel = FakeRoleChannel(is_super=True)
    ok, detail = management._drop_configured_role(channel, "argus", "argus")
    assert ok is True
    assert "superuser role" in detail
    assert channel.executed == []


def test_drop_role_removes_a_dedicated_role():
    channel = FakeRoleChannel()
    ok, detail = management._drop_configured_role(channel, "argus", "argus")
    assert ok is True
    assert "removed" in detail
    assert channel.executed == ['DROP ROLE IF EXISTS "argus"']


def test_local_state_cleanup_removes_secrets_and_keeps_other_files(tmp_path, monkeypatch):
    monkeypatch.setattr(management, "HERE", str(tmp_path))
    for name in (".env", "deploy.json", ".recovery", ".session_secret",
                 ".wallet_secret", ".vault_key", "id_ed25519",
                 "id_ed25519.pub"):
        (tmp_path / name).write_text("secret")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin")
    (tmp_path / "keep.py").write_text("source code")

    assert management._remove_local_state() is True
    for name in management.DELETE_LOCAL_STATE:
        assert not (tmp_path / name).exists()
    assert (tmp_path / "keep.py").read_text() == "source code"


def test_install_directory_removal_refuses_an_unexpected_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(management, "HERE", str(tmp_path))
    ok, detail = management._remove_install_directory()
    assert ok is False
    assert "refusing" in detail
    assert tmp_path.exists()


def test_install_directory_removal_removes_the_checkout(tmp_path, monkeypatch):
    install = tmp_path / "argus-management"
    install.mkdir()
    (install / "management.py").write_text("# marker\n")
    (install / ".env").write_text("secret\n")
    monkeypatch.setattr(management, "HERE", str(install))

    ok, detail = management._remove_install_directory()
    assert ok is True
    assert "removed" in detail
    assert not install.exists()


def test_staff_account_cleanup_only_accepts_generated_names():
    class StaffChannel:
        def query(self, sql, db=None):
            return [["argus_alice"], ["root"], ["argus_bad-name"],
                    ["argus_" + "x" * 40], ["ARGUS_UPPER"]]

    names = management._staff_os_accounts(StaffChannel(), "argus")
    assert names == ["argus_alice"]


def test_delete_mode_removes_database_service_and_checkout(tmp_path, monkeypatch):
    install = tmp_path / "argus-management"
    install.mkdir()
    (install / "management.py").write_text("# marker\n")
    (install / "deploy.json").write_text(
        '{"db_host":"127.0.0.1","db_port":5432,"db_user":"argus",'
        '"db_name":"argus","host":"127.0.0.1","port":8080,"base_path":""}\n')
    (install / ".env").write_text("DB_PASSWORD=secret\n")
    channel = FakeChannel()
    removed = []

    monkeypatch.setattr(management, "HERE", str(install))
    monkeypatch.setattr(management, "CONFIG_PATH", str(install / "deploy.json"))
    monkeypatch.setattr(management, "ENV_PATH", str(install / ".env"))
    monkeypatch.setattr(management, "VENV_DIR", str(install / ".venv"))
    monkeypatch.setattr(management, "UNIT_PATH", str(tmp_path / "not-installed.service"))
    monkeypatch.setattr(management, "TUNNEL_UNIT_PATH",
                        str(tmp_path / "not-installed-tunnel.service"))
    monkeypatch.setattr(management, "_delete_database_channel",
                        lambda cfg, yes: channel)
    monkeypatch.setattr(management, "_unit_active", lambda name: False)
    monkeypatch.setattr(management, "_stop_delete_service",
                        lambda name, path: (True, "stopped"))
    monkeypatch.setattr(management, "_drop_configured_role",
                        lambda ch, user, db: (True, "role left alone"))
    monkeypatch.setattr(management, "_remove_delete_service",
                        lambda name, path, best_effort=False: (
                            removed.append(name) or True, "removed"))

    assert management.delete_mode(assume_yes=True) == 0
    assert channel.exists is False
    assert "argus-management" in removed
    assert "argus-tunnel" in removed
    assert not install.exists()

