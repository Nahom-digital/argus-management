"""The command-line flags management.py documents and accepts.

Every flag the entry point understands has to appear in the usage text, and
each one routes to its own mode. These run main() with the modes stubbed out,
so nothing here touches the database, the service or the real configuration.
"""
import sys

import pytest

import management


def test_every_flag_the_entry_point_knows_is_documented():
    for flag in ("--service", "--upgrade", "--update", "--serve", "--status",
                 "--recovery-codes", "--setup", "--help"):
        assert flag in management.USAGE, flag


def test_update_runs_the_wizard(monkeypatch):
    called = []
    monkeypatch.setattr(management, "wizard", lambda: called.append("wizard"))
    monkeypatch.setattr(sys, "argv", ["management.py", "--update"])
    management.main()
    assert called == ["wizard"]


def test_upgrade_still_runs_upgrade_mode(monkeypatch):
    called = []
    monkeypatch.setattr(management, "upgrade_mode",
                        lambda: called.append("upgrade") or 0)
    monkeypatch.setattr(sys, "argv", ["management.py", "--upgrade"])
    with pytest.raises(SystemExit):
        management.main()
    assert called == ["upgrade"]
