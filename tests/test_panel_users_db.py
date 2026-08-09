"""Storage and resolution of grants against the real database.

These deliberately use grant sets that never provision an OS account, so the
suite runs without root. OS account provisioning is exercised by hand during
deployment, not here.
"""
import pytest

import panel_users as pu

USER = "pytest_grants_user"
PASSWORD = "Str0ng!Pass"
NEW_PASSWORD = "An0ther!Pass"


@pytest.fixture
def staff(conn):
    """A staff row that is always torn down, even on assertion failure."""
    pu.delete_user(conn, USER)
    pu.create_user(conn, USER, PASSWORD, {"db_read": True, "svc_status": True}, "admin")
    try:
        yield conn
    finally:
        pu.delete_user(conn, USER)


def test_create_stores_a_complete_normalized_grant_set(staff):
    u = pu.get_user(staff, USER)
    assert set(u["grants"]) == set(pu.GRANT_KEYS)
    assert u["grants"]["db_read"] is True
    assert u["grants"]["svc_status"] is True
    assert u["grants"]["db_write"] is False
    assert u["grants"]["disk_scope"] == "none"


def test_update_replaces_the_whole_grant_set(staff):
    pu.update_user(staff, USER, grants={"db_read": True, "db_write": True})
    g = pu.get_user(staff, USER)["grants"]
    assert g["db_write"] is True
    # svc_status was in the old set and absent from the new one, so it is gone.
    assert g["svc_status"] is False


def test_update_cannot_be_tricked_into_an_unknown_grant(staff):
    pu.update_user(staff, USER, grants={"db_read": True, "is_admin": True,
                                        "terminal": "wheel"})
    g = pu.get_user(staff, USER)["grants"]
    assert "is_admin" not in g
    assert g["terminal"] == "none"


def test_password_reset_bumps_only_that_users_epoch(staff):
    before = pu.auth_epoch_for(staff, USER)
    pu.update_user(staff, USER, password=NEW_PASSWORD)
    assert pu.auth_epoch_for(staff, USER) == before + 1
    assert pu.verify_login(staff, USER, NEW_PASSWORD) is not None
    assert pu.verify_login(staff, USER, PASSWORD) is None


def test_withdrawing_a_grant_bumps_the_epoch(staff):
    before = pu.auth_epoch_for(staff, USER)
    pu.update_user(staff, USER, grants={"db_read": True, "db_write": True})
    # svc_status was withdrawn, so any live session must be re-evaluated.
    assert pu.auth_epoch_for(staff, USER) == before + 1


def test_widening_grants_leaves_the_session_alone(staff):
    before = pu.auth_epoch_for(staff, USER)
    pu.update_user(staff, USER, grants={"db_read": True, "svc_status": True,
                                        "logs_access": True})
    assert pu.auth_epoch_for(staff, USER) == before


def test_staff_resolves_to_exactly_its_grants(staff):
    p = pu.resolve_permissions(staff, USER)
    assert p["role"] == "staff"
    assert p["db_read"] is True
    assert p["db_write"] is False
    assert p["disk_scope"] == "none"
    assert set(pu.GRANT_KEYS) <= set(p)


def test_admin_resolves_to_every_grant(conn):
    p = pu.resolve_permissions(conn, "admin")
    assert p["role"] == "admin"
    assert p["terminal"] == pu.TERMINAL_ROOT
    assert p["disk_scope"] == pu.DISK_FULL
    assert all(p[k] is True for k in pu.GRANT_KEYS if k not in pu.CHOICE_KEYS)


def test_unknown_identity_resolves_to_nothing(conn):
    p = pu.resolve_permissions(conn, "no_such_person")
    assert p["role"] == "none"
    assert p["disk_scope"] == "none"
    assert p["terminal"] == "none"
    assert not any(p[k] for k in pu.GRANT_KEYS if k not in pu.CHOICE_KEYS)


def test_list_users_exposes_grants(staff):
    row = next(r for r in pu.list_users(staff) if r["username"] == USER)
    assert row["grants"]["db_read"] is True
    assert row["full_name"] == ""


def test_legacy_row_is_backfilled_conservatively(conn):
    """A row written by the old schema keeps its meaning, except that delete
    is withheld: nobody silently gains a destructive grant."""
    cur = conn.cursor()
    pu.delete_user(conn, USER)
    pu.ensure_table(conn)
    cur.execute(
        """INSERT INTO panel_user
           (username, password_hash, terminal_access, database_access,
            logs_access, disk_access, created_by, grants)
           VALUES (%s, %s, 'none', TRUE, TRUE, TRUE, 'admin', '{}'::jsonb)""",
        (USER, recovery_hash()),
    )
    conn.commit()
    cur.close()
    try:
        # ensure_table is a no-op after the first call in a process, so the
        # migration has to be asked for explicitly here.
        pu.ensure_table(conn, force=True)
        g = pu.get_user(conn, USER)["grants"]
        assert g["db_read"] is True
        assert g["db_write"] is False
        assert g["logs_access"] is True
        assert g["disk_scope"] == "full"
        assert g["disk_download"] is True
        assert g["disk_delete"] is False
    finally:
        pu.delete_user(conn, USER)


def recovery_hash():
    import recovery
    return recovery.hash_password(PASSWORD)
