"""Installing missing packages from the panel.

The install path runs a package manager as root, so what matters here is that a
request can only ever name a component this module already knows, that the
package list comes from the module and never from the request, and that a
machine which cannot escalate says so instead of hanging on a password prompt.
"""
import pytest

import panel
import provision
from fastapi.testclient import TestClient

STAFF = "pytest_prov_user"
PASSWORD = "Pr0vision!Pass"


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51041)) as c:
        yield c


@pytest.fixture(scope="module", autouse=True)
def staff(db):
    import panel_users as pu
    conn = db.get_connection()
    try:
        pu.delete_user(conn, STAFF)
        pu.create_user(conn, STAFF, PASSWORD, {}, "admin")
        panel._forget_user_epoch(STAFF)
        yield
        pu.delete_user(conn, STAFF)
    finally:
        db.release_connection(conn)


def as_user(client, name):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(name))


# --- the registry ----------------------------------------------------------- #

def test_every_component_names_its_own_packages_and_check():
    """A component is a fixed recipe. Nothing about it is assembled at request
    time, which is what keeps a request off the command line."""
    for key, spec in provision.COMPONENTS.items():
        assert spec["packages"], f"{key} has nothing to install"
        for alternative in spec["packages"]:
            assert isinstance(alternative, tuple)
            for name in alternative:
                assert isinstance(name, str) and name
                # A package name is a package name. Anything a shell would find
                # interesting has no business in this table.
                assert all(ch.isalnum() or ch in ".-+" for ch in name), name
        assert callable(spec["check"])


def test_a_component_nobody_defined_is_not_installable():
    ok, detail = provision.ensure("rm -rf /")
    assert ok is False
    assert detail == "unknown component"


def test_missing_only_reports_components_that_are_really_absent():
    for key in provision.missing():
        assert not provision.COMPONENTS[key]["check"]()


# --- the endpoint ----------------------------------------------------------- #

def test_a_staff_account_cannot_install_anything(client):
    as_user(client, STAFF)
    assert client.post("/api/system/install", json={"component": "compose"}).status_code == 403
    assert client.get("/api/system/install").status_code == 403


def test_a_component_name_that_is_not_in_the_registry_is_refused(client):
    """The one place a string from a request meets this module. It is looked up,
    never passed through."""
    as_user(client, "admin")
    for payload in ({"component": "bash; rm -rf /"}, {"component": "postgresql"},
                    {"components": ["docker-compose-plugin"]}, {}, {"components": []}):
        r = client.post("/api/system/install", json=payload)
        assert r.status_code == 400, payload
        assert "install" in r.json()["error"]


def test_the_state_endpoint_says_what_is_missing(client):
    as_user(client, "admin")
    d = client.get("/api/system/install").json()
    assert set(d["missing"]) <= set(provision.COMPONENTS)
    assert isinstance(d["can_install"], bool)
    assert isinstance(d["busy"], bool)


def test_escalation_never_asks_for_a_password():
    """A background job has nobody to type at it, so sudo is only ever tried
    with -n. A machine that would prompt counts as one that cannot."""
    prefix = provision.escalation()
    assert prefix is None or prefix == [] or prefix == ["sudo", "-n"]


# --- what mail reports when something is missing ---------------------------- #

def test_mail_offers_to_install_rather_than_naming_a_package():
    """The old message told the operator to go and install a package. If the
    panel can do it, the status has to say so, because that is what the page
    turns into a button."""
    import mailcow
    status = mailcow.status()
    assert "needs" in status and "can_install" in status
    for problem in status["problems"]:
        assert "docker-compose-plugin" not in problem
