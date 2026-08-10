"""Mail: who can read what, and what "internal" is allowed to mean.

Two properties matter more than the rest and both are asserted here against the
real endpoints. A message the sender was told stayed inside this system must not
have left it, and one account must never see another account's mail, no matter
what it asks for.
"""
import pytest

import DB
import mail
import mailcow
import panel
import panel_users as pu
from fastapi.testclient import TestClient

DOMAIN = "pytest-mail.test"
ALICE, BOB = "pytest_mail_alice", "pytest_mail_bob"
PASSWORD = "M4ilTest!pass"


def _wipe(conn):
    cur = conn.cursor()
    cur.execute("DELETE FROM mail_message WHERE from_addr LIKE %s OR to_addr LIKE %s",
                (f"%@{DOMAIN}", f"%@{DOMAIN}"))
    cur.execute("DELETE FROM mail_box WHERE address LIKE %s", (f"%@{DOMAIN}",))
    cur.execute("DELETE FROM mail_config")
    conn.commit()
    cur.close()


@pytest.fixture
def client(conn):
    mail.ensure_schema(conn)
    _wipe(conn)
    for name in (ALICE, BOB):
        pu.delete_user(conn, name)
        pu.create_user(conn, name, PASSWORD, {}, "admin")
        panel._forget_user_epoch(name)
    with TestClient(panel.app, client=("127.0.0.1", 51041)) as c:
        yield c
    _wipe(conn)
    for name in (ALICE, BOB):
        pu.delete_user(conn, name)


def _as(client, username):
    # No cookie path: these requests use the bare paths nginx forwards, and a
    # cookie scoped to MGMT_BASE would not be sent with them.
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(username))


def _setup(client, conn):
    """A configured system with an address for each of the two accounts."""
    _as(client, "admin")
    client.post("/api/mail/domain", json={"domain": DOMAIN})
    for local, owner in (("alice", ALICE), ("bob", BOB)):
        client.post("/api/mail/box", json={"local_part": local, "owner": owner,
                                           "full_name": local.title()})


# --------------------------------------------------------------- validation
@pytest.mark.parametrize("local", ["alice", "a", "first.last", "a_b-c", "x+tag",
                                   "sales2024"])
def test_a_reasonable_address_is_accepted(local):
    assert mail.local_part_problem(local) == ""


@pytest.mark.parametrize("local", [
    "", " ", "-alice", "alice-", ".alice", "al ice", "a" * 65,
    "alice@example.com", "alice\r\nBcc: x@y.z", "../../etc/passwd", "alice;id",
])
def test_an_address_that_could_carry_a_header_is_refused(local):
    assert mail.local_part_problem(local) != "", f"{local!r} was accepted"


@pytest.mark.parametrize("address", [
    "", "alice", "alice@", "@example.com", "alice@example.com, bob@evil.com",
    "alice@example.com\nBcc: bob@evil.com", "a b@example.com",
])
def test_a_recipient_that_is_not_one_address_is_refused(address):
    assert mail.address_problem(address) != "", f"{address!r} was accepted"


def test_a_capitalised_address_is_accepted_as_its_lowercase_self():
    """Mail addresses are handed out by people typing them, and nobody thinks
    Alice@ and alice@ are two mailboxes. It is normalised rather than refused."""
    assert mail.local_part_problem("Alice") == ""


def test_a_subject_cannot_carry_a_second_header():
    """This is the whole reason subjects are put through one filter: a newline in
    a subject is how a Bcc gets added to somebody else's message."""
    built = mail.build_message("a@x.test", "A", "b@x.test",
                               mail._one_line("Hi\r\nBcc: sneaky@evil.com", 300),
                               "body")
    assert "Bcc" not in built
    assert "\n" not in built["Subject"] and "\r" not in built["Subject"]
    assert built["Subject"] == "Hi Bcc: sneaky@evil.com"


def test_the_relay_password_is_never_handed_back(conn):
    mail.ensure_schema(conn)
    _wipe(conn)
    mail.set_relay(conn, "smtp.example.com", 587, "user", "sup3rsecret", True)
    cfg = mail.config(conn)
    assert cfg["relay_secret_set"] is True
    assert "sup3rsecret" not in str(cfg)
    assert "relay_secret" not in cfg


def test_the_relay_password_is_encrypted_at_rest(conn):
    mail.ensure_schema(conn)
    _wipe(conn)
    mail.set_relay(conn, "smtp.example.com", 587, "user", "sup3rsecret", True)
    cur = conn.cursor()
    cur.execute("SELECT relay_secret FROM mail_config ORDER BY id LIMIT 1")
    stored = cur.fetchone()[0]
    cur.close()
    assert stored and "sup3rsecret" not in stored
    assert mail._relay_secret(conn) == "sup3rsecret"


def test_saving_the_relay_again_without_a_password_keeps_the_old_one(conn):
    """Otherwise editing the port would silently forget the password."""
    mail.ensure_schema(conn)
    _wipe(conn)
    mail.set_relay(conn, "smtp.example.com", 587, "user", "keepme", True)
    mail.set_relay(conn, "smtp.example.com", 2525, "user", "", True)
    assert mail._relay_secret(conn) == "keepme"
    assert mail.config(conn)["relay_port"] == 2525


# ------------------------------------------------------------------- reading
def test_a_staff_account_cannot_configure_mail(client, conn):
    _as(client, ALICE)
    for path, payload in [("/api/mail/domain", {"domain": DOMAIN}),
                          ("/api/mail/relay", {"host": "smtp.example.com"}),
                          ("/api/mail/relay/check", {}),
                          ("/api/mail/box", {"local_part": "sneaky"}),
                          ("/api/mail/box/assign", {"address": f"a@{DOMAIN}", "owner": ALICE}),
                          ("/api/mail/box/name", {"address": f"a@{DOMAIN}"}),
                          ("/api/mail/inbound/prepare", {"domain": DOMAIN}),
                          ("/api/mail/inbound/start", {}),
                          ("/api/mail/inbound/key", {"key": "x"})]:
        assert client.post(path, json=payload).status_code == 403, path
    assert client.get("/api/mail/inbound-job").status_code == 403
    assert client.delete(f"/api/mail/box/a@{DOMAIN}").status_code == 403


def test_an_unconfigured_system_tells_staff_so(client, conn):
    _as(client, ALICE)
    body = client.get("/api/mail/overview").json()
    assert body["configured"] is False
    assert body["boxes"] == []
    assert "config" not in body, "relay settings are not staff business"
    assert "inbound" not in body


def test_one_account_cannot_read_another_accounts_mail(client, conn):
    _setup(client, conn)
    _as(client, ALICE)
    sent = client.post("/api/mail/send", json={
        "from": f"alice@{DOMAIN}", "to": f"bob@{DOMAIN}", "route": "internal",
        "subject": "Lunch", "body": "One o'clock?"})
    assert sent.status_code == 200

    # Bob has it.
    _as(client, BOB)
    inbox = client.get("/api/mail/messages?folder=inbox").json()
    assert [m["subject"] for m in inbox["messages"]] == ["Lunch"]
    message_id = inbox["messages"][0]["id"]

    # Alice does not, however she asks.
    _as(client, ALICE)
    assert client.get("/api/mail/messages?folder=inbox").json()["total"] == 0
    assert client.get(f"/api/mail/messages?folder=inbox&box=bob@{DOMAIN}").json()["total"] == 0
    assert client.post("/api/mail/read", json={"id": message_id}).status_code == 404
    assert client.delete(f"/api/mail/message/{message_id}").status_code == 404


def test_a_box_filter_can_only_narrow(client, conn):
    """The filter is a convenience, not the permission check. Asking for a box
    that is not yours returns nothing rather than everything."""
    _setup(client, conn)
    _as(client, ALICE)
    for hostile in (f"bob@{DOMAIN}", "' OR 1=1 --", f"BOB@{DOMAIN}"):
        body = client.get("/api/mail/messages", params={"folder": "inbox",
                                                        "box": hostile}).json()
        assert body["total"] == 0, hostile


def test_the_unread_count_is_per_account(client, conn):
    _setup(client, conn)
    _as(client, ALICE)
    client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                        "to": f"bob@{DOMAIN}", "route": "internal",
                                        "subject": "One", "body": "x"})
    assert client.get("/api/mail/unread").json()["unread"] == 0, \
        "a sent message is not unread mail for the sender"
    _as(client, BOB)
    assert client.get("/api/mail/unread").json()["unread"] == 1
    message_id = client.get("/api/mail/messages?folder=inbox").json()["messages"][0]["id"]
    client.post("/api/mail/read", json={"id": message_id})
    assert client.get("/api/mail/unread").json()["unread"] == 0


def test_the_admin_sees_every_mailbox(client, conn):
    _setup(client, conn)
    _as(client, "admin")
    body = client.get("/api/mail/overview").json()
    assert {b["address"] for b in body["boxes"]} == {f"alice@{DOMAIN}", f"bob@{DOMAIN}"}
    assert body["is_admin"] is True


# ------------------------------------------------------------------- sending
def test_sending_from_an_address_that_is_not_yours_is_refused(client, conn):
    _setup(client, conn)
    _as(client, ALICE)
    r = client.post("/api/mail/send", json={"from": f"bob@{DOMAIN}",
                                            "to": f"alice@{DOMAIN}",
                                            "route": "internal", "subject": "x",
                                            "body": "x"})
    assert r.status_code == 400
    assert "not one of your addresses" in r.json()["error"]


def test_internal_mail_to_an_outside_address_is_refused_not_upgraded(client, conn):
    """The sender was told it would not leave this system. Quietly sending it
    through the relay instead would make that a lie."""
    _setup(client, conn)
    _as(client, ALICE)
    r = client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                            "to": "stranger@example.com",
                                            "route": "internal", "subject": "x",
                                            "body": "x"})
    assert r.status_code == 400
    assert "cannot be delivered internally" in r.json()["error"]


def test_internal_mail_never_opens_the_relay(client, conn, monkeypatch):
    _setup(client, conn)

    def explode(*a, **k):
        raise AssertionError("internal mail reached the SMTP relay")
    monkeypatch.setattr(mail.smtplib, "SMTP", explode)
    _as(client, "admin")
    client.post("/api/mail/relay", json={"host": "smtp.example.com", "port": 587,
                                         "user": "u", "password": "p"})
    _as(client, ALICE)
    r = client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                            "to": f"bob@{DOMAIN}",
                                            "route": "internal", "subject": "x",
                                            "body": "x"})
    assert r.status_code == 200 and r.json()["route"] == "internal"


def test_external_mail_without_a_relay_is_refused(client, conn):
    _setup(client, conn)
    _as(client, ALICE)
    r = client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                            "to": "stranger@example.com",
                                            "route": "external", "subject": "x",
                                            "body": "x"})
    assert r.status_code == 400 and "relay" in r.json()["error"]


def test_a_route_that_is_neither_is_refused(client, conn):
    _setup(client, conn)
    _as(client, ALICE)
    for route in ("", "both", "smtp", "internal external"):
        r = client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                                "to": f"bob@{DOMAIN}",
                                                "route": route, "subject": "x",
                                                "body": "x"})
        assert r.status_code == 400, route


def test_a_failed_external_send_is_still_recorded(client, conn, monkeypatch):
    """A message that could not go out is exactly the one somebody will come
    looking for."""
    _setup(client, conn)
    _as(client, "admin")
    client.post("/api/mail/relay", json={"host": "127.0.0.1", "port": 1,
                                         "user": "", "password": ""})
    _as(client, ALICE)
    r = client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                            "to": "stranger@example.com",
                                            "route": "external", "subject": "Out",
                                            "body": "x"})
    assert r.status_code == 400
    sent = client.get("/api/mail/messages?folder=sent").json()["messages"]
    assert sent and sent[0]["status"] == "failed" and sent[0]["route"] == "external"
    assert sent[0]["detail"], "a failure with no reason is not a record"


def test_both_sides_of_an_internal_message_are_stored(client, conn):
    _setup(client, conn)
    _as(client, ALICE)
    client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                        "to": f"bob@{DOMAIN}", "route": "internal",
                                        "subject": "Kept", "body": "hello"})
    _as(client, ALICE)
    assert client.get("/api/mail/messages?folder=sent").json()["total"] == 1
    _as(client, BOB)
    assert client.get("/api/mail/messages?folder=inbox").json()["total"] == 1


# ------------------------------------------------------------------ mailboxes
def test_an_address_cannot_be_created_before_the_domain(client, conn):
    _as(client, "admin")
    r = client.post("/api/mail/box", json={"local_part": "sales"})
    assert r.status_code == 400 and "domain" in r.json()["error"]


def test_the_domain_cannot_be_changed_under_existing_addresses(client, conn):
    _setup(client, conn)
    _as(client, "admin")
    r = client.post("/api/mail/domain", json={"domain": "somewhere-else.test"})
    assert r.status_code == 400
    assert "mailboxes" in r.json()["error"]


def test_assigning_to_an_account_that_does_not_exist_is_refused(client, conn):
    _setup(client, conn)
    _as(client, "admin")
    r = client.post("/api/mail/box/assign", json={"address": f"alice@{DOMAIN}",
                                                   "owner": "nobody_at_all"})
    assert r.status_code == 400


def test_reassigning_an_address_moves_the_mail_with_it(client, conn):
    """Mail belongs to the address, not to whoever held it last."""
    _setup(client, conn)
    _as(client, ALICE)
    client.post("/api/mail/send", json={"from": f"alice@{DOMAIN}",
                                        "to": f"bob@{DOMAIN}", "route": "internal",
                                        "subject": "Handover", "body": "x"})
    _as(client, "admin")
    assert client.post("/api/mail/box/assign",
                       json={"address": f"bob@{DOMAIN}", "owner": ALICE}).status_code == 200
    _as(client, ALICE)
    subjects = [m["subject"] for m in
                client.get("/api/mail/messages?folder=inbox").json()["messages"]]
    assert "Handover" in subjects
    _as(client, BOB)
    assert client.get("/api/mail/messages?folder=inbox").json()["total"] == 0


# ------------------------------------------------------------------- mailcow
def test_the_inbound_status_is_honest_about_what_is_missing():
    """A page that says "configured" while nothing listens on 25 is worse than
    one that says nothing works."""
    status = mailcow.status()
    assert set(("docker", "compose", "installed", "smtp_listening", "ready",
                "problems")) <= set(status)
    if not status["smtp_listening"]:
        assert status["ready"] is False
        assert status["problems"], "something is missing and nothing said so"


def test_the_dns_help_names_the_records_mail_cannot_work_without():
    records = mailcow.dns_help("example.com")
    kinds = {r["type"] for r in records}
    assert {"A", "MX", "TXT"} <= kinds
    assert any(r["name"] == "example.com" and r["type"] == "MX" for r in records)
    assert all("<domain>" not in r["name"] + r["value"] for r in records)


def test_every_mail_route_is_a_real_route():
    known = set()
    for route in panel.app.routes:
        for method in getattr(route, "methods", ()) or ():
            known.add((method, getattr(route, "path", "")))
    for method, path in [
        ("GET", "/api/mail/overview"), ("GET", "/api/mail/unread"),
        ("GET", "/api/mail/messages"), ("POST", "/api/mail/read"),
        ("DELETE", "/api/mail/message/{message_id}"), ("POST", "/api/mail/send"),
        ("POST", "/api/mail/domain"), ("POST", "/api/mail/relay"),
        ("POST", "/api/mail/relay/check"), ("POST", "/api/mail/box"),
        ("POST", "/api/mail/box/assign"), ("POST", "/api/mail/box/name"),
        ("DELETE", "/api/mail/box/{address}"),
        ("POST", "/api/mail/inbound/prepare"), ("POST", "/api/mail/inbound/{action}"),
        ("GET", "/api/mail/inbound-job"), ("POST", "/api/mail/sync"),
    ]:
        assert (method, path) in known, f"{method} {path} is missing"


def test_the_mail_tab_sits_left_of_logs():
    keys = [k for k, _label, _icon in panel._NAV]
    assert keys.index("mail") < keys.index("logs")


def test_signing_out_closes_the_mail_endpoints(client):
    client.cookies.clear()
    for path in ("/api/mail/overview", "/api/mail/unread", "/api/mail/messages"):
        assert client.get(path).status_code in (401, 403), path
