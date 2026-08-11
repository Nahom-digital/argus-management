"""The Telegram bot.

Two properties are worth a test here and everything else follows from them:
a chat nobody allowed can do nothing but learn its own ID, and an allowed chat
can do exactly what its panel account may do, no more. The Telegram API itself
is stubbed, because what is under test is the gate, not their HTTP.
"""
import pytest

import panel_users as pu
import telegram_bot as tb
from fastapi.testclient import TestClient

import panel

STRANGER = 990001
BOSS = 990002
WORKER = 990003
STAFF = "pytest_tg_user"
PASSWORD = "T3legram!Pass"


@pytest.fixture
def bot(conn, monkeypatch):
    sent = []
    monkeypatch.setattr(tb, "send_message",
                        lambda c, chat_id, text, quiet=False: sent.append((chat_id, text)) or True)
    monkeypatch.setattr(tb, "notify", lambda c, s, b: sent.append(("EMAIL", s)))
    monkeypatch.setattr(tb, "call", lambda tok, m, p=None, timeout=20: (True, {"ok": True}))
    cur = conn.cursor()
    for statement in tb.SCHEMA:
        cur.execute(statement)
    _wipe(cur)
    cur.close()
    yield sent
    cur = conn.cursor()
    _wipe(cur)
    cur.close()


def _wipe(cur):
    ids = (STRANGER, BOSS, WORKER)
    cur.execute("DELETE FROM tg_log WHERE telegram_id IN %s", (ids,))
    cur.execute("DELETE FROM tg_user WHERE telegram_id IN %s", (ids,))


def update(uid, text):
    return {"message": {"chat": {"id": uid},
                        "from": {"id": uid, "username": f"u{uid}", "first_name": "T"},
                        "text": text}}


def last(sent):
    return next(t for who, t in reversed(sent) if who != "EMAIL")


def test_a_stranger_learns_their_own_id_and_nothing_else(conn, bot):
    tb.handle_update(conn, update(STRANGER, "/status"))
    reply = last(bot)
    assert str(STRANGER) in reply
    assert "CPU" not in reply
    assert [p["telegram_id"] for p in tb.pending(conn)] == [STRANGER]


def test_the_stranger_is_emailed_about_once_not_once_per_message(conn, bot):
    for _ in range(4):
        tb.handle_update(conn, update(STRANGER, "hello"))
    assert sum(1 for who, _ in bot if who == "EMAIL") == 1


def test_a_blocked_id_gets_no_reply_at_all(conn, bot):
    tb.allow(conn, STRANGER, tb.ROLE_BLOCKED, actor="admin")
    bot.clear()
    tb.handle_update(conn, update(STRANGER, "/help"))
    assert not [t for who, t in bot if who != "EMAIL"]


def test_an_admin_reaches_every_command(conn, bot):
    tb.allow(conn, BOSS, tb.ROLE_ADMIN, actor="admin")
    tb.handle_update(conn, update(BOSS, "/help"))
    reply = last(bot)
    for spec in tb.COMMANDS:
        assert spec["word"] in reply, f"{spec['word']} missing from the admin help"


def test_a_user_without_a_panel_account_gets_the_identity_commands_only(conn, bot):
    tb.allow(conn, WORKER, tb.ROLE_USER, actor="admin")
    tb.handle_update(conn, update(WORKER, "/help"))
    reply = last(bot)
    assert "/sh" not in reply and "/status" not in reply
    assert "/id" in reply and "/whoami" in reply


def test_a_command_the_help_hides_is_also_refused(conn, bot):
    tb.allow(conn, WORKER, tb.ROLE_USER, actor="admin")
    bot.clear()
    tb.handle_update(conn, update(WORKER, "/sh whoami"))
    assert "not allowed" in last(bot)


def test_a_user_gets_exactly_what_their_panel_account_holds(conn, bot):
    pu.delete_user(conn, STAFF)
    pu.create_user(conn, STAFF, PASSWORD, {"svc_status": True}, "admin")
    try:
        tb.allow(conn, WORKER, tb.ROLE_USER, STAFF, actor="admin")
        tb.handle_update(conn, update(WORKER, "/help"))
        reply = last(bot)
        assert "/services" in reply
        assert "/sh" not in reply
        assert "/allow" not in reply
    finally:
        pu.delete_user(conn, STAFF)


def test_every_message_lands_in_the_conversation_log(conn, bot):
    tb.handle_update(conn, update(STRANGER, "knock knock"))
    rows = tb.recent(conn, limit=10, telegram_id=STRANGER)
    assert any(r["direction"] == "in" and r["text"] == "knock knock" for r in rows)
    assert any(r["direction"] == "out" for r in rows)
    assert all(r["allowed"] is False for r in rows)


def test_the_stored_token_never_reaches_the_interface(conn, bot):
    ok, detail = tb.set_config(conn, bot_token="123456789:" + "A" * 35)
    assert ok, detail
    view = tb.config(conn)
    assert view["token_set"] and "123456789" not in repr(view)
    cur = conn.cursor()
    cur.execute("DELETE FROM system_settings WHERE key LIKE 'tg_%'")
    cur.close()


def test_a_token_that_is_not_a_token_is_refused(conn, bot):
    ok, _ = tb.set_config(conn, bot_token="hunter2")
    assert not ok


# --------------------------------------------------------------- the webhook
@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51000)) as c:
        yield c


def test_the_webhook_is_invisible_until_the_bot_is_connected(client, conn):
    cur = conn.cursor()
    cur.execute("DELETE FROM system_settings WHERE key LIKE 'tg_%'")
    cur.close()
    assert client.post("/bot", json={}).status_code == 404


def test_the_webhook_refuses_a_delivery_without_telegrams_secret(client, conn):
    for statement in tb.SCHEMA:
        conn.cursor().execute(statement)
    tb._put(conn, tb.S_ENABLED, "1")
    tb._put(conn, tb.S_SECRET, "a-secret-only-telegram-has")
    try:
        assert client.post("/bot", json={}).status_code == 403
        assert client.post("/bot", json={}, headers={
            "X-Telegram-Bot-Api-Secret-Token": "guessed"}).status_code == 403
        assert client.post("/bot", json={}, headers={
            "X-Telegram-Bot-Api-Secret-Token": "a-secret-only-telegram-has"
        }).status_code == 200
    finally:
        cur = conn.cursor()
        cur.execute("DELETE FROM system_settings WHERE key LIKE 'tg_%'")
        cur.close()
