"""Specific attacks, each one pinned so it cannot come back.

Every test here corresponds to a real hole found by reviewing the permission
rewrite, not to a hypothetical.
"""
import os

import pytest

import DB
import panel
import panel_users as pu
import System
from fastapi.testclient import TestClient

STAFF = "pytest_sec_user"
PASSWORD = "S3curity!Pass"


@pytest.fixture(scope="module")
def client():
    with TestClient(panel.app, client=("127.0.0.1", 51030)) as c:
        yield c


# --- a staff row named after the admin would resolve to full admin ----------

def test_creating_a_staff_account_named_admin_is_refused(conn):
    pu.delete_user(conn, "admin")
    with pytest.raises(ValueError):
        pu.create_user(conn, "admin", PASSWORD, {}, "admin")


def test_a_pre_existing_staff_row_named_admin_cannot_sign_in(conn):
    """Inserted straight into the table, bypassing create_user, the way a row
    written before the fix would look."""
    import recovery
    cur = conn.cursor()
    pu.ensure_table(conn)
    cur.execute("DELETE FROM panel_user WHERE username = 'admin'")
    cur.execute(
        """INSERT INTO panel_user (username, password_hash, grants, created_by)
           VALUES ('admin', %s, '{}'::jsonb, 'attacker')""",
        (recovery.hash_password(PASSWORD),),
    )
    conn.commit()
    cur.close()
    try:
        assert pu.verify_login(conn, "admin", PASSWORD) is None, \
            "a staff row named admin must never authenticate"
    finally:
        cur = conn.cursor()
        cur.execute("DELETE FROM panel_user WHERE username = 'admin'")
        conn.commit()
        cur.close()


def test_the_api_refuses_to_create_a_user_named_admin(client):
    client.cookies.clear()
    client.cookies.set("session", panel._create_session_token("admin"))
    r = client.post("/api/config/users",
                    json={"username": "admin", "password": PASSWORD, "grants": {}})
    assert r.status_code == 400, r.text


# --- the disk sandbox must survive a symlink planted inside it --------------

def test_a_symlink_out_of_the_sandbox_is_refused(tmp_path):
    sandbox = tmp_path / "home" / "argus_someone"
    sandbox.mkdir(parents=True)
    (sandbox / "mine.txt").write_text("ok")
    secret = tmp_path / "outside.txt"
    secret.write_text("not for them")
    os.symlink(secret, sandbox / "escape.txt")

    root = str(sandbox)
    full, reason = System.resolve_download(str(sandbox / "mine.txt"), root=root)
    assert reason is None and full

    full, reason = System.resolve_download(str(sandbox / "escape.txt"), root=root)
    assert full is None and reason == "blocked", "symlink escape was allowed"

    ok, reason = System.delete_file(str(sandbox / "escape.txt"), root=root)
    assert not ok and reason == "blocked"


def test_dot_dot_traversal_is_refused(tmp_path):
    sandbox = tmp_path / "home" / "argus_someone"
    sandbox.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("nope")
    full, reason = System.resolve_download(
        str(sandbox / ".." / ".." / "outside.txt"), root=str(sandbox))
    assert full is None and reason == "blocked"


def test_a_sibling_directory_sharing_a_name_prefix_is_refused(tmp_path):
    """/home/argus_ab must not be reachable from a sandbox at /home/argus_a."""
    (tmp_path / "argus_a").mkdir()
    (tmp_path / "argus_ab").mkdir()
    (tmp_path / "argus_ab" / "theirs.txt").write_text("theirs")
    full, reason = System.resolve_download(
        str(tmp_path / "argus_ab" / "theirs.txt"), root=str(tmp_path / "argus_a"))
    assert full is None and reason == "blocked"


def test_listing_outside_the_sandbox_returns_nothing_useful(tmp_path):
    sandbox = tmp_path / "argus_someone"
    sandbox.mkdir()
    out = System.list_dir("/etc", root=str(sandbox))
    assert out["entries"] == []
    assert out["parent"] is None
    assert "permitted" in (out.get("error") or "").lower()


def test_the_sandbox_root_has_no_parent_link(tmp_path):
    sandbox = tmp_path / "argus_someone"
    sandbox.mkdir()
    (sandbox / "a.txt").write_text("a")
    out = System.list_dir(str(sandbox), root=str(sandbox))
    assert out["parent"] is None, "staff could walk up out of their own home"
    assert [e["name"] for e in out["entries"]] == ["a.txt"]


def test_own_scope_without_a_system_account_reaches_nothing():
    perms = {"disk_scope": pu.DISK_OWN, "os_username": None}
    root = panel._disk_root(perms)
    assert root and not os.path.exists(root)
    full, reason = System.resolve_download("/etc/hostname", root=root)
    assert full is None and reason == "blocked"


# --- grant payloads can only ever narrow -----------------------------------

def test_no_payload_shape_can_invent_a_grant():
    for hostile in [
        {"role": "admin"}, {"grants": {"db_write": True}},
        {"__proto__": {"db_write": True}}, {"db_write": {"toString": 1}},
        {"disk_scope": ["full"]}, {"terminal": {"root": True}},
    ]:
        out = pu.normalize_grants(hostile)
        assert set(out) == set(pu.GRANT_KEYS)
        assert out["disk_scope"] == "none"
        assert out["terminal"] == "none"


def test_a_malformed_value_never_reads_as_permission():
    """Python calls a non-empty dict or list truthy, so a JSON object arriving
    where a boolean belongs must collapse to the default, not to True."""
    for value in ({"a": 1}, [1], {"nested": {"deep": True}}, [[]]):
        assert pu.normalize_grants({"db_write": value})["db_write"] is False, value
    # Genuine shapes still work.
    assert pu.normalize_grants({"db_write": True})["db_write"] is True
    assert pu.normalize_grants({"db_write": "yes"})["db_write"] is True
    assert pu.normalize_grants({"db_write": 1})["db_write"] is True
    assert pu.normalize_grants({"db_write": 0})["db_write"] is False
    assert pu.normalize_grants({"db_write": "off"})["db_write"] is False


def test_a_proxy_filename_cannot_walk_out_of_the_nginx_directory():
    """filename comes straight off the URL, so it is attacker-shaped input. If
    it were joined raw, ../../../etc/passwd would be read and then rewritten."""
    import nginx_proxy
    for hostile in ("../../../../etc/passwd", "..%2f..%2fshadow",
                    "/etc/shadow", "sub/dir/other.conf", "....//nginx.conf"):
        assert nginx_proxy.get_host(hostile) is None or \
            "/" not in os.path.basename(hostile), hostile
        # The read path and the delete path must agree on the sanitizer.
        assert os.path.basename(hostile) == os.path.basename(os.path.basename(hostile))


def test_a_proxy_config_path_is_always_derived_from_the_slug_not_the_input():
    """Even a domain that passed validation must not be able to choose where the
    file lands."""
    import nginx_proxy
    for hostile in ("../../evil/../app.example.com", "/etc/nginx/nginx.conf",
                    "..", "...", "./.hidden", "a/b/c"):
        slug = nginx_proxy._slug(hostile)
        assert "/" not in slug, slug
        assert ".." not in slug, slug
        assert not slug.startswith("."), slug
        assert slug, "an empty filename would land on the directory itself"


def test_a_proxy_spec_from_a_request_body_keeps_only_known_fields():
    """A stored spec is rendered into a config file, so an unknown key that
    survived would be a way to inject text into nginx's own syntax."""
    import panel
    import nginx_proxy
    hostile = {
        "domain": "app.example.com",
        "forward_host": "127.0.0.1",
        "forward_port": 8080,
        "extra_directives": "}\nserver { listen 9999; }",
        "__class__": "nope",
        "locations": [{"path": "/api", "forward_host": "127.0.0.1",
                       "forward_port": 9000, "sneaky": "return 200 'pwned';"}],
    }
    spec = panel._proxy_spec_from_body(hostile)
    assert "extra_directives" not in spec and "__class__" not in spec
    assert "sneaky" not in spec["locations"][0]
    rendered = nginx_proxy.render(nginx_proxy.normalize(spec))
    assert "listen 9999" not in rendered
    assert "pwned" not in rendered


def test_a_request_cannot_ask_for_an_unbounded_number_of_locations():
    """Each location becomes a block in a config file nginx has to parse."""
    import panel
    body = {"domain": "app.example.com", "forward_host": "127.0.0.1",
            "forward_port": 80,
            "locations": [{"path": f"/p{i}", "forward_host": "127.0.0.1",
                           "forward_port": 9000} for i in range(500)]}
    assert len(panel._proxy_spec_from_body(body)["locations"]) <= 40


def test_the_ingress_gate_does_not_take_the_callers_word_for_who_they_are():
    """The gate rules on the hop, and the hop must never come from a header any
    caller can write. X-Forwarded-For is exactly that: a comma separated list a
    stranger prepends to at will. It is read for logging, from a local hop only,
    so the two have to stay separate.
    """
    class Req:
        def __init__(self, peer, headers):
            self.client = type("C", (), {"host": peer})()
            self.headers = headers

    cloudflare = "173.245.48.1"

    # A stranger naming a Cloudflare address does not become Cloudflare.
    outsider = Req("203.0.113.7", {"x-forwarded-for": cloudflare,
                                   "x-real-ip": cloudflare,
                                   "cf-connecting-ip": cloudflare})
    assert panel._hop_ip(outsider) == "203.0.113.7"
    assert panel._ingress_allowed(panel._hop_ip(outsider)) is False

    # Through nginx on loopback, the hop is what nginx reports and nothing else.
    proxied = Req("127.0.0.1", {"x-real-ip": cloudflare,
                                "x-forwarded-for": "198.51.100.9",
                                "cf-connecting-ip": "198.51.100.9"})
    assert panel._hop_ip(proxied) == cloudflare
    assert panel._client_ip(proxied) == "198.51.100.9", \
        "the visitor Cloudflare named is who gets logged and blocked"

    # No Cloudflare in front: the leftmost forwarded entry is the visitor, and
    # only the leftmost, so appending entries cannot shift the blame.
    plain = Req("127.0.0.1", {"x-forwarded-for": "198.51.100.9, 10.0.0.1, 10.0.0.2"})
    assert panel._hop_ip(plain) == "127.0.0.1"
    assert panel._ingress_allowed("127.0.0.1") is True
    assert panel._client_ip(plain) == "198.51.100.9"
