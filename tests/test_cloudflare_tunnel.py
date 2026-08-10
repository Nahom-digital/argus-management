"""The Cloudflare Tunnel module: what it refuses, and what it writes.

Nothing here talks to Cloudflare. Every test either checks a decision made
before cloudflared is ever run, or checks the text of a file that gets written.
Those are the two places a mistake would be dangerous: a value that reaches a
config file unchecked, and a config file that says something other than what the
operator asked for.
"""
import os
import re

import pytest

import cloudflare_tunnel as cf
import panel
import panel_users as pu


# --------------------------------------------------------------- names
@pytest.mark.parametrize("name", ["home", "home-server", "a", "a1-b2", "x" * 62])
def test_a_reasonable_tunnel_name_is_accepted(name):
    assert cf.name_problem(name) == ""


@pytest.mark.parametrize("name", [
    "", " ", "Home", "-home", "home_server", "home server", "x" * 63,
    "../../etc/passwd", "home;reboot", "home$(id)", "hôme", "home.server",
])
def test_a_name_that_could_not_be_a_filename_is_refused(name):
    """The name becomes part of a path under /etc/cloudflared and part of a
    command line, so anything but lowercase letters, digits and hyphens is
    refused before either happens."""
    assert cf.name_problem(name) != "", f"{name!r} was accepted"


def test_the_credentials_path_stays_inside_the_config_directory():
    for name in ["home", "a1-b2", "x" * 62]:
        path = os.path.realpath(cf.cred_path(name))
        assert path.startswith(os.path.realpath(cf.CONFIG_DIR) + os.sep), path


# --------------------------------------------------------------- routes
def test_a_normal_forward_is_accepted():
    assert cf.route_problem("app.example.com", "127.0.0.1", 8080) == ""
    assert cf.route_problem("a.b.example.co.uk", "10.0.0.5", "443") == ""
    assert cf.route_problem("*.example.com", "backend", 3000) == ""


@pytest.mark.parametrize("hostname", [
    "", "example", "http://app.example.com", "app.example.com/path",
    "app example.com", "app.example.com; rm -rf /", "-app.example.com",
    "app.example.com\nservice: http://evil", "app.exam ple.com",
])
def test_a_hostname_that_is_not_a_hostname_is_refused(hostname):
    """The hostname is written into a YAML file as a bare scalar, so a value
    carrying a newline or a colon could add lines of its own."""
    assert cf.route_problem(hostname, "127.0.0.1", 80) != "", f"{hostname!r} was accepted"


@pytest.mark.parametrize("port", ["", None, 0, -1, 65536, "eighty", "80; reboot", 1.5e9])
def test_a_port_that_is_not_a_port_is_refused(port):
    assert cf.route_problem("app.example.com", "127.0.0.1", port) != "", f"{port!r} was accepted"


@pytest.mark.parametrize("local", ["", "10.0.0.1 && id", "back end", "back\nend",
                                   "-x", "a" * 300])
def test_a_local_address_that_is_not_an_address_is_refused(local):
    assert cf.route_problem("app.example.com", local, 80) != "", f"{local!r} was accepted"


# --------------------------------------------------------------- the config
def _rendered(rows):
    return cf.render_config("home", "/etc/cloudflared/home.json", rows)


def test_the_config_says_what_was_asked_for():
    text = _rendered([
        {"hostname": "app.example.com", "local_host": "127.0.0.1", "local_port": 8080},
        {"hostname": "api.example.com", "local_host": "10.0.0.9", "local_port": 3000},
    ])
    assert "tunnel: home" in text
    assert "credentials-file: /etc/cloudflared/home.json" in text
    assert "  - hostname: app.example.com" in text
    assert "    service: http://127.0.0.1:8080" in text
    assert "  - hostname: api.example.com" in text
    assert "    service: http://10.0.0.9:3000" in text


def test_the_config_ends_with_a_catch_all():
    """Without it cloudflared answers hostnames nobody configured, which is how a
    tunnel ends up serving the wrong thing to a name somebody guessed."""
    text = _rendered([{"hostname": "app.example.com", "local_host": "127.0.0.1",
                       "local_port": 8080}])
    assert text.rstrip().endswith("- service: http_status:404")


def test_a_tunnel_with_no_forwards_still_renders_a_usable_config():
    text = _rendered([])
    assert "ingress:" in text and "http_status:404" in text


def test_the_local_side_is_always_plain_http():
    """Cloudflare terminates TLS at its edge. If the local side were HTTPS the
    service would need a certificate of its own, which is the thing a tunnel
    exists to avoid."""
    text = _rendered([{"hostname": "app.example.com", "local_host": "127.0.0.1",
                       "local_port": 8080}])
    assert "service: http://" in text
    assert "https://" not in text


def test_every_line_of_a_rendered_config_is_a_line_yaml_would_recognise():
    """A crude parse, but it catches the failure that matters: a value that broke
    out of its own line."""
    text = _rendered([{"hostname": "app.example.com", "local_host": "127.0.0.1",
                       "local_port": 8080}])
    for line in text.splitlines():
        assert re.match(r"^(#.*|[a-z-]+: \S+|ingress:|  - [a-z_]+: \S+|    [a-z_]+: \S+)$",
                        line), f"unexpected config line: {line!r}"


# --------------------------------------------------------------- the unit file
def test_the_unit_runs_our_config_and_nothing_else():
    unit = cf.UNIT_TEMPLATE.format(binary="/usr/local/bin/cloudflared",
                                   config=cf.CONFIG_PATH, cert=cf.CERT_PATH)
    assert f"--config {cf.CONFIG_PATH} tunnel run" in unit
    assert "Restart=on-failure" in unit
    assert f"TUNNEL_ORIGIN_CERT={cf.CERT_PATH}" in unit


def test_the_unit_is_not_named_cloudflared():
    """An operator may already run cloudflared for something else. Taking over
    that unit name would stop their tunnel to start ours."""
    assert cf.SERVICE_NAME == "argus-tunnel"
    assert "cloudflared.service" not in cf.UNIT_PATH


# --------------------------------------------------------------- refusals
def test_creating_a_tunnel_without_an_account_is_refused(conn, monkeypatch):
    monkeypatch.setattr(cf, "logged_in", lambda: False)
    ok, message = cf.create_tunnel(conn, "pytest-tunnel")
    assert ok is False and "account" in message.lower()


def test_a_bad_name_never_reaches_cloudflared(conn, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("cloudflared was run with a name that should have been refused")
    monkeypatch.setattr(cf, "_run", explode)
    monkeypatch.setattr(cf, "logged_in", lambda: True)
    ok, message = cf.create_tunnel(conn, "Bad Name; reboot")
    assert ok is False and message


def test_a_bad_route_never_reaches_cloudflared(conn, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("cloudflared was run with a route that should have been refused")
    monkeypatch.setattr(cf, "_run", explode)
    ok, message = cf.add_route(conn, "home", "not a hostname", "127.0.0.1", 80)
    assert ok is False and message


def test_the_service_only_takes_the_three_verbs_it_knows(monkeypatch):
    monkeypatch.setattr(cf, "_systemctl", lambda *a, **k: (0, ""))
    for verb in ("start", "stop", "restart"):
        ok, _ = cf.service_action(verb)
        assert ok is True, verb
    for verb in ("mask", "", "reboot", "start; reboot", "daemon-reload"):
        ok, _ = cf.service_action(verb)
        assert ok is False, verb


def test_writing_a_config_for_a_tunnel_with_no_credentials_is_refused(conn):
    """Without the credentials file the tunnel cannot start, and a config that
    names a missing file makes systemd fail in a way that is hard to read."""
    ok, note = cf.write_config(conn, "pytest-nonexistent-tunnel")
    assert ok is False and "credentials" in note


# --------------------------------------------------------------- the wiring
def test_the_grant_exists_and_is_a_network_grant():
    grant = [g for g in pu.PERMISSIONS if g.key == "tunnel_manage"]
    assert grant and grant[0].group == "network"
    assert grant[0].default is False, "no staff account starts with this"


def test_every_tunnel_route_is_a_real_route():
    known = set()
    for route in panel.app.routes:
        for method in getattr(route, "methods", ()) or ():
            known.add((method, getattr(route, "path", "")))
    for method, path in [
        ("GET", "/api/config/tunnel"),
        ("POST", "/api/config/tunnel/login"),
        ("GET", "/api/config/tunnel/login"),
        ("POST", "/api/config/tunnel/disconnect"),
        ("POST", "/api/config/tunnel/create"),
        ("DELETE", "/api/config/tunnel/{name}"),
        ("POST", "/api/config/tunnel/active"),
        ("POST", "/api/config/tunnel/route"),
        ("DELETE", "/api/config/tunnel/route/{hostname}"),
        ("POST", "/api/config/tunnel/service"),
    ]:
        assert (method, path) in known, f"{method} {path} is missing"


def test_the_card_only_renders_for_an_account_that_holds_the_grant():
    with_grant = panel._config_sub_proxy({"net_proxy": True, "tunnel_manage": True})
    without = panel._config_sub_proxy({"net_proxy": True})
    assert "cf-card" in with_grant
    assert "cf-card" not in without
