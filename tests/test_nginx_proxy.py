"""Proxy host specs: what is refused, what is rendered, what round-trips.

None of these touch /etc/nginx. Rendering is a pure function of the spec, and
that is the part worth pinning down: a config that reads plausibly but that
nginx rejects takes the whole web server down on reload, so the rules encoded
here were each found by running a real `nginx -t` over the output.
"""
import json
import os
import tempfile

import pytest

import nginx_proxy as np

# validate() only asks whether the certificate is a file that exists, so two
# stand-ins are enough and the suite does not depend on the host having certs.
_CERT_DIR = tempfile.mkdtemp(prefix="pytest-nginx-certs-")
CERT = os.path.join(_CERT_DIR, "fullchain.pem")
CERT_KEY = os.path.join(_CERT_DIR, "privkey.pem")
for _path in (CERT, CERT_KEY):
    with open(_path, "w") as _fh:
        _fh.write("stand-in\n")


def spec(**over):
    base = {
        "domain": "app.example.com",
        "listen_scheme": "https",
        "forward_scheme": "http",
        "forward_host": "127.0.0.1",
        "forward_port": 8080,
        "cert_path": CERT,
        "cert_key_path": CERT_KEY,
        "locations": [],
    }
    base.update(over)
    return base


def problems_matching(spec_dict, needle):
    return [p for p in np.validate(spec_dict) if needle.lower() in p.lower()]


# ---------------------------------------------------------------- validation
def test_a_plain_http_host_needs_no_certificate():
    assert np.validate(spec(listen_scheme="http", cert_path="", cert_key_path="")) == []


def test_an_https_host_without_a_certificate_is_refused():
    assert problems_matching(spec(cert_path="", cert_key_path=""), "certificate")


def test_a_certificate_path_that_is_not_absolute_is_refused():
    assert problems_matching(spec(cert_path="certs/mine.pem"), "absolute")


def test_a_certificate_that_is_not_on_disk_is_refused():
    assert problems_matching(spec(cert_path="/etc/ssl/certs/not-here-at-all.pem"),
                             "no certificate file")


def test_the_stand_in_certificate_files_really_exist():
    """Otherwise every "this spec is acceptable" test below would be passing on
    a certificate complaint rather than on what it means to test."""
    assert os.path.isfile(CERT) and os.path.isfile(CERT_KEY)


def test_a_domain_that_is_not_a_domain_is_refused():
    for bad in ("", "not a domain", "http://example.com", "example .com",
                "-example.com", "a" * 300):
        assert problems_matching(spec(domain=bad), "domain"), bad


def test_a_forward_host_carrying_shell_or_nginx_syntax_is_refused():
    for bad in ("127.0.0.1; rm -rf /", "$(whoami)", "host name", "a{b}",
                "127.0.0.1 8080"):
        assert np.validate(spec(forward_host=bad)), bad


def test_a_forward_port_outside_the_range_is_refused():
    for bad in (0, -1, 70000, "", "eighty", None):
        assert problems_matching(spec(forward_port=bad), "port"), bad


def test_an_unresolvable_forward_host_is_refused_before_anything_is_written():
    """nginx resolves proxy_pass names when it loads the config, so a name that
    does not resolve is an [emerg] that stops nginx starting at all. Catching it
    here is the difference between one rejected form and every proxy host down.
    """
    found = problems_matching(spec(forward_host="definitely-not-real.invalid"),
                              "does not resolve")
    assert found, "an unresolvable hostname must be refused"


def test_an_ip_address_always_counts_as_resolvable():
    assert np.resolves("127.0.0.1")
    assert np.resolves("::1")
    assert np.resolves("203.0.113.7")


def test_localhost_resolves_but_a_made_up_name_does_not():
    assert np.resolves("localhost")
    assert not np.resolves("no-such-host.invalid")
    assert not np.resolves("")


def test_a_custom_location_path_must_look_like_a_path():
    for bad in ("api", "/api file", "/api;return 1", "/api{}", ""):
        s = spec(locations=[{"path": bad, "forward_host": "127.0.0.1",
                             "forward_port": 9000}])
        assert problems_matching(s, "custom location 1"), bad


def test_a_custom_location_with_a_bad_port_is_refused():
    s = spec(locations=[{"path": "/api", "forward_host": "127.0.0.1",
                         "forward_port": 0}])
    assert problems_matching(s, "custom location 1")


def test_a_good_custom_location_passes():
    s = spec(locations=[{"path": "/api", "forward_scheme": "http",
                         "forward_host": "127.0.0.1", "forward_port": 9000}])
    assert np.validate(s) == []


def test_a_tcp_host_needs_a_listen_port():
    s = spec(listen_scheme="tcp", listen_port=None)
    assert problems_matching(s, "listen on")


def test_tcp_is_refused_outright_when_the_stream_module_is_missing(monkeypatch):
    monkeypatch.setattr(np, "stream_problem",
                        lambda: "The stream module is built but not loaded.")
    s = spec(listen_scheme="tcp", listen_port=15432)
    assert problems_matching(s, "stream module")


def test_tcp_passes_when_stream_is_available(monkeypatch):
    monkeypatch.setattr(np, "stream_problem", lambda: "")
    s = spec(listen_scheme="tcp", listen_port=15432)
    assert np.validate(s) == []


# ---------------------------------------------------------------- normalizing
def test_normalize_drops_keys_the_renderer_does_not_know():
    out = np.normalize(dict(spec(), evil="rm -rf /", nested={"a": 1}))
    assert "evil" not in out and "nested" not in out


def test_normalize_fills_every_flag_so_render_never_reads_a_missing_key():
    out = np.normalize({"domain": "x.example.com", "forward_host": "127.0.0.1",
                        "forward_port": 80})
    for flag in np.TLS_FLAGS + np.BEHAVIOUR_FLAGS:
        assert flag in out and isinstance(out[flag], bool)


def test_normalize_falls_back_to_a_known_scheme():
    assert np.normalize(spec(listen_scheme="gopher"))["listen_scheme"] == "https"
    assert np.normalize(spec(forward_scheme="ftp"))["forward_scheme"] == "http"


def test_normalize_lowercases_the_domain():
    assert np.normalize(spec(domain="APP.Example.COM"))["domain"] == "app.example.com"


# ---------------------------------------------------------------- rendering
def test_a_rendered_config_carries_the_marker_so_ours_is_distinguishable():
    text = np.render(np.normalize(spec()))
    assert np.MANAGED_MARKER in text


def test_the_spec_round_trips_through_the_rendered_file():
    """The generated file embeds its own spec, so reopening a host for editing
    shows exactly what was saved instead of a guess reverse-engineered from
    directives."""
    original = np.normalize(spec(
        force_ssl=True, hsts=True, http2=True, websockets=True,
        cache_assets=True, block_exploits=True,
        locations=[{"path": "/api", "forward_scheme": "http",
                    "forward_host": "127.0.0.1", "forward_port": 9001,
                    "websockets": True, "cache_assets": False,
                    "block_exploits": True}]))
    text = np.render(original)
    parsed = np._parse(text, "/etc/nginx/sites-available/app.example.com")
    assert parsed["managed"] is True
    assert parsed["spec"] == original


def test_a_hand_written_config_is_not_claimed_as_ours():
    text = "server {\n  server_name mine.example.com;\n  proxy_pass http://127.0.0.1:5000;\n}\n"
    parsed = np._parse(text, "/etc/nginx/sites-available/mine")
    assert parsed["managed"] is False
    assert parsed["spec"] is None
    assert parsed["domain"] == "mine.example.com"


def test_http2_is_emitted_as_its_own_directive_on_a_current_nginx(monkeypatch):
    """nginx 1.25.1 deprecated "listen ... http2". Emitting the old form logs a
    warning on every reload and is scheduled to stop working."""
    monkeypatch.setattr(np, "nginx_version", lambda: (1, 30, 1))
    text = np.render(np.normalize(spec(http2=True)))
    assert "http2 on;" in text
    assert "ssl http2" not in text


def test_http2_falls_back_to_the_listen_form_on_an_older_nginx(monkeypatch):
    monkeypatch.setattr(np, "nginx_version", lambda: (1, 18, 0))
    text = np.render(np.normalize(spec(http2=True)))
    assert "listen 443 ssl http2;" in text
    assert "http2 on;" not in text


def test_force_ssl_adds_a_redirect_server_block():
    text = np.render(np.normalize(spec(force_ssl=True)))
    assert "return 301 https://$host$request_uri;" in text


def test_without_force_ssl_there_is_no_redirect():
    text = np.render(np.normalize(spec(force_ssl=False)))
    assert "return 301" not in text


def test_hsts_subdomains_only_appears_with_hsts():
    with_sub = np.render(np.normalize(spec(hsts=True, hsts_subdomains=True)))
    assert "includeSubDomains" in with_sub
    without = np.render(np.normalize(spec(hsts=False, hsts_subdomains=True)))
    assert "Strict-Transport-Security" not in without, \
        "HSTS subdomains without HSTS is meaningless and must not leak out"


def test_each_behaviour_flag_shows_up_only_when_it_is_on():
    for flag, tell in (("websockets", "$http_upgrade"),
                       ("block_exploits", "Block Common Exploits"),
                       ("cache_assets", "Cache Assets")):
        on = np.render(np.normalize(spec(**{flag: True})))
        off = np.render(np.normalize(spec(**{flag: False})))
        assert tell in on, flag
        assert tell not in off, flag


def test_a_custom_location_renders_its_own_block_and_its_own_flags():
    text = np.render(np.normalize(spec(websockets=False, locations=[
        {"path": "/api", "forward_scheme": "http", "forward_host": "127.0.0.1",
         "forward_port": 9001, "websockets": True},
    ])))
    assert "location /api {" in text
    assert "http://127.0.0.1:9001" in text
    assert "$http_upgrade" in text, \
        "a location's own websocket flag must apply even when the host's is off"


def test_a_stream_host_renders_a_stream_block_not_a_server_name():
    text = np.render(np.normalize(spec(listen_scheme="tcp", listen_port=15432,
                                       forward_port=5432)))
    assert "listen 15432;" in text
    assert "proxy_pass 127.0.0.1:5432;" in text
    assert "server_name" not in text


def test_a_udp_stream_says_udp_on_the_listen_line():
    text = np.render(np.normalize(spec(listen_scheme="udp", listen_port=15353,
                                       forward_port=53)))
    assert "listen 15353 udp;" in text


def test_the_embedded_spec_is_a_single_comment_line_so_nginx_ignores_it():
    text = np.render(np.normalize(spec()))
    meta = [l for l in text.splitlines() if l.startswith(np.META_PREFIX)]
    assert len(meta) == 1
    assert json.loads(meta[0][len(np.META_PREFIX):])["domain"] == "app.example.com"


def test_nothing_a_caller_types_can_break_out_of_the_config():
    """Validation is the only thing standing between a form field and a
    directive nginx will execute, so a rejected spec must never be rendered."""
    for bad in ("127.0.0.1;\n}\nserver {\n  listen 9999;", "1.1.1.1 # }",
                "x\n  proxy_pass http://evil;"):
        assert np.validate(spec(forward_host=bad)), bad


def test_a_domain_with_a_newline_cannot_smuggle_a_directive():
    assert np.validate(spec(domain="ok.example.com;\n}\nserver{"))


# ---------------------------------------------------------------- stream gate
def test_stream_support_needs_both_a_directory_and_a_loaded_module(monkeypatch):
    monkeypatch.setattr(np, "_stream_dir", lambda: "/etc/nginx/stream.d")
    monkeypatch.setattr(np, "stream_module_available", lambda: (False, "not loaded"))
    assert np.stream_supported() is False
    assert "not loaded" in np.stream_problem()

    monkeypatch.setattr(np, "stream_module_available", lambda: (True, ""))
    assert np.stream_supported() is True
    assert np.stream_problem() == ""


def test_a_missing_stream_directory_is_reported_as_the_reason(monkeypatch):
    monkeypatch.setattr(np, "_stream_dir", lambda: None)
    monkeypatch.setattr(np, "stream_module_available", lambda: (True, ""))
    assert np.stream_supported() is False
    assert "stream config directory" in np.stream_problem()


def test_this_host_reports_its_real_stream_state_without_raising():
    ok, reason = np.stream_module_available()
    assert isinstance(ok, bool)
    assert ok or reason, "an unavailable stream module must explain itself"
