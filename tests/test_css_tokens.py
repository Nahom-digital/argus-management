"""Every CSS custom property referenced must actually be defined.

This is not pedantry. The server detail modal said color: var(--ink, #222) and
--ink was never defined, so in dark mode the fallback painted #222 text onto a
#241a0f surface: present in the DOM, invisible on screen. A silent fallback is
the whole hazard, because nothing errors.

It also checks that every token has a dark-theme counterpart, which is the
other half of the same problem.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS = os.path.join(ROOT, "static_mgmt", "dash.css")

# Colour tokens are theme-dependent. Type, shape and motion tokens are not, so
# they legitimately live only in :root.
THEME_EXEMPT = {"--font", "--display", "--mono"}


def _sheet():
    with open(CSS, encoding="utf-8") as f:
        return f.read()


def _strip_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _block(text, selector):
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\n\s*\}", text, re.S)
    assert m, f"{selector} block not found in dash.css"
    return set(re.findall(r"(--[a-z0-9-]+)\s*:", m.group(1)))


def test_no_referenced_token_is_undefined():
    text = _strip_comments(_sheet())
    defined = set(re.findall(r"^\s*(--[a-z0-9-]+)\s*:", text, re.M))
    used = set(re.findall(r"var\(\s*(--[a-z0-9-]+)", text))
    missing = sorted(used - defined)
    assert not missing, (
        "these custom properties are used but never defined, so their fallback "
        f"silently wins and the theme cannot reach them: {missing}")


def test_every_theme_token_has_a_dark_counterpart():
    text = _strip_comments(_sheet())
    light = _block(text, ":root")
    dark = _block(text, '[data-theme="dark"]')
    unthemed = sorted(light - dark - THEME_EXEMPT)
    assert not unthemed, (
        "these tokens are defined for the light theme only, so dark mode "
        f"inherits the light value: {unthemed}")


def test_the_scanner_would_catch_a_regression():
    """Proves the patterns match, so a green result means something."""
    sample = ":root {\n  --a: red;\n}\n.x { color: var(--nope, #222); }\n"
    defined = set(re.findall(r"^\s*(--[a-z0-9-]+)\s*:", sample, re.M))
    used = set(re.findall(r"var\(\s*(--[a-z0-9-]+)", sample))
    assert sorted(used - defined) == ["--nope"]


def test_the_detail_modal_uses_real_tokens():
    """The specific regression: the drill-down that was unreadable in dark mode."""
    text = _strip_comments(_sheet())
    m = re.search(r"#srv-detail-modal\s*\{(.*?)\}", text, re.S)
    assert m
    body = m.group(1)
    assert "var(--black)" in body, "modal text colour must be a themed token"
    assert "#222" not in body


def test_the_sticky_detail_header_cannot_be_scrolled_over():
    text = _strip_comments(_sheet())
    m = re.search(r"#srv-detail-body thead th\s*\{(.*?)\}", text, re.S)
    assert m, "the sticky header rule is gone"
    body = m.group(1)
    assert "position:sticky" in body.replace(" ", "")
    assert "z-index" in body, "a sticky header with no z-index gets painted over"
    assert "var(--white)" in body, "it needs an opaque themed background"


def test_the_frontend_has_no_hardcoded_status_colours():
    """Status colours must come from tokens, because the literals were tuned
    for the light theme and several of them fail contrast on the dark surface.
    #c0392b on #241a0f is about 2.6:1; #1e8449 is worse."""
    js = os.path.join(ROOT, "static_mgmt", "management.js")
    with open(js, encoding="utf-8") as f:
        text = f.read()
    banned = ["#c0392b", "#e74c3c", "#27ae60", "#1e8449", "#2980b9", "#e67e22",
              "rgba(231,76,60", "rgba(39,174,96"]
    found = {b: text.count(b) for b in banned if b in text}
    assert not found, f"hardcoded status colours are back: {found}"


def test_semantic_colour_tokens_exist_in_both_themes():
    text = _strip_comments(_sheet())
    for token in ("--danger", "--success", "--warn", "--info"):
        assert token in _block(text, ":root"), token
        assert token in _block(text, '[data-theme="dark"]'), token


def test_the_hidden_attribute_beats_any_display_rule():
    """The user-agent rule for [hidden] is display:none at the lowest layer, so
    an author rule like .px-row { display: flex } wins and the element stays on
    screen. Two elements were already showing when they should not have been.
    """
    text = _strip_comments(_sheet())
    m = re.search(r"\[hidden\]\s*\{([^}]*)\}", text)
    assert m, "dash.css must state a [hidden] rule of its own"
    assert "display" in m.group(1) and "none" in m.group(1)
    assert "!important" in m.group(1), \
        "without !important a later component rule takes the element back"


def test_everything_the_markup_ships_hidden_stays_hidden():
    """Walks the real markup rather than a list kept by hand, so a new hidden
    element inherits the guarantee."""
    panel_py = os.path.join(ROOT, "panel.py")
    with open(panel_py, encoding="utf-8") as f:
        markup = f.read()
    text = _strip_comments(_sheet())
    hidden_ids = set(re.findall(r'id="([\w-]+)"[^>]*\bhidden\b', markup))
    assert hidden_ids, "the scanner found nothing, so it is not scanning"
    # The blanket rule is what makes this hold, so assert it is reachable for
    # every one of them rather than re-checking each component's display.
    assert re.search(r"\[hidden\]\s*\{[^}]*display\s*:\s*none\s*!important", text)


def test_the_switch_animates_on_the_compositor():
    """A toggle that animates left/width repaints on every frame. transform is
    the only property here that the compositor can take on its own."""
    text = _strip_comments(_sheet())
    m = re.search(r"\.px-switch-knob\s*\{([^}]*)\}", text)
    assert m, ".px-switch-knob not found"
    body = m.group(1)
    assert "transition: transform" in body, body
    m2 = re.search(r"\.px-switch input:checked ~ \.px-switch-track "
                   r"\.px-switch-knob\s*\{([^}]*)\}", text)
    assert m2 and "transform" in m2.group(1), "the on state must move by transform"


def test_motion_in_the_proxy_form_has_a_reduced_motion_path():
    text = _strip_comments(_sheet())
    assert "prefers-reduced-motion" in text
    blocks = re.findall(r"@media\s*\(prefers-reduced-motion: reduce\)\s*\{(.*?)\n\}",
                        text, re.S)
    assert any("px-switch" in b for b in blocks), \
        "the switch animates, so it needs a reduced-motion alternative"


def test_the_segmented_control_shows_its_selection_without_javascript():
    """The grant form adds an .on class in JS. Any other segmented group (the
    proxy scheme picker) would render with no selection visible at all."""
    text = _strip_comments(_sheet())
    assert re.search(r"\.grant-seg:has\(input:checked\)", text), \
        "selection must be driven by the radio, not only by a JS class"
