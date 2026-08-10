"""The avatar upload is a file one signed-in person hands to every other one.

So the tests that matter are not "does a valid PNG survive" but "what happens to
a file built to do something else". Each payload below is a real technique:
script in an SVG, an event handler, an external fetch, an entity expansion, a
scheme in an attribute, a PNG with a polyglot tail. None of them may come back
out of the sanitizer, and the reason none of them can is that nothing is copied
across unless it was recognised first.
"""
import struct
import zlib

import pytest

import identity


# --------------------------------------------------------------------------- #
# names
# --------------------------------------------------------------------------- #
def test_a_name_cannot_smuggle_a_second_mail_header():
    """This name ends up in a From header. A carriage return in it would end
    that header and start one of the sender's choosing."""
    name = identity.clean_name("Nahom\r\nBcc: everyone@example.com")
    assert "\r" not in name and "\n" not in name
    assert name == "Nahom Bcc: everyone@example.com"


def test_a_name_cannot_carry_angle_brackets():
    """From: "Nahom" <admin@x> is a shape, and a name holding its own brackets
    breaks it. Escaping saves the HTML, not the address."""
    assert "<" not in identity.clean_name('Na<script>hom')
    assert ">" not in identity.clean_name("Nahom>")


@pytest.mark.parametrize("raw,why", [
    ("", "empty"),
    ("   ", "whitespace only"),
    ("x", "one character"),
    ("12 34", "no letters"),
])
def test_names_that_are_refused(raw, why):
    assert identity.name_problem(raw), why


def test_a_name_is_bounded():
    assert len(identity.clean_name("n" * 500)) == identity.NAME_MAX


def test_initials_fall_back_all_the_way_to_the_username():
    assert identity.initials("Nahom Berhe") == "NB"
    assert identity.initials("", "limbo") == "LI"
    assert identity.initials("madonna") == "MA"
    assert identity.initials("ops.team.lead") == "OL"
    assert identity.initials("", "") == "?"


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #
def _png(width=8, height=8, color=6, extra=b"", end=True):
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0)
    body = zlib.compress(b"\x00" + b"\xff" * (width * 4) * height)
    out = identity._PNG_MAGIC + chunk(b"IHDR", ihdr) + extra + chunk(b"IDAT", body)
    return out + (chunk(b"IEND", b"") if end else b"")


def test_a_real_png_survives():
    kind, data = identity.clean_upload(_png())
    assert kind == "png"
    assert data.startswith(identity._PNG_MAGIC)
    assert data.endswith(b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF))


def test_a_png_comes_back_without_its_metadata():
    """A tEXt chunk can hold anything, including markup. It is not sanitized, it
    is simply never copied into the rebuilt file."""
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    payload = b"Comment\x00<script>alert(1)</script>"
    raw = _png(extra=chunk(b"tEXt", payload))
    assert payload in raw
    _, cleaned = identity.clean_upload(raw)
    assert b"script" not in cleaned
    assert b"tEXt" not in cleaned


def test_a_png_with_html_appended_does_not_keep_it():
    """The polyglot: a valid image with a document glued on the end, served back
    and hoped to be sniffed as HTML. Rebuilding stops at IEND."""
    raw = _png() + b"<html><script>alert(1)</script>"
    _, cleaned = identity.clean_upload(raw)
    assert b"<html" not in cleaned and b"script" not in cleaned


def test_a_png_with_a_broken_checksum_is_refused():
    raw = bytearray(_png())
    raw[-5] ^= 0xFF
    with pytest.raises(ValueError, match="checksum"):
        identity.clean_upload(bytes(raw))


def test_a_png_that_never_ends_is_refused():
    with pytest.raises(ValueError, match="never ends"):
        identity.clean_upload(_png(end=False))


def test_a_png_claiming_an_enormous_chunk_is_refused():
    raw = identity._PNG_MAGIC + struct.pack(">I", 0xFFFFFF00) + b"IHDR" + b"\x00" * 8
    with pytest.raises(ValueError):
        identity.clean_upload(raw)


def test_a_png_too_many_pixels_a_side_is_refused():
    with pytest.raises(ValueError, match="pixels"):
        identity.clean_upload(_png(width=4000, height=4000))


def test_a_file_larger_than_the_cap_is_refused_before_anything_else():
    with pytest.raises(ValueError, match="KB"):
        identity.clean_upload(b"\x89PNG\r\n\x1a\n" + b"x" * identity.MAX_UPLOAD)


# --------------------------------------------------------------------------- #
# SVG, the part that can actually run code
# --------------------------------------------------------------------------- #
GOOD_SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="7" fill="#bd5b3d"/>
  <circle cx="16" cy="16" r="6" fill="#fff"/>
</svg>"""


def test_a_real_svg_survives_with_its_drawing_intact():
    kind, data = identity.clean_upload(GOOD_SVG)
    assert kind == "svg"
    text = data.decode()
    assert "<rect" in text and "<circle" in text
    assert 'fill="#bd5b3d"' in text
    assert 'xmlns="http://www.w3.org/2000/svg"' in text
    assert 'viewBox="0 0 32 32"' in text


ATTACKS = {
    "a script element": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <script>alert(document.cookie)</script><rect width="10" height="10"/></svg>""",
    "an event handler": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <rect width="10" height="10" onload="alert(1)" onmouseover="alert(2)"/></svg>""",
    "a script in a style attribute": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <rect width="10" height="10" style="background:url(javascript:alert(1))"/></svg>""",
    "an embedded stylesheet": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <style>@import url(http://evil.example/x.css);</style><rect width="10" height="10"/></svg>""",
    "html smuggled through foreignObject": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject>
        <rect width="10" height="10"/></svg>""",
    "an external image": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <image href="http://evil.example/track.png" width="10" height="10"/><rect width="10" height="10"/></svg>""",
    "an animation that fires script": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <rect width="10" height="10"><animate attributeName="fill" onbegin="alert(1)"/></rect></svg>""",
    "a link": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <a href="javascript:alert(1)"><rect width="10" height="10"/></a></svg>""",
    "an external use reference": b"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">
        <use xlink:href="http://evil.example/x.svg#a"/><rect width="10" height="10"/></svg>""",
    "a data uri in a fill": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <rect width="10" height="10" fill="url(data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=)"/></svg>""",
    "a handler element": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <handler type="text/javascript">alert(1)</handler><rect width="10" height="10"/></svg>""",
    "a set element rewriting an attribute": b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <rect width="10" height="10"><set attributeName="onclick" to="alert(1)"/></rect></svg>""",
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_nothing_executable_survives_the_sanitizer(name):
    raw = ATTACKS[name]
    try:
        kind, data = identity.clean_upload(raw)
    except ValueError:
        # Refusing the file outright is the other acceptable answer, and the one
        # that happens when the payload was the only thing in it: dropping an
        # unrecognised element takes its children with it, deliberately, so a
        # drawing hidden inside a <a href="javascript:..."> goes too.
        return
    text = data.decode().lower()
    assert kind == "svg"
    for banned in ("script", "onload", "onmouseover", "onbegin", "onclick",
                   "javascript:", "foreignobject", "<image", "<use", "<a ",
                   "<style", "@import", "http://evil.example", "data:",
                   "<handler", "<set", "<animate"):
        assert banned not in text, f"{name}: {banned} came back out"


def test_an_entity_expansion_is_refused_before_it_is_parsed():
    """The billion laughs: a small file that becomes gigabytes inside the parser.
    The refusal has to happen on the bytes, because by parse time it is over."""
    bomb = (b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><desc>&b;</desc>'
            b'<rect width="1" height="1"/></svg>')
    with pytest.raises(ValueError, match="document type"):
        identity.clean_upload(bomb)


def test_a_file_reading_entity_is_refused():
    """The other half of the same door: an entity pointed at a file on disk."""
    xxe = (b'<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><desc>&x;</desc>'
           b'<rect width="1" height="1"/></svg>')
    with pytest.raises(ValueError, match="document type"):
        identity.clean_upload(xxe)


def test_a_local_gradient_reference_still_works():
    """The sanitizer has to leave real drawings alone, or people cannot use it.
    url(#id) inside the same file is the one url() form allowed."""
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
      <defs><linearGradient id="g1"><stop offset="0" stop-color="#fff"/>
      <stop offset="1" stop-color="#000"/></linearGradient></defs>
      <rect width="20" height="20" fill="url(#g1)"/></svg>"""
    _, data = identity.clean_upload(svg)
    text = data.decode()
    assert 'id="g1"' in text and 'fill="url(#g1)"' in text
    assert "<linearGradient" in text and text.count("<stop") == 2


def test_an_svg_with_no_viewbox_gets_one_from_its_size():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48"><rect width="48" height="48"/></svg>'
    _, data = identity.clean_upload(svg)
    assert 'viewBox="0 0 48 48"' in data.decode()


def test_an_svg_with_nothing_measurable_is_refused():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%"><rect/></svg>'
    with pytest.raises(ValueError, match="viewBox"):
        identity.clean_upload(svg)


def test_an_svg_that_is_only_a_script_leaves_nothing_to_draw():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><script>alert(1)</script></svg>'
    with pytest.raises(ValueError, match="nothing to draw"):
        identity.clean_upload(svg)


def test_an_svg_with_too_many_elements_is_refused():
    body = b"<rect width='1' height='1'/>" * 500
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">' + body + b"</svg>"
    with pytest.raises(ValueError, match="too many elements"):
        identity.clean_upload(svg)


def test_something_that_is_neither_format_is_refused():
    for raw in (b"GIF89a....", b"%PDF-1.4", b"<html><body>hi</body></html>",
                b"\xff\xd8\xff\xe0JFIF"):
        with pytest.raises(ValueError, match="PNG and SVG"):
            identity.clean_upload(raw)


def test_the_kind_is_decided_by_the_bytes_not_by_a_claim():
    """A file called avatar.png holding a script-bearing SVG must be treated as
    the SVG it is and cleaned, not waved through as a PNG."""
    assert identity.sniff(ATTACKS["a script element"]) == "svg"
    assert identity.sniff(_png()) == "png"
    assert identity.sniff(b"<html>") == ""


# --------------------------------------------------------------------------- #
# BIMI
# --------------------------------------------------------------------------- #
def test_bimi_needs_a_square_svg_and_says_so_when_it_does_not_have_one():
    assert identity.bimi_problem("png", b"") .startswith("BIMI needs an SVG")
    _, square = identity.clean_upload(GOOD_SVG)
    assert identity.bimi_problem("svg", square) == ""
    wide = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 32"><rect width="64" height="32"/></svg>'
    _, wide = identity.clean_upload(wide)
    assert "square" in identity.bimi_problem("svg", wide)


def test_the_bimi_logo_carries_what_the_profile_requires():
    _, square = identity.clean_upload(GOOD_SVG)
    out = identity.bimi_svg(square, "Nahom Berhe").decode()
    assert 'baseProfile="tiny-ps"' in out
    assert 'version="1.2"' in out
    assert "<title>Nahom Berhe</title>" in out
    assert 'viewBox="0 0 32 32"' in out
    assert "<rect" in out and "<circle" in out


def test_the_bimi_record_does_not_claim_a_certificate_it_does_not_have():
    record = identity.bimi_record("https://panel.example.com/mgmt/bimi/admin.svg")
    assert record.startswith("v=BIMI1;")
    assert "l=https://panel.example.com/mgmt/bimi/admin.svg" in record
    assert record.rstrip().endswith("a=")
