"""Who somebody is, as the rest of the panel shows them: a name and a picture.

Two reasons this is its own table rather than columns on panel_user.

The admin is not in panel_user at all, it lives in the admin table, so anything
keyed only to staff rows cannot describe the one account that is always there.
And mail needs one lookup that answers "what name and face goes on this
message" without caring which of the two tables the sender came from.

The upload is the part worth reading carefully. An avatar is a file a signed-in
person hands the server, which the server then serves back to every other
signed-in person, so it is an XSS delivery route unless three separate things
are true:

  1. Nothing arbitrary is stored. Both accepted formats are rebuilt from an
     allowlist rather than scrubbed of known-bad patterns. A PNG is
     re-serialized from the chunks we recognise, an SVG is re-serialized from
     the elements and attributes we recognise, and anything else in the file is
     gone because it was never copied across.
  2. It is never inlined. An SVG in an <img> cannot run script or fetch
     anything, whatever it contains. The panel only ever renders avatars that
     way, and a test holds that line.
  3. It is served defensively anyway: its own restrictive CSP, nosniff, and no
     ability to become a document. That is the third layer, not the first.

A stored SVG doubles as a BIMI logo, which is the same picture published for
receiving mail servers to fetch, so the same sanitizer covers both.
"""
import binascii
import hashlib
import re
import struct
import xml.etree.ElementTree as ET

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS panel_identity (
        username     VARCHAR(100) PRIMARY KEY,
        full_name    VARCHAR(120) NOT NULL DEFAULT '',
        avatar_kind  VARCHAR(8)   NOT NULL DEFAULT '',
        avatar       BYTEA,
        avatar_hash  VARCHAR(64)  NOT NULL DEFAULT '',
        updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
    )""",
)

# Bigger than any sensible avatar and small enough that a request body is never
# a way to spend the server's memory. Checked before the bytes are read.
MAX_UPLOAD = 512 * 1024
MAX_SVG_OUT = 64 * 1024
MAX_PIXELS = 2048
NAME_MAX = 120

_schema_ready = False


def ensure_schema(conn):
    global _schema_ready
    if _schema_ready:
        return
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    conn.commit()
    cur.close()
    _schema_ready = True


# --------------------------------------------------------------------------- #
# the display name
# --------------------------------------------------------------------------- #
# A name reaches a mail header, so a carriage return in it is a way to add a
# second header. It also reaches HTML, which is escaped at every point of use,
# but angle brackets in a From name break the address form itself, so they go.
_NAME_BAD = re.compile(r"[\x00-\x1f\x7f<>\"\\]")


def clean_name(raw):
    """The name as it will be stored: one line, trimmed, bounded."""
    text = _NAME_BAD.sub(" ", str(raw or ""))
    return re.sub(r"\s+", " ", text).strip()[:NAME_MAX]


def name_problem(raw):
    """Why this name cannot be used, or "" if it can."""
    name = clean_name(raw)
    if not name:
        return "A name cannot be empty."
    if len(name) < 2:
        return "That name is too short."
    if not re.search(r"[A-Za-z]", name):
        return "A name needs at least one letter."
    return ""


def initials(full_name, username=""):
    """The two letters shown when there is no picture."""
    source = (full_name or "").strip() or (username or "").strip()
    parts = [p for p in re.split(r"[\s._-]+", source) if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][:1] + parts[-1][:1]).upper()


# --------------------------------------------------------------------------- #
# PNG: rebuilt from the chunks we recognise
# --------------------------------------------------------------------------- #
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
# Everything needed to draw the image, and nothing that carries text, colour
# profiles, or private data. Metadata is not sanitized, it is simply not copied.
_PNG_KEEP = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND",
             b"gAMA", b"sRGB", b"cHRM", b"pHYs", b"bKGD"}
_PNG_COLOR_TYPES = {0, 2, 3, 4, 6}


def _png_chunk(kind, data):
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF))


def clean_png(raw):
    """A PNG rebuilt from its recognised chunks, or ValueError.

    Rebuilding rather than trusting means a file that is half PNG and half
    something else cannot survive: only the parts we understood are written out.
    """
    if not raw.startswith(_PNG_MAGIC):
        return None
    pos = len(_PNG_MAGIC)
    out = [_PNG_MAGIC]
    seen = []
    color_type = None
    while pos + 8 <= len(raw):
        (length,) = struct.unpack(">I", raw[pos:pos + 4])
        kind = raw[pos + 4:pos + 8]
        if length > len(raw) or pos + 12 + length > len(raw):
            raise ValueError("That PNG is truncated or malformed.")
        data = raw[pos + 8:pos + 8 + length]
        (crc,) = struct.unpack(">I", raw[pos + 8 + length:pos + 12 + length])
        if crc != (binascii.crc32(kind + data) & 0xFFFFFFFF):
            raise ValueError("That PNG is corrupt: a checksum does not match.")
        if not re.fullmatch(rb"[A-Za-z]{4}", kind):
            raise ValueError("That PNG is malformed.")
        seen.append(kind)
        if kind == b"IHDR":
            if length != 13:
                raise ValueError("That PNG has an invalid header.")
            width, height, depth, color, comp, filt, inter = struct.unpack(">IIBBBBB", data)
            if not (0 < width <= MAX_PIXELS and 0 < height <= MAX_PIXELS):
                raise ValueError(f"Use an image no larger than {MAX_PIXELS} pixels a side.")
            if color not in _PNG_COLOR_TYPES or comp != 0 or filt != 0 or inter > 1:
                raise ValueError("That PNG uses a format this does not support.")
            color_type = color
        if kind in _PNG_KEEP:
            out.append(_png_chunk(kind, data))
        pos += 12 + length
        if kind == b"IEND":
            break
    if not seen or seen[0] != b"IHDR":
        raise ValueError("That PNG does not start with a header.")
    if b"IEND" not in seen:
        raise ValueError("That PNG is truncated: it never ends.")
    if b"IDAT" not in seen:
        raise ValueError("That PNG holds no image data.")
    # A palette image with no palette cannot be drawn. Every other colour type
    # does not want one, so this is only a problem for type 3.
    if color_type == 3 and b"PLTE" not in seen:
        raise ValueError("That PNG is missing its colour palette.")
    return b"".join(out)


# --------------------------------------------------------------------------- #
# SVG: rebuilt from the elements and attributes we recognise
# --------------------------------------------------------------------------- #
SVG_NS = "http://www.w3.org/2000/svg"

# Shapes, groups, and the paint that fills them. No <script>, no <a>, no
# <foreignObject>, no <image>, no <use>, no <style>, no animation elements, and
# no <text>: a logo with lettering should carry it as outlines, because text
# depends on fonts the receiver does not have.
_SVG_TAGS = {
    "svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse",
    "line", "polyline", "polygon", "linearGradient", "radialGradient", "stop",
    "clipPath", "mask", "symbol", "marker", "pattern",
}
_SVG_ATTRS = {
    "id", "transform", "opacity", "display", "visibility", "color",
    "fill", "fill-opacity", "fill-rule", "clip-path", "clip-rule", "mask",
    "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin",
    "stroke-dasharray", "stroke-dashoffset", "stroke-opacity",
    "stroke-miterlimit", "vector-effect", "paint-order", "shape-rendering",
    "d", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry",
    "width", "height", "points", "offset", "pathLength",
    "gradientUnits", "gradientTransform", "spreadMethod", "fx", "fy",
    "stop-color", "stop-opacity", "clipPathUnits", "maskUnits",
    "markerWidth", "markerHeight", "patternUnits", "refX", "refY", "orient",
}
_SVG_ROOT_ATTRS = {"viewBox", "version", "baseProfile", "preserveAspectRatio",
                   "width", "height"}
# A value may not carry a scheme, a character reference, or a tag. url() is the
# one function allowed, and only pointing at an id inside this same document.
_VALUE_BAD = re.compile(r"(javascript:|vbscript:|data:|&#|&\w+;|<|>|expression\s*\()", re.I)
_URL_LOCAL = re.compile(r"^url\(\s*#[A-Za-z_][\w.:-]*\s*\)$")
_ID_OK = re.compile(r"^[A-Za-z_][\w.:-]{0,63}$")
_NUM = re.compile(r"^-?\d+(\.\d+)?$")
_MAX_ELEMENTS = 400


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _attr_ok(name, value):
    if name.lower().startswith("on") or "script" in name.lower():
        return False
    if len(value) > 1024 or _VALUE_BAD.search(value):
        return False
    if "url(" in value.lower() and not _URL_LOCAL.match(value.strip()):
        return False
    if name == "id" and not _ID_OK.match(value):
        return False
    return True


def _copy_element(src, root=False):
    tag = _local(src.tag)
    if tag not in _SVG_TAGS:
        return None
    out = ET.Element(tag)
    allowed = _SVG_ATTRS | _SVG_ROOT_ATTRS if root else _SVG_ATTRS
    for name, value in src.attrib.items():
        # A namespaced attribute is xlink:href or similar: dropped outright,
        # since nothing in the allowlist needs one.
        if "}" in name or ":" in name:
            continue
        if name in allowed and _attr_ok(name, value):
            out.set(name, value.strip())
    text = (src.text or "").strip()
    if tag in ("title", "desc") and text:
        out.text = text[:200]
    for child in list(src):
        kid = _copy_element(child)
        if kid is not None:
            out.append(kid)
    return out


def clean_svg(raw):
    """An SVG rebuilt from the elements and attributes we recognise, or ValueError."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("That SVG is not valid UTF-8 text.")
    # A document type declaration is how an XML parser is talked into reading
    # files off the disk or expanding itself until the process dies. Refused
    # before parsing, because by then it is too late.
    if re.search(r"<!DOCTYPE|<!ENTITY|<\?xml-stylesheet", text, re.I):
        raise ValueError("That SVG carries a document type declaration, which is not accepted.")
    try:
        src = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"That SVG is not well formed: {e}")
    if _local(src.tag) != "svg":
        raise ValueError("That file is not an SVG.")
    if len(list(src.iter())) > _MAX_ELEMENTS:
        raise ValueError("That SVG has too many elements to be an avatar.")
    root = _copy_element(src, root=True)
    if root is None:
        raise ValueError("That file is not an SVG.")
    if not len(root):
        raise ValueError("Nothing in that SVG survived checking, so there is nothing to draw.")
    if not root.get("viewBox"):
        w, h = root.get("width", ""), root.get("height", "")
        if _NUM.match(w) and _NUM.match(h):
            root.set("viewBox", f"0 0 {w} {h}")
        else:
            raise ValueError("That SVG needs a viewBox or a plain numeric width and height.")
    root.set("xmlns", SVG_NS)
    out = ET.tostring(root, encoding="unicode")
    if len(out.encode("utf-8")) > MAX_SVG_OUT:
        raise ValueError("That SVG is too large once cleaned.")
    return out.encode("utf-8")


def sniff(raw):
    """png, svg, or "" for anything else. The bytes decide, never the filename
    and never the content type the browser claimed."""
    if raw.startswith(_PNG_MAGIC):
        return "png"
    head = raw[:512].lstrip()
    if head.startswith(b"<") and (b"<svg" in raw[:2048].lower()):
        return "svg"
    return ""


def clean_upload(raw):
    """(kind, bytes) for something we will store, or ValueError with the reason."""
    if not raw:
        raise ValueError("That file is empty.")
    if len(raw) > MAX_UPLOAD:
        raise ValueError(f"Use a file under {MAX_UPLOAD // 1024} KB.")
    kind = sniff(raw)
    if kind == "png":
        return "png", clean_png(raw)
    if kind == "svg":
        return "svg", clean_svg(raw)
    raise ValueError("Only PNG and SVG images are accepted.")


MIME = {"png": "image/png", "svg": "image/svg+xml"}


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #
def _seed_name(conn, username):
    """A staff member whose name the admin already recorded starts with it.

    panel_user.full_name predates this table and the staff form still writes it,
    so it is the sensible default for a row that does not exist yet. It is only
    ever read here: what the person sets themselves lives in panel_identity and
    wins.
    """
    cur = conn.cursor()
    try:
        cur.execute("SELECT full_name FROM panel_user WHERE username = %s", (username,))
        row = cur.fetchone()
    except Exception:
        return ""
    finally:
        cur.close()
    return (row[0] or "") if row else ""


def get(conn, username):
    """Everything about an identity except the picture itself."""
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute("""SELECT full_name, avatar_kind, avatar_hash, updated_at
                   FROM panel_identity WHERE username = %s""", (username,))
    row = cur.fetchone()
    cur.close()
    if not row:
        name = _seed_name(conn, username)
        return {"username": username, "full_name": name, "avatar_kind": "",
                "avatar_hash": "", "has_avatar": False, "updated_at": None,
                "initials": initials(name, username)}
    full_name, kind, digest, updated = row
    return {"username": username, "full_name": full_name or "",
            "avatar_kind": kind or "", "avatar_hash": digest or "",
            "has_avatar": bool(kind),
            # A string, not a datetime: this dict goes straight into a JSON
            # response, and json.dumps has no opinion about timestamps.
            "updated_at": str(updated)[:19] if updated else None,
            "initials": initials(full_name, username)}


def display_name(conn, username):
    """The name to put in front of a person: theirs if they set one, else the
    account name, which is always something."""
    return get(conn, username)["full_name"] or username


def set_full_name(conn, username, raw):
    problem = name_problem(raw)
    if problem:
        return False, problem
    name = clean_name(raw)
    cur = conn.cursor()
    cur.execute("""INSERT INTO panel_identity (username, full_name)
                   VALUES (%s, %s)
                   ON CONFLICT (username) DO UPDATE
                     SET full_name = EXCLUDED.full_name, updated_at = now()""",
                (username, name))
    conn.commit()
    cur.close()
    return True, name


def set_avatar(conn, username, raw):
    """Store a cleaned copy of an uploaded picture. Returns (ok, kind_or_problem)."""
    ensure_schema(conn)
    try:
        kind, data = clean_upload(raw)
    except ValueError as e:
        return False, str(e)
    digest = hashlib.sha256(data).hexdigest()
    cur = conn.cursor()
    cur.execute("""INSERT INTO panel_identity (username, avatar_kind, avatar, avatar_hash)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (username) DO UPDATE
                     SET avatar_kind = EXCLUDED.avatar_kind,
                         avatar = EXCLUDED.avatar,
                         avatar_hash = EXCLUDED.avatar_hash,
                         updated_at = now()""",
                (username, kind, memoryview(data), digest))
    conn.commit()
    cur.close()
    return True, kind


def clear_avatar(conn, username):
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute("""UPDATE panel_identity
                   SET avatar_kind = '', avatar = NULL, avatar_hash = '',
                       updated_at = now()
                   WHERE username = %s""", (username,))
    conn.commit()
    cur.close()
    return True


def avatar(conn, username):
    """(kind, bytes, hash), or (None, None, None) when there is no picture."""
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT avatar_kind, avatar, avatar_hash FROM panel_identity "
                "WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    if not row or not row[0] or row[1] is None:
        return None, None, None
    return row[0], bytes(row[1]), row[2]


def everyone(conn):
    """Every stored identity, for the one place that needs them all at once:
    deciding which senders in a mailbox have a face to show."""
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT username, full_name, avatar_kind, avatar_hash FROM panel_identity")
    rows = cur.fetchall()
    cur.close()
    return {r[0]: {"full_name": r[1] or "", "avatar_kind": r[2] or "",
                   "avatar_hash": r[3] or "", "has_avatar": bool(r[2]),
                   "initials": initials(r[1], r[0])} for r in rows}


# --------------------------------------------------------------------------- #
# BIMI
# --------------------------------------------------------------------------- #
def bimi_problem(kind, svg_bytes):
    """Why this avatar cannot be published as a BIMI logo, or "".

    BIMI is fussy on purpose: a receiving mail server fetches this file and
    draws it beside the message, so it must be an SVG, square, and free of
    anything that would make it depend on the machine drawing it.
    """
    if kind != "svg":
        return "BIMI needs an SVG logo. This account's picture is a PNG."
    try:
        root = ET.fromstring(svg_bytes.decode("utf-8"))
    except Exception:
        return "The stored logo could not be read."
    box = (root.get("viewBox") or "").replace(",", " ").split()
    if len(box) != 4:
        return "The logo has no usable viewBox."
    try:
        _, _, w, h = (float(v) for v in box)
    except ValueError:
        return "The logo has no usable viewBox."
    if abs(w - h) > 0.5:
        return "BIMI needs a square logo, and this one is not square."
    return ""


def bimi_svg(svg_bytes, title):
    """The stored SVG as SVG Tiny PS, which is the only profile BIMI accepts.

    The sanitizer has already removed everything the profile forbids, so this
    adds what it requires: the version and profile markers, and a title, which
    is the accessible name a mail client reads out.
    """
    root = ET.fromstring(svg_bytes.decode("utf-8"))
    out = ET.Element("svg")
    out.set("xmlns", SVG_NS)
    out.set("version", "1.2")
    out.set("baseProfile", "tiny-ps")
    out.set("viewBox", root.get("viewBox", "0 0 512 512"))
    node = ET.SubElement(out, "title")
    node.text = clean_name(title)[:64] or "Logo"
    for child in list(root):
        if _local(child.tag) in ("title", "desc"):
            continue
        # Copied through the same allowlist rather than moved: re-parsing put the
        # SVG namespace back on every element, and moving those into a plain root
        # would publish a logo full of ns0: prefixes.
        kid = _copy_element(child)
        if kid is not None:
            out.append(kid)
    return ET.tostring(out, encoding="unicode").encode("utf-8")


def bimi_record(url):
    """The DNS value that points receivers at the logo. No VMC: one costs money
    and only Gmail insists on it, so the record is honest about not having one."""
    return f"v=BIMI1; l={url}; a="
