"""Who is knocking, and should they be let in.

The panel already had tables for web login attempts, blocked addresses and
blocked devices, and readers for all of them, but nothing on the login path ever
wrote a row or checked a block. This module is the missing middle: it turns a
request into an identity (address plus device), decides whether that identity is
currently allowed to try, and answers the counts the Logs tab shows.

Two rules shape the design.

A blocked caller gets the ordinary wrong-credentials answer. Telling them they
are blocked tells them the lockout exists, how long it lasts, and that a
different address would get further. They learn nothing here.

An attempted password is never stored. People mistype, so the column would fill
with real passwords, one character off, in plain text. What an attacker tried is
not worth keeping a password store for.
"""
import hashlib
import re

# The device identity is built from headers a browser sends on every request.
# Not a unique id and not meant to be: it separates one machine and browser
# from another well enough that five failures from one of them is a signal, and
# it cannot be turned off without also changing it.
_FP_HEADERS = (
    "user-agent",
    "accept-language",
    "accept-encoding",
    "sec-ch-ua",
    "sec-ch-ua-platform",
    "sec-ch-ua-mobile",
)

FAIL_LIMIT = 5
BLOCK_HOURS = 24

RANGES = {
    "today": ("Today", "1 day"),
    "3days": ("Last 3 days", "3 days"),
    "week":  ("Last week", "7 days"),
    "month": ("Last month", "30 days"),
}
DEFAULT_RANGE = "today"


def range_interval(name):
    """(label, postgres interval) for a range the UI asked for. An unknown name
    falls back rather than failing, because it arrives from a query string."""
    label, interval = RANGES.get(name) or RANGES[DEFAULT_RANGE]
    return label, interval


def _headers_of(request):
    try:
        return request.headers
    except AttributeError:
        return {}


def fingerprint(request):
    """(fp_hash, summary). The hash identifies the device; the summary is what a
    person reads in the Logs tab to recognise it."""
    headers = _headers_of(request)
    parts = []
    for name in _FP_HEADERS:
        try:
            value = headers.get(name) or ""
        except AttributeError:
            value = ""
        parts.append(f"{name}={value.strip()[:300]}")
    raw = "\n".join(parts)
    fp_hash = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]
    return fp_hash, describe(headers)


_BROWSERS = (
    ("Edg/", "Edge"), ("OPR/", "Opera"), ("Chrome/", "Chrome"),
    ("Firefox/", "Firefox"), ("Safari/", "Safari"), ("curl/", "curl"),
    ("Wget/", "wget"), ("python-requests", "python-requests"),
)
_PLATFORMS = (
    ("Windows NT 10", "Windows"), ("Windows", "Windows"),
    ("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
    ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux"),
)


def describe(headers):
    """A short human label for a device: "Chrome 141 on Linux, en-US".

    Deliberately readable rather than complete. The full header set is what the
    hash is built from; this is so somebody scanning the log can tell their own
    laptop from whatever is hammering the login page.
    """
    try:
        ua = (headers.get("user-agent") or "").strip()
        lang = (headers.get("accept-language") or "").strip()
    except AttributeError:
        ua, lang = "", ""
    if not ua:
        return "no user agent"

    browser = "unknown browser"
    for tell, name in _BROWSERS:
        if tell in ua:
            browser = name
            m = re.search(re.escape(tell) + r"([0-9]+)", ua)
            if m:
                browser = f"{name} {m.group(1)}"
            break

    platform = ""
    for tell, name in _PLATFORMS:
        if tell in ua:
            platform = name
            break

    bits = [browser]
    if platform:
        bits.append("on " + platform)
    first_lang = lang.split(",")[0].strip()
    if first_lang:
        bits.append(first_lang)
    return ", ".join([" ".join(bits[:2])] + bits[2:])[:160]


def is_private(ip):
    """Whether an address is on a local network. Recorded for context only: a
    private address gets blocked exactly like a public one, because the machine
    on the desk next to the server is not more trustworthy than the internet."""
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local
