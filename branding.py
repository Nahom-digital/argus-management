"""The panel's own mark: the icon in the browser tab.

It is the Argus Recon icon, because the two are one system to the person using
them and a tab strip with both open should say so. The file ships with the panel
(static_mgmt/favicon.svg) rather than being fetched at runtime, which is why
there is nothing here to configure: no button that could fail, no stored copy
that could drift, and no outbound request from the panel to get an icon.

It was taken from Recon once, run through the same allowlist sanitizer an
uploaded avatar is, and committed. Replacing it means replacing that file.
"""
import hashlib
import os

_ASSET = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "static_mgmt", "favicon.svg")

# If the file is missing from a deployment, the tab still needs an icon. This is
# the panel's own crest, the same mark the top bar and the login card carry.
FALLBACK = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
            b'<rect width="32" height="32" rx="7" fill="#8a5a2b"/>'
            b'<g fill="none" stroke="#fbf2e2" stroke-width="2.2" stroke-linecap="round">'
            b'<rect x="7" y="6" width="18" height="8" rx="2.4"/>'
            b'<rect x="7" y="18" width="18" height="8" rx="2.4"/></g></svg>')

_cache = None


def get():
    """(kind, bytes, hash). Read once and kept, because it cannot change while
    the process is running."""
    global _cache
    if _cache is None:
        try:
            with open(_ASSET, "rb") as fh:
                data = fh.read()
        except OSError:
            data = FALLBACK
        if not data.lstrip()[:4].lower().startswith(b"<svg"):
            data = FALLBACK
        _cache = ("svg", data, hashlib.sha256(data).hexdigest()[:16])
    return _cache
