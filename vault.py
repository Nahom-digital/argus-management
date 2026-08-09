# Symmetric encryption for secrets that must be read back in plaintext later
# (an SSH private key, a root password) rather than only verified, like the
# admin password. Everything else in this app is one-way hashed; this module
# is the one place something reversible is stored, and it stays reversible
# only inside this process, keyed by a local file, never in the database.
import os
import stat

# Imported lazily (see _fernet_class below) so this module can be imported
# before the dependency bootstrap has installed `cryptography`, it is only
# needed once encrypt()/decrypt() are actually called.

_KEY_FILENAME = ".vault_key"
_key_cache = None


def _key_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), _KEY_FILENAME)


def _load_or_create_key():
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    path = _key_path()
    if os.path.exists(path):
        with open(path, "rb") as f:
            _key_cache = f.read().strip()
        return _key_cache
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    _key_cache = key
    return key


def _fernet():
    from cryptography.fernet import Fernet
    return Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    """Returns a URL-safe token string, or "" for empty input."""
    if not plaintext:
        return ""
    token = _fernet().encrypt(plaintext.encode())
    return token.decode()


def decrypt(token: str) -> str:
    """Returns the original plaintext, or "" if token is empty/unreadable
    (e.g. the vault key was rotated or the value predates this vault)."""
    if not token:
        return ""
    from cryptography.fernet import InvalidToken
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""
