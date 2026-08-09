"""No em dashes, en dashes, or hyphens standing in for them.

This is a hard project rule, and it is cheaper to keep than to clean up, so it
gets a test rather than a habit.

Telling prose apart from arithmetic by regex does not work: "Required - issuing"
and "now - last" look identical to a pattern. So Python files are tokenized and
only string and comment tokens are examined, which is exact. Other file types
are scanned whole, minus CSS calc() where a spaced hyphen is required syntax.
"""
import glob
import io
import os
import re
import tokenize

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BANNED_CHARS = {"—": "em dash", "–": "en dash", "―": "horizontal bar"}
BANNED_ENTITIES = re.compile(r"&(?:mdash|ndash|#8212|#8211|#x2014|#x2013);")
# One spaced hyphen or several: "a -- b" is the same em dash worn as a disguise,
# and it reads exactly as machine-written as the character it stands in for.
SPACED_HYPHEN = re.compile(r"(?<=[A-Za-z,;:)\]}])\s-{1,3}\s(?=[A-Za-z\[{(])")

# These two files must contain the characters they police in order to test for
# them at all, so they are exempt.
SKIP = {"tests/test_punctuation.py", "tests/test_dashboard_render.py"}


def _files():
    patterns = ("*.py", "*.md", "*.txt", "*.json", "static_mgmt/*",
                "docs/**/*.md", "tests/*.py")
    out = []
    for pat in patterns:
        for path in glob.glob(os.path.join(ROOT, pat), recursive=True):
            rel = os.path.relpath(path, ROOT)
            if os.path.isfile(path) and rel not in SKIP:
                out.append(rel)
    return sorted(set(out))


def _prose_spans(rel, text):
    """(line_number, text) pairs that are prose rather than code."""
    if rel.endswith(".py"):
        spans = []
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type in (tokenize.STRING, tokenize.COMMENT):
                    spans.append((tok.start[0], tok.string))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            # An unparseable file is a different failure; do not mask it here.
            return [(i, l) for i, l in enumerate(text.split("\n"), 1)]
        return spans
    return [(i, l) for i, l in enumerate(text.split("\n"), 1)
            if "calc(" not in l]


SQL_TELL = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|GROUP BY|HAVING|"
                      r"CREATE TABLE|ALTER TABLE|JOIN|ORDER BY)\b")


def _looks_like_sql(chunk):
    """A SQL string is code that happens to live in a string literal, so its
    arithmetic ("now() - make_interval(...)") is not prose punctuation."""
    return bool(SQL_TELL.search(chunk))


@pytest.mark.parametrize("rel", _files())
def test_file_has_no_dash_punctuation(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        text = f.read()

    problems = []
    for i, line in enumerate(text.split("\n"), 1):
        for char, name in BANNED_CHARS.items():
            if char in line:
                problems.append(f"L{i} {name}: {line.strip()[:90]}")
    for line_no, chunk in _prose_spans(rel, text):
        if BANNED_ENTITIES.search(chunk):
            problems.append(f"L{line_no} dash entity: {chunk.strip()[:90]}")
        if SPACED_HYPHEN.search(chunk) and not _looks_like_sql(chunk):
            problems.append(f"L{line_no} spaced hyphen: {chunk.strip()[:90]}")

    assert not problems, f"{rel} contains dash punctuation:\n  " + "\n  ".join(problems)


def test_the_scanner_actually_catches_things():
    """Without this the suite could pass because nothing ever matches.

    Note that excluding arithmetic is the tokenizer's job, not the pattern's:
    the pattern cannot tell "now - last" from prose, and is not asked to.
    """
    assert BANNED_ENTITIES.search("a &mdash; b")
    assert SPACED_HYPHEN.search("Required - issuing new codes retires them.")
    assert SPACED_HYPHEN.search("check() - always call _authed() first")
    assert SPACED_HYPHEN.search("not installed -- install it manually")
    assert SPACED_HYPHEN.search("no setuid --- refuse to run as root")
    assert not SPACED_HYPHEN.search("offset = (page - 1) * rows")
    assert not SPACED_HYPHEN.search("a-b, well-known, key-only")
    assert not SPACED_HYPHEN.search("run with --upgrade to pull new code")
    assert not SPACED_HYPHEN.search("pass -y to apt-get")


def test_python_tokenizing_separates_prose_from_arithmetic():
    src = 'x = now - last\ny = "Required - issuing new codes"\n# note - a comment\n'
    found = [c for _, c in _prose_spans("thing.py", src) if SPACED_HYPHEN.search(c)]
    assert len(found) == 2, found
