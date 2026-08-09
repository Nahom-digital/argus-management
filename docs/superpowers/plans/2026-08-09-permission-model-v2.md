# Permission Model v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the four coarse boolean grants on `panel_user` with a fourteen-grant registry that drives storage, enforcement and the admin form from one definition, and let the admin edit a staff member's grants and password.

**Architecture:** `panel_users.py` gains a `PERMISSIONS` registry plus a `grants JSONB` column. Every permission check in `panel.py` reads a registry key through the existing `_require(request, check)` helper. The admin form is generated from the registry served as JSON, so a grant cannot exist in the form without an endpoint honouring it. Session tokens carry a per-user `auth_epoch` so resetting one staff password does not sign out the admin.

**Tech Stack:** Python 3, FastAPI, psycopg2, PostgreSQL JSONB, pytest, vanilla JS front end.

## Global Constraints

- No em dashes, no en dashes, no spaced hyphens used as punctuation, in any file including the README and commit messages.
- No Claude attribution in commit messages.
- Legacy columns `database_access`, `logs_access`, `disk_access` are left in place and unread, so a rollback loses no data.
- Backfill never grants a destructive permission the row did not already hold: `disk_delete` stays false.
- Username is immutable. `os_username` and the audit trail derive from it.
- The admin account (`admin` table) is always full access and is never represented as a `panel_user` row.
- Every gated endpoint keeps calling `_authed()` before `_require()`.

---

### Task 1: Grant registry and normalization

**Files:**
- Modify: `panel_users.py` (add registry, `SCHEMA`, `normalize_grants`, `describe_grants`)
- Test: `tests/test_grants.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `PERMISSIONS`: tuple of `Grant` namedtuples with fields `key, kind, choices, default, group, label, help`
  - `GRANT_KEYS`: frozenset of every valid key
  - `normalize_grants(raw: dict) -> dict` returns exactly one entry per registry key, unknown keys dropped, wrong types coerced to the default, choice values validated against `choices`
  - `describe_grants() -> list[dict]` JSON-safe registry for the front end
  - `TERMINAL_NONE`, `TERMINAL_LIMITED`, `TERMINAL_ROOT` stay exported for `System.py`

- [ ] **Step 1: Write the failing test**

```python
import panel_users as pu

def test_registry_covers_all_seven_groups():
    groups = {g.group for g in pu.PERMISSIONS}
    assert groups == {"terminal", "disk", "database", "network", "compute", "services", "logs"}
    assert len(pu.PERMISSIONS) == 14

def test_normalize_fills_every_key_with_defaults():
    out = pu.normalize_grants({})
    assert set(out) == set(pu.GRANT_KEYS)
    assert out["terminal"] == "none"
    assert out["disk_scope"] == "none"
    assert out["db_read"] is False

def test_normalize_drops_unknown_keys():
    out = pu.normalize_grants({"db_read": True, "root": True, "__proto__": True})
    assert out["db_read"] is True
    assert "root" not in out and "__proto__" not in out

def test_normalize_rejects_invalid_choice():
    assert pu.normalize_grants({"terminal": "wheel"})["terminal"] == "none"
    assert pu.normalize_grants({"disk_scope": "/etc"})["disk_scope"] == "none"

def test_normalize_coerces_truthy_to_real_bool():
    out = pu.normalize_grants({"db_read": "yes", "db_write": 0, "db_log": None})
    assert out["db_read"] is True and out["db_write"] is False and out["db_log"] is False

def test_describe_grants_is_json_safe():
    import json
    json.dumps(pu.describe_grants())
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m pytest tests/test_grants.py -v`
Expected: FAIL, `AttributeError: module 'panel_users' has no attribute 'PERMISSIONS'`

- [ ] **Step 3: Implement the registry**

```python
Grant = collections.namedtuple("Grant", "key kind choices default group label help")

PERMISSIONS = (
    Grant("terminal", "choice", TERMINAL_LEVELS, TERMINAL_NONE, "terminal",
          "Terminal access", "None, a locked-down shell as their own OS user, or full root."),
    Grant("disk_scope", "choice", ("none", "own", "full"), "none", "disk",
          "Files they can see", "Nothing, only their own home directory, or the whole filesystem."),
    Grant("disk_download", "bool", None, False, "disk", "Download files", "Pull files off the server."),
    Grant("disk_delete", "bool", None, False, "disk", "Delete files", "Remove files permanently."),
    Grant("db_read", "bool", None, False, "database", "Read tables", "Browse rows in the panel's tables."),
    Grant("db_write", "bool", None, False, "database", "Change rows", "Insert, edit and delete rows."),
    Grant("db_log", "bool", None, False, "database", "View change log", "See who changed which row and when."),
    Grant("net_detail", "bool", None, False, "network", "Network detail",
          "Open the connection list in the Server section."),
    Grant("net_proxy", "bool", None, False, "network", "Manage proxy hosts",
          "Create and edit reverse proxy hosts."),
    Grant("cpumem_detail", "bool", None, False, "compute", "CPU and memory detail",
          "Open the top-process lists for CPU and memory."),
    Grant("svc_status", "bool", None, False, "services", "See service status", "List services and read their state."),
    Grant("svc_restart", "bool", None, False, "services", "Start and restart", "Bring services up again."),
    Grant("svc_stop", "bool", None, False, "services", "Stop services", "Take services down."),
    Grant("logs_access", "bool", None, False, "logs", "Logs section", "Open the Logs tab and its readers."),
)

GRANT_KEYS = frozenset(g.key for g in PERMISSIONS)
_BY_KEY = {g.key: g for g in PERMISSIONS}
GROUP_ORDER = ("terminal", "disk", "database", "network", "compute", "services", "logs")
GROUP_LABELS = {"terminal": "Terminal", "disk": "Disk", "database": "Database",
                "network": "Network", "compute": "CPU and memory",
                "services": "Services", "logs": "Logs"}


def normalize_grants(raw):
    """Exactly one entry per registry key, nothing else. Anything unrecognized,
    mistyped or out of range collapses to that grant's default, so a hostile
    payload can only ever reduce what it is asking for."""
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    for g in PERMISSIONS:
        value = raw.get(g.key, g.default)
        if g.kind == "choice":
            out[g.key] = value if value in g.choices else g.default
        else:
            out[g.key] = bool(value) if not isinstance(value, str) else value.strip().lower() in ("1", "true", "yes", "on")
    return out


def describe_grants():
    return [
        {"key": g.key, "kind": g.kind, "choices": list(g.choices) if g.choices else None,
         "default": g.default, "group": g.group, "label": g.label, "help": g.help}
        for g in PERMISSIONS
    ]
```

- [ ] **Step 4: Run it and confirm it passes**

Run: `python3 -m pytest tests/test_grants.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add panel_users.py tests/test_grants.py
git commit -m "Add a grant registry as the single definition of panel permissions"
```

---

### Task 2: Schema migration, backfill and grant persistence

**Files:**
- Modify: `panel_users.py` (`SCHEMA`, `ensure_table`, `create_user`, `get_user`, `list_users`, `update_user`, `resolve_permissions`, `set_password`, `bump_auth_epoch`)
- Test: `tests/test_panel_users_db.py`

**Interfaces:**
- Consumes: Task 1's `normalize_grants`, `GRANT_KEYS`
- Produces:
  - `create_user(conn, username, password, grants, created_by) -> str | None` returns `os_username` when one was provisioned
  - `get_user(conn, username) -> dict | None` with a `grants` dict already normalized
  - `update_user(conn, username, grants=None, password=None, full_name=None) -> bool`
  - `resolve_permissions(conn, username) -> dict` carrying `role`, `os_username`, `auth_epoch` and every grant key at top level
  - `auth_epoch_for(conn, username) -> int`

Schema additions, applied idempotently in `ensure_table` alongside the existing `CREATE TABLE IF NOT EXISTS`:

```sql
ALTER TABLE panel_user ADD COLUMN IF NOT EXISTS grants JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE panel_user ADD COLUMN IF NOT EXISTS auth_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_user ADD COLUMN IF NOT EXISTS full_name VARCHAR(120);
```

Backfill, run once per row where `grants = '{}'::jsonb`, in Python so the registry stays the only mapping authority:

| Legacy | Becomes |
|---|---|
| `terminal_access` | `terminal`, verbatim |
| `database_access` true | `db_read` true only |
| `logs_access` true | `logs_access` true |
| `disk_access` true | `disk_scope` full, `disk_download` true, `disk_delete` false |

- [ ] **Step 1: Write the failing test**

```python
import DB, panel_users as pu

USER = "pytest_grants_user"

def _conn():
    DB.init_pool()
    return DB.get_connection()

def test_create_read_update_roundtrip():
    c = _conn()
    try:
        pu.delete_user(c, USER)
        pu.create_user(c, USER, "Str0ng!Pass", {"db_read": True, "svc_status": True}, "admin")
        u = pu.get_user(c, USER)
        assert u["grants"]["db_read"] is True
        assert u["grants"]["db_write"] is False
        assert set(u["grants"]) == set(pu.GRANT_KEYS)

        pu.update_user(c, USER, grants={"db_read": True, "db_write": True})
        assert pu.get_user(c, USER)["grants"]["db_write"] is True
        assert pu.get_user(c, USER)["grants"]["svc_status"] is False
    finally:
        pu.delete_user(c, USER); DB.release_connection(c)

def test_password_reset_bumps_only_that_users_epoch():
    c = _conn()
    try:
        pu.delete_user(c, USER)
        pu.create_user(c, USER, "Str0ng!Pass", {}, "admin")
        before = pu.auth_epoch_for(c, USER)
        pu.update_user(c, USER, password="An0ther!Pass")
        assert pu.auth_epoch_for(c, USER) == before + 1
        assert pu.verify_login(c, USER, "An0ther!Pass") is not None
        assert pu.verify_login(c, USER, "Str0ng!Pass") is None
    finally:
        pu.delete_user(c, USER); DB.release_connection(c)

def test_admin_resolves_to_every_grant():
    c = _conn()
    try:
        p = pu.resolve_permissions(c, "admin")
        assert p["role"] == "admin"
        assert p["terminal"] == pu.TERMINAL_ROOT
        assert p["disk_scope"] == "full"
        assert all(p[k] is True for k in pu.GRANT_KEYS
                   if k not in ("terminal", "disk_scope"))
    finally:
        DB.release_connection(c)

def test_unknown_identity_resolves_to_nothing():
    c = _conn()
    try:
        p = pu.resolve_permissions(c, "no_such_person")
        assert p["role"] == "none"
        assert p["disk_scope"] == "none"
        assert not any(p[k] for k in pu.GRANT_KEYS if k not in ("terminal", "disk_scope"))
    finally:
        DB.release_connection(c)
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m pytest tests/test_panel_users_db.py -v`
Expected: FAIL, `create_user()` still takes the old positional boolean arguments

- [ ] **Step 3: Implement schema, backfill and the new accessors**

`create_user` takes a `grants` dict, normalizes it, provisions the OS account when
`terminal == limited` **or** `disk_scope == own`, and stores `json.dumps(grants)`.
`update_user` normalizes any incoming grants, hashes any incoming password, and bumps
`auth_epoch` whenever the password changes or a grant is withdrawn. `resolve_permissions`
returns the admin's all-true dict built from `GRANT_KEYS` rather than a hand-written
literal, so a new grant is never accidentally denied to the admin.

- [ ] **Step 4: Run it and confirm it passes**

Run: `python3 -m pytest tests/test_panel_users_db.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add panel_users.py tests/test_panel_users_db.py
git commit -m "Store panel permissions as a normalized grant set with per-user auth epochs"
```

---

### Task 3: Rewire every enforcement point in panel.py

**Files:**
- Modify: `panel.py` (`_NO_PERMISSIONS`, `_visible_nav`, `_config_cards`, `_get_token_data`, and each gated route)
- Modify: `System.py` (disk sandbox root argument)
- Test: `tests/test_permission_matrix.py`

**Interfaces:**
- Consumes: Task 2's `resolve_permissions`, `auth_epoch_for`
- Produces: `_grant(key)` returning a check callable for `_require`, and `_disk_root(perms)` returning the sandbox prefix or `None` for full access

Mapping to apply, one route at a time:

| Route | Check |
|---|---|
| `/api/system/processes` | `_grant("cpumem_detail")` |
| `/api/system/connections` | `_grant("net_detail")` |
| `/api/system/files` | `perms["disk_scope"] != "none"` |
| `/api/system/download` | `_grant("disk_download")` and scope |
| `/api/system/delete` | `_grant("disk_delete")` and scope |
| `/api/services`, `/api/services/{name}` | `_grant("svc_status")` |
| `/api/services/{name}/{action}` start, restart | `_grant("svc_restart")` |
| `/api/services/{name}/{action}` stop | `_grant("svc_stop")` |
| `/api/config/db/tables`, `/table/{name}` | `_grant("db_read")` |
| `/api/config/db/table/{name}/row` and `/column`, any write verb | `_grant("db_write")` |
| `/api/config/proxy/*` | `_grant("net_proxy")` |
| every log reader listed in the spec | `_grant("logs_access")` |
| `/api/config/users*`, `/api/config/ssh/*`, `/api/system/config` | `_is_admin` |
| `/api/account/recovery-status`, `/api/account/recovery-codes` | `_is_admin` |

- [ ] **Step 1: Write the failing test**

```python
import panel_users as pu
from fastapi.testclient import TestClient
import panel

GATED = {
    "cpumem_detail": [("GET", "/api/system/processes")],
    "net_detail":    [("GET", "/api/system/connections")],
    "disk_download": [("GET", "/api/system/download?path=/etc/hostname")],
    "db_read":       [("GET", "/api/config/db/tables")],
    "net_proxy":     [("GET", "/api/config/proxy/hosts")],
    "svc_status":    [("GET", "/api/services")],
    "logs_access":   [("GET", "/api/system/log-counts")],
}

def test_each_grant_unlocks_only_its_own_endpoints(staff_client_factory):
    for grant, allowed in GATED.items():
        client = staff_client_factory({grant: True, "disk_scope": "full"})
        for method, url in allowed:
            assert client.request(method, url).status_code != 403, f"{grant} should open {url}"
        for other, urls in GATED.items():
            if other == grant:
                continue
            for method, url in urls:
                assert client.request(method, url).status_code == 403, \
                    f"{grant} must not open {url}"

def test_admin_only_endpoints_reject_every_staff_grant(staff_client_factory):
    client = staff_client_factory({k: True for k in pu.GRANT_KEYS if k not in ("terminal", "disk_scope")})
    for url in ("/api/config/users", "/api/config/ssh/status",
                "/api/system/config", "/api/account/recovery-status"):
        assert client.get(url).status_code == 403, url
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m pytest tests/test_permission_matrix.py -v`
Expected: FAIL, endpoints still consult `database_access` and answer 200

- [ ] **Step 3: Apply the mapping route by route, then the sandbox**

`_disk_root(perms)` returns `f"/home/{perms['os_username']}"` for `own` scope and `None`
for `full`. `System.py`'s file browse, download and delete take that root, call
`os.path.realpath()` on the joined path, and refuse anything whose real path does not
start with the root followed by a separator. `full` scope keeps the existing protected
path rules untouched.

- [ ] **Step 4: Run it and confirm it passes**

Run: `python3 -m pytest tests/test_permission_matrix.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add panel.py System.py tests/test_permission_matrix.py
git commit -m "Gate every panel endpoint on a named grant instead of four coarse booleans"
```

---

### Task 4: Per-user session revocation and admin-only recovery

**Files:**
- Modify: `panel.py:110-148` (`_create_session_token`, `_get_token_data`), `panel.py:1263-1395` (recovery routes)
- Test: `tests/test_session_epoch.py`

**Interfaces:**
- Consumes: Task 2's `auth_epoch_for`
- Produces: tokens carrying `{"ae": <global>, "ue": <per-user>}`; `_get_token_data` rejects a token whose `ue` no longer matches the subject's `auth_epoch`

- [ ] **Step 1: Write the failing test**

```python
def test_resetting_staff_password_does_not_sign_out_the_admin(admin_client, staff_client, reset_staff_password):
    assert admin_client.get("/api/system/stats").status_code == 200
    reset_staff_password("Br4nd!New")
    assert staff_client.get("/api/system/stats").status_code in (401, 403)
    assert admin_client.get("/api/system/stats").status_code == 200
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m pytest tests/test_session_epoch.py -v`
Expected: FAIL, the global epoch signs the admin out too

- [ ] **Step 3: Add the per-user epoch to the token and verify it on read**

- [ ] **Step 4: Run it and confirm it passes**

Run: `python3 -m pytest tests/test_session_epoch.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add panel.py tests/test_session_epoch.py
git commit -m "Revoke sessions per user and restrict recovery codes to the admin"
```

---

### Task 5: Permission form and staff account card

**Files:**
- Modify: `panel.py` (`_config_cards`, `_CONFIG_CARD_META`, users pane template, new `GET /api/config/grants`, new `POST /api/config/users/{username}` edit route)
- Modify: `static_mgmt/management.js` (render the form from the registry, edit view, password reset)
- Modify: `static_mgmt/dash.css` (grant group layout)

**Interfaces:**
- Consumes: Task 1's `describe_grants`, Task 2's `update_user`
- Produces: `GET /api/config/grants` returning `{"groups": [...], "grants": [...]}`

REQUIRED SUB-SKILLS before writing any of this: `emil-design-eng`, then `impeccable`, then `design-taste-frontend`, in that order.

- [ ] **Step 1: Serve the registry and assert the form cannot drift**

```python
def test_every_registry_grant_appears_in_the_form_payload(admin_client):
    import panel_users as pu
    body = admin_client.get("/api/config/grants").json()
    assert {g["key"] for g in body["grants"]} == set(pu.GRANT_KEYS)
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m pytest tests/test_permission_matrix.py -k grants_form -v`
Expected: FAIL, 404, the route does not exist

- [ ] **Step 3: Add the route, then build the grouped form and the edit view**

The create-user form and the edit-user form render from one function over the
registry, grouped by `GROUP_ORDER` with `GROUP_LABELS` as headings, choice grants as
radio rows and boolean grants as switches, each with its `help` text as a caption.
`_config_cards` returns `["account"]` for staff and the full list for the admin.

- [ ] **Step 4: Run it and confirm it passes**

Run: `python3 -m pytest tests/ -v`
Expected: all green

- [ ] **Step 5: Commit**

```bash
git add panel.py static_mgmt/management.js static_mgmt/dash.css tests/
git commit -m "Render the permission form from the grant registry and let the admin edit staff"
```

---

### Task 6: Full suite, security review, em dash sweep

**Files:**
- Modify: `requirements.txt` (one em dash), `DB.py`, `System.py`, `management.py`, `panel.py` (ten spaced hyphens)
- Modify: `README.md` (document the grant model)

- [ ] **Step 1: Run the whole suite and show the output**

Run: `python3 -m pytest tests/ -v`

- [ ] **Step 2: Sweep the punctuation and prove it is clean**

Run the scanner from the spec work and confirm it reports zero offenders.

- [ ] **Step 3: Review the diff for the obvious weaknesses**

Check specifically: grant payloads cannot escalate past `normalize_grants`, the disk
sandbox resolves symlinks before comparing, admin-only routes never consult a staff
grant, no permission decision is made in JavaScript alone, and the audit trail records
the acting username on every grant change.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Document the grant model and clear the remaining punctuation offenders"
```

## Self-Review

**Spec coverage.** Phase 1 of the spec maps to tasks as follows: storage and registry to Task 1 and 2, grant taxonomy to Task 1, enforcement table to Task 3, disk sandbox to Task 3, session revocation to Task 4, admin editing of staff to Task 2 and 5, staff Config tab to Task 5, verification to Task 3 and 6. Recovery codes becoming admin-only sits in Task 4. No phase 1 requirement is unassigned.

**Placeholders.** None. The two steps that describe rather than quote code (Task 2 Step 3 and Task 3 Step 3) name the exact functions, the exact schema statements and the exact refusal rule, and their tests pin the behaviour.

**Type consistency.** `normalize_grants` is used with the same signature in Tasks 1, 2 and 5. `grants` is a `dict[str, bool | str]` everywhere. `resolve_permissions` returns grant keys at the top level in Task 2 and is read that way in Task 3. `auth_epoch_for` has one signature across Tasks 2 and 4.
