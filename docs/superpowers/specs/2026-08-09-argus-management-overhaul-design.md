# Argus Management overhaul, design

Date: 2026-08-09

Ten requested changes, decomposed into nine phases. Permissions come first because
six of the ten items gate on the same grant model. Every phase after phase 1 is
independent and can ship on its own.

## Decisions already taken

These were settled before implementation and must not be relitigated.

| Question | Decision |
|---|---|
| Grant storage | One `grants JSONB` column driven by a `PERMISSIONS` registry, not one column per grant |
| Avatar uploads | Accept PNG, JPEG and SVG, rasterize every upload to PNG on arrival, store only the PNG |
| Staff view of Config | Config tab always visible, containing only their own account card |
| Database `log` grant | Lets the holder view the database change audit log |
| Disk sandbox for `own` scope | `/home/argus_<username>`, auto-created when the grant is given, even with no terminal access |
| mailcow install | Opt-in from the Mail tab, triggered once by an admin. Not a `management.py` startup requirement |
| BIMI | Domain-level record plus SVG Tiny PS logo is one feature. Per-user avatars in outbound mail are a separate feature, embedded in the message MIME |
| Username changes | Not permitted. `os_username` and the audit trail derive from it |

### Why mailcow cannot be a startup requirement

mailcow-dockerized needs Docker Compose, roughly 6GB of RAM, a valid MX record and a
clean PTR record. Installing it on every `management.py` run would break any deploy
lacking those. `management.py` reports whether the prerequisites are present. The
Mail tab performs the install once, on an explicit admin action.

### Why BIMI cannot carry a per-user avatar

BIMI publishes exactly one logo for an entire domain, and Gmail renders it only for
senders holding a Verified Mark Certificate, which requires a registered trademark.
So `fullname@domain.com` cannot show a per-user picture through BIMI. Per-user
avatars are delivered by embedding the image in the message itself. Both are built,
as two separate features.

## Phase 1, permission model v2

Covers request items 1 (permission half), 2 and 9.

### Storage

`panel_user` gains:

- `grants JSONB NOT NULL DEFAULT '{}'`
- `auth_epoch INTEGER NOT NULL DEFAULT 0`

`panel_users.py` gains a `PERMISSIONS` registry: an ordered sequence of grant
definitions carrying key, kind, choices, default, group, label and help text. The
registry is the single source of truth and drives four consumers:

1. validation of incoming grant payloads
2. `resolve_permissions()` output
3. the admin permission form, rendered from the registry
4. the read-only grant list on a staff member's own account card

Generating the form from the same registry the enforcement reads makes it impossible
to ship a checkbox that no endpoint honours, or an endpoint no checkbox exposes.

The four legacy boolean columns stay in place, unread, so a rollback loses nothing.
A one-time backfill maps existing rows conservatively:

| Legacy column | Becomes |
|---|---|
| `database_access` | `db_read` only, no write, no log |
| `logs_access` | `logs_access` |
| `disk_access` | `disk_scope: full`, `disk_download: true`, `disk_delete: false` |
| `terminal_access` | `terminal`, unchanged |

Delete is withheld on backfill deliberately: nobody silently gains a destructive
grant they did not previously hold.

### Grant taxonomy

Fourteen grants in seven groups.

| Group | Key | Kind | Default |
|---|---|---|---|
| Terminal | `terminal` | choice: none, limited, root | none |
| Disk | `disk_scope` | choice: none, own, full | none |
| Disk | `disk_download` | bool | false |
| Disk | `disk_delete` | bool | false |
| Database | `db_read` | bool | false |
| Database | `db_write` | bool | false |
| Database | `db_log` | bool | false |
| Network | `net_detail` | bool | false |
| Network | `net_proxy` | bool | false |
| Compute | `cpumem_detail` | bool | false |
| Services | `svc_status` | bool | false |
| Services | `svc_restart` | bool | false |
| Services | `svc_stop` | bool | false |
| Logs | `logs_access` | bool | false |

Phases 5, 7 and 8 add `firewall_manage`, `tunnel_manage` and `mail_access` to the
registry. No migration is needed to do so, which is the point of the JSONB choice.

### Enforcement

The existing `_require(request, check)` helper stays. Each check reads a registry
grant instead of a legacy boolean.

| Endpoint | Grant |
|---|---|
| `/api/system/processes` | `cpumem_detail` |
| `/api/system/connections` | `net_detail` |
| `/api/system/files` | `disk_scope` is not none |
| `/api/system/download` | `disk_download` |
| `/api/system/delete` | `disk_delete` |
| `/api/services`, `/api/services/{name}` | `svc_status` |
| `/api/services/{name}/start`, `/restart` | `svc_restart` |
| `/api/services/{name}/stop` | `svc_stop` |
| `/api/config/db/tables`, `/api/config/db/table/{name}` | `db_read` |
| `/api/config/db/table/{name}/row`, `/column` writes | `db_write` |
| database change audit view | `db_log` |
| `/api/config/proxy/*` | `net_proxy` |
| `/api/logs*` and every log reader | `logs_access` |
| `/api/config/users*`, `/api/config/ssh/*`, `/api/system/config` | admin only |
| `/api/account/recovery-*` | admin only |

Recovery codes become admin-only, per request item 9. A staff member who forgets
their password asks the admin in person, and the admin resets it from the user list.

### Disk sandbox

With `disk_scope: own`, `/home/argus_<username>` is provisioned at grant time.
Every path from the client is passed through `os.path.realpath()` before the prefix
comparison, so a symlink planted inside the sandbox cannot escape it. With
`disk_scope: full` the existing protected-path rules in `System.py` still apply.

### Session revocation

`_auth_epoch()` in `panel.py` currently revokes tokens globally, so resetting one
staff password would sign out the admin too. It becomes per-user: the token carries
the subject's `auth_epoch`, and the column is bumped when that person's password is
reset or their grants are reduced. Only that user is signed out.

### Admin editing of staff

The user list gains a per-member edit view: the full grant form pre-filled with
current grants, a set-new-password field, and delete. Username is immutable. Every
grant change and password reset writes to the audit trail with the acting admin's
username attached, which is also the groundwork for item 6.

### Staff Config tab

`_visible_nav()` currently hides Config from anyone without `database_access`. It
instead always shows Config, and `_config_cards()` returns `["account"]` for staff:
username, role, grants read-only, and change-own-password.

### Verification

A permission matrix test. For each of the fourteen grants, create a staff account
holding only that grant, call every gated endpoint, and assert 200 for the endpoints
it unlocks and 403 for all the others. Roughly 14 by 20 assertions. This is the only
way to be certain no endpoint was missed.

## Phase 2, server pane fixes

Covers item 1's user interface half.

- The sticky detail-table header at `dash.css:680` hardcodes `background: var(--white,#fff)` and
  carries no `z-index`, so in dark mode it renders light and rows scroll over it.
  Fix: theme token background, explicit `z-index`, and an opaque backdrop.
- Dark mode text contrast across the detail panes: audit every hardcoded colour and
  replace with theme tokens.
- Disk browser gains a delete control for holders of `disk_delete`.
- CPU, memory and network detail panes return 403 and render an explanatory empty
  state when the caller lacks `cpumem_detail` or `net_detail`.

## Phase 3, Config navigation and database viewer

Covers items 2 (navigation half) and 4.

- Config drill-down becomes a full-page view rather than a bottom panel. Back
  returns to the card grid. Browser back is wired to the same handler.
- Database table viewer truncates long cell values with an ellipsis, keeps a
  `title` tooltip for the full value, and lists only the columns that fit.

## Phase 4, SSH

Covers item 3 and the SSH half of item 6.

- The generated keypair is installed into the target account's `authorized_keys`
  with correct ownership and modes, and the panel verifies the key actually
  authenticates before reporting success.
- Five failed SSH attempts from one IP triggers an automatic block, enforced by a
  firewall DROP rule, with a manual block control in the SSH log view.

## Phase 5, proxy v2 and firewall

Covers item 5. `nginx_proxy.py` is rewritten.

Add Proxy Host form:

- Domain name, with an incoming scheme selector (HTTP, HTTPS, TCP, UDP)
- Forward scheme, forward hostname or IP, forward port
- HTTPS listeners prompt for a certificate path, chosen from a server file picker
- HTTPS toggles: Force SSL, HSTS Enabled, HTTP/2 Support, HSTS Subdomains
- Behaviour toggles: Cache Assets, Block Common Exploits, Websockets Support
- Custom locations: any number of subdomain or endpoint rules, each with its own
  forward host, port and its own copy of the behaviour toggles
- Hosts not carrying the managed marker are read-only. No edit, no delete.
- Managed hosts are editable from the list, not just creatable.

Firewall settings, presented as "Firewall Settings" rather than ufw:

- Inbound and outbound port rules, each toggleable on and off
- Ports used by a proxy host are added to the allow list automatically
- Delegable to staff through a `firewall_manage` grant

## Phase 6, logs audit and repair

Covers item 6. More exists than expected: `ssh_log`, `web_login_log`,
`web_fp_block`, `web_login_block`, `web_session_log` and `http_access_log` are all
present, and fingerprint blocking already lives in `DB.py`. The work is verification
and repair, not construction.

- Prove each log view reads real data, and repair the ones that do not
- A blocked IP or blocked device gets the ordinary "wrong credentials" response, never
  a hint that it is blocked
- Five failed web logins blocks both the IP and the device fingerprint
- Server activity entries record the acting username
- Replace the four confusing summary tiles with four unambiguous ones: SSH successful
  logins, SSH failed logins, web successful logins, web failed logins
- The time range selector (today, 3 days, week, month) actually re-queries

## Phase 7, Cloudflare Tunnel

Covers item 7. `cloudflared` is already installed on the target box.

- A Cloudflare Proxy card inside Proxy settings, reachable by admins and by staff
  holding `tunnel_manage`
- Pressing connect produces a login link, and the panel detects the completed
  authorization
- Once connected, a tunnel maps a chosen local host and port to an HTTPS hostname,
  forwarding to plain HTTP locally
- `management.py` installs `cloudflared` when absent

## Phase 8, mail

Covers item 8. Largest new subsystem.

- A Mail tab on the left of the Logs section, with an unread badge in red
- Two admin-only setup actions: Configure Inbound Mail, which installs mailcow and
  opens TCP 25, and Configure Outbound Mail, which collects SMTP relay host, port,
  username, password and STARTTLS encryption
- Setup asks for the system's main domain, saves it, and then hides itself
- The admin creates addresses under that domain and assigns them to users
- Sending asks internal or external. Internal never touches the relay. External
  does. Both are recorded, tagged internal or external, in the database
- Before configuration, staff see "Not configured yet" and only the admin sees the
  setup actions

## Phase 9, account and branding

Covers item 10.

- No em dashes anywhere, including the README
- The topbar identity control becomes a round avatar button opening the account page
- The account page shows username and role, and edits full name and avatar
- Uploads accept PNG, JPEG and SVG and are rasterized to PNG, which removes the
  entire SVG scripting attack surface
- Outbound mail sends `Full Name <fullname@domain.com>` and embeds the avatar
- A domain-level BIMI record and SVG Tiny PS logo are published, and mailcow is
  configured to match
- The favicon is taken from Argus Recon, running on port 7666
