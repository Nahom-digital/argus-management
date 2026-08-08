# Argus Management Panel

A self-contained FastAPI **server management panel** — live telemetry, an in-browser
terminal, process/connection views, systemd service control, and a security/activity
log. It ships as **one easy-to-deploy app**: clone it, run one command, answer a few
questions, and it's live.

Published at **https://argus.welinkp2p.digital** (nginx → `127.0.0.1:8080`).

## Quick start

```bash
python3 management.py
```

That is the whole install. No `pip install`, no `apt install`, no database setup.

The wizard does all of it for you:

1. **Installs its own Python dependencies.** If pip is missing it bootstraps it. On
   Debian/Kali/Ubuntu, where pip refuses to touch system site-packages (PEP 668), it
   retries with `--user`, then `--break-system-packages`, then distro packages, and
   finally builds a private `.venv` and restarts itself inside it. One of those always
   works.
2. **Makes sure PostgreSQL is installed and running** — installing it with apt / dnf /
   yum / pacman / zypper / apk / brew and starting the service if it isn't.
3. **Finds a privileged way into the server**, even when the configured role does not
   exist yet: direct TCP, the local unix socket, and `sudo -u postgres psql` (the
   standard bootstrap path on Debian-likes, which psycopg2 cannot reach on its own).
   Only if all of those fail does it ask you for a superuser login.
4. **Lists every database on the server** so you can pick one. If there are none it
   says so plainly and offers to create one — asking for the database name, the
   database user, and a password (leave it blank and a strong one is generated).
5. **Creates the tables this panel needs**, then verifies all of them landed.
6. **Creates your panel administrator account** — the username and password you sign
   in with. Any leftover insecure `admin`/`admin` account is removed.
7. **Asks which host and port to bind**, warning you if the port is already taken.
8. **Offers to install itself as a systemd service.** Say yes and it installs, starts,
   verifies the port is live, tells you the port, and exits — the panel keeps running
   and comes back on boot. Say no and it runs in the foreground, warning you that
   closing the terminal stops the panel.

Answers are saved to `deploy.json` (non-secret) and `.env` (mode 0600). Re-running the
wizard over an existing install is safe — every step is idempotent.

## Commands

```bash
python3 management.py             # setup wizard, then run
python3 management.py --service   # install + start the systemd service, then exit
python3 management.py --serve     # run in the foreground from deploy.json
python3 management.py --status    # config / dependency / database / service report
python3 management.py --setup     # force the wizard even without a TTY
python3 management.py --help
```

If you chose **not** to run as a service and want to switch later, that's
`python3 management.py --service`. Installing a system service needs root, so run it
with `sudo` if you aren't root.

Once installed the service is ordinary systemd:

```bash
systemctl status  argus-management
systemctl restart argus-management
journalctl -u argus-management -f
```

## Files

| file | what it is |
|------|------------|
| `management.py` | deployment front door: dependency bootstrap, DB provisioning, setup wizard, service installer |
| `panel.py`      | the FastAPI panel itself (routes, UI, websocket terminal) |
| `DB.py`         | PostgreSQL pool, admin auth, settings, security/activity logs |
| `System.py`     | host telemetry, PTY terminal, process/connection helpers |
| `static_mgmt/`  | CSS design system + panel JS + icon sprite |
| `vendor/`       | bundled fonts, xterm.js, icons (no external CDN needed) |

## Database schema

The wizard creates exactly what the panel runs on:

| table | purpose |
|-------|---------|
| `admin` | panel login accounts (PBKDF2-SHA256) |
| `system_settings` | key/value runtime configuration |
| `management_log` | the panel's own structured event + audit log |
| `admin_action` | append-only administrator audit trail |
| `ssh_log` | SSH authentication events collected from journald |
| `web_login_log` | panel login attempts with device fingerprints |
| `web_fp_block` / `web_login_block` | brute-force blocks by device and by IP |
| `web_session_log` | issued panel sessions |
| `http_access_log` | HTTP request/response log |

Picking an existing database only adds these tables; nothing already there is touched.

## Configuration

Non-secret runtime choices live in **`deploy.json`**; the DB password lives in **`.env`**
(mode 0600). Both are git-ignored — see `deploy.example.json` and `.env.example`.
Environment variables (`DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`,
`MGMT_BASE`) override both.

## Reverse proxy

nginx serves the panel at the root of `argus.welinkp2p.digital` and proxies to the
loopback port, forwarding websocket upgrades for the in-browser terminal. Set
`base_path` to `""` when serving from a subdomain root, or to e.g. `/management` when
mounting under a path on a shared host.
