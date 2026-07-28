# Argus Management Panel

A self-contained FastAPI **server management panel** — live telemetry, an in-browser
terminal, process/connection views, systemd service control, and a security/activity
log. It ships as **one easy-to-deploy app**: clone it, run one command, answer a few
questions, and it's live.

Published at **https://argus.welinkp2p.digital** (nginx → `127.0.0.1:8080`), reusing the
same PostgreSQL database as the main app.

## Quick start

```bash
pip install -r requirements.txt
python3 management.py
```

The wizard will:

1. **Connect to PostgreSQL and list the databases it finds.**
2. Let you **pick one** — or **create a new database**, giving it a name and the
   **table structure** you want (guided column-by-column, or paste raw SQL). The
   tables are created for you.
3. Ask which **host / port** to bind (defaults to `127.0.0.1:8080`).
4. Offer to **install itself as a systemd service** (`argus-management.service`) so it
   starts on boot.
5. Save your answers to `deploy.json` + `.env` and start serving, printing the port.

### Non-interactive / service mode

```bash
python3 management.py --serve     # read deploy.json and run (this is what systemd calls)
python3 management.py --setup     # force the wizard even without a TTY
```

## Files

| file | what it is |
|------|------------|
| `management.py` | deployment launcher + setup wizard (the front door) |
| `panel.py`      | the FastAPI panel itself (routes, UI, websocket terminal) |
| `DB.py`         | PostgreSQL pool, admin auth, settings, security/activity logs |
| `System.py`     | host telemetry, PTY terminal, process/connection helpers |
| `static_mgmt/`  | CSS design system + panel JS + icon sprite |
| `vendor/`       | bundled fonts, xterm.js, icons (no external CDN needed) |

## Configuration

Non-secret runtime choices live in **`deploy.json`**; the DB password lives in **`.env`**.
Both are git-ignored. See `deploy.example.json` and `.env.example`. Environment
variables (`DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `MGMT_BASE`)
override the files.

## Reverse proxy

nginx serves the panel at the root of `argus.welinkp2p.digital` and proxies to the
loopback port, forwarding websocket upgrades for the in-browser terminal. Set
`base_path` to `""` when serving from a subdomain root, or to e.g. `/management` when
mounting under a path on a shared host.
