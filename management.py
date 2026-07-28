#!/usr/bin/env python3
# management.py — one-command deployment launcher for the Server Management panel.
#
#   python3 management.py            interactive setup wizard (see below), then run
#   python3 management.py --serve    run straight from deploy.json (used by systemd)
#   python3 management.py --setup    force the wizard even from a non-TTY
#
# The wizard walks you through everything needed to stand the panel up:
#   1. Connects to PostgreSQL and *lists the databases it finds*.
#   2. Lets you pick which database the panel should use, OR create a brand new
#      one by giving a name and the table structure you need — the tables are
#      created for you.
#   3. Asks which host/port to bind (localhost + a port you choose).
#   4. Offers to install itself as a systemd service so it survives reboots.
#   5. Saves the answers to deploy.json and starts serving, printing the port.
#
# The FastAPI app itself lives in panel.py (imported below); this file is only
# the deployment front-door so the whole thing ships as one easy-to-run app.

import os
import sys
import json
import shutil
import getpass
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "deploy.json")
ENV_PATH = os.path.join(HERE, ".env")
SERVICE_NAME = "argus-management"

DEFAULTS = {
    "db_host": "127.0.0.1",
    "db_port": 5432,
    "db_user": "elink",
    "db_password": "",
    "db_name": "elink",
    "host": "127.0.0.1",
    "port": 8080,
    "base_path": "",          # "" -> served at the domain root (e.g. a subdomain)
}


# --------------------------------------------------------------------------- #
# small tty helpers
# --------------------------------------------------------------------------- #
def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def head(text):
    print("\n" + _c("── " + text + " " + "─" * max(0, 56 - len(text)), "1;36"))

def ok(text):
    print(_c("  ✓ ", "1;32") + text)

def warn(text):
    print(_c("  ! ", "1;33") + text)

def ask(prompt, default=None):
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        val = input(_c("  » ", "1;35") + prompt + suffix + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    return val or (default if default is not None else "")

def ask_yes(prompt, default=False):
    d = "Y/n" if default else "y/N"
    val = ask(f"{prompt} ({d})", "").lower()
    if not val:
        return default
    return val in ("y", "yes")


# --------------------------------------------------------------------------- #
# config persistence
# --------------------------------------------------------------------------- #
def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                cfg.update(json.load(f))
        except Exception as e:
            warn(f"could not read deploy.json: {e}")
    # env / .env fallback for the password so it need not live in deploy.json
    if not cfg.get("db_password"):
        cfg["db_password"] = os.environ.get("DB_PASSWORD", _env_file_value("DB_PASSWORD", ""))
    return cfg

def _env_file_value(key, default=""):
    if not os.path.exists(ENV_PATH):
        return default
    try:
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
    except Exception:
        pass
    return default

def save_config(cfg):
    # deploy.json holds the non-secret runtime choices; the DB password is
    # written to .env (gitignored) so DB.py's own loader picks it up.
    public = {k: v for k, v in cfg.items() if k != "db_password"}
    with open(CONFIG_PATH, "w") as f:
        json.dump(public, f, indent=2)
    write_env(cfg)

def write_env(cfg):
    lines = [
        "# Written by management.py — keep out of version control.",
        f"DB_NAME={cfg['db_name']}",
        f"DB_USER={cfg['db_user']}",
        f"DB_PASSWORD={cfg['db_password']}",
        f"DB_HOST={cfg['db_host']}",
        f"DB_PORT={cfg['db_port']}",
        "",
    ]
    with open(ENV_PATH, "w") as f:
        f.write("\n".join(lines))
    os.chmod(ENV_PATH, 0o600)


# --------------------------------------------------------------------------- #
# database discovery / creation (psycopg2)
# --------------------------------------------------------------------------- #
def _connect(cfg, dbname):
    import psycopg2
    return psycopg2.connect(
        dbname=dbname, user=cfg["db_user"], password=cfg["db_password"],
        host=cfg["db_host"], port=cfg["db_port"], connect_timeout=5,
    )

def list_databases(cfg):
    """Return the list of non-template databases the server can see."""
    for probe in (cfg["db_name"], "postgres", "template1"):
        try:
            conn = _connect(cfg, probe)
        except Exception:
            continue
        try:
            cur = conn.cursor()
            cur.execute("SELECT datname FROM pg_database "
                        "WHERE datistemplate = false ORDER BY datname;")
            names = [r[0] for r in cur.fetchall()]
            cur.close()
            return names
        finally:
            conn.close()
    raise RuntimeError("could not connect to PostgreSQL with the given credentials")

def list_tables(cfg, dbname):
    try:
        conn = _connect(cfg, dbname)
    except Exception:
        return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' ORDER BY table_name;")
        rows = [r[0] for r in cur.fetchall()]
        cur.close()
        return rows
    finally:
        conn.close()

def create_database(cfg, name):
    import psycopg2
    from psycopg2 import sql
    for admin_db in ("postgres", "template1", cfg["db_name"]):
        try:
            conn = _connect(cfg, admin_db)
        except Exception:
            continue
        conn.autocommit = True   # CREATE DATABASE cannot run in a transaction
        try:
            cur = conn.cursor()
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
            cur.close()
            return
        except psycopg2.errors.DuplicateDatabase:
            warn(f"database '{name}' already exists — reusing it")
            return
        finally:
            conn.close()
    raise RuntimeError("no admin database reachable to CREATE DATABASE (need a "
                       "role allowed to create databases)")

def run_sql(cfg, dbname, statements):
    conn = _connect(cfg, dbname)
    try:
        cur = conn.cursor()
        for stmt in statements:
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)
        conn.commit()
        cur.close()
    finally:
        conn.close()

def build_create_table():
    """Interactively build one CREATE TABLE statement. Returns SQL or None."""
    table = ask("New table name (blank to stop adding tables)", "")
    if not table:
        return None
    print("    Define columns one per line as:  name type [constraints]")
    print("    e.g.  id serial primary key   /   email text unique not null")
    print("    Leave the line blank when you're done.")
    cols = []
    while True:
        line = ask(f"    column #{len(cols) + 1}", "")
        if not line:
            break
        cols.append("  " + line)
    if not cols:
        warn("no columns given — skipping this table")
        return None
    return f"CREATE TABLE IF NOT EXISTS {table} (\n" + ",\n".join(cols) + "\n);"

def create_new_database_flow(cfg):
    head("Create a new database")
    name = ask("Database name", "")
    while not name:
        name = ask("Database name (required)", "")
    print(f"  Creating database {_c(name, '1;37')} …")
    create_database(cfg, name)
    ok(f"database '{name}' ready")

    head("Define the table structure")
    print("  Add as many tables as you need. You can also paste raw SQL.")
    statements = []
    if ask_yes("Paste a raw SQL schema instead of the guided builder?", False):
        print("  Paste your SQL, then a line containing only  ;;  to finish:")
        buf = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == ";;":
                break
            buf.append(line)
        statements = [s for s in "\n".join(buf).split(";") if s.strip()]
    else:
        while True:
            stmt = build_create_table()
            if stmt is None:
                break
            statements.append(stmt)
            ok(f"queued table definition")
    if statements:
        run_sql(cfg, name, statements)
        ok(f"created {len(statements)} object(s) in '{name}'")
    else:
        warn("no tables defined — the database is empty for now")
    cfg["db_name"] = name
    return cfg


# --------------------------------------------------------------------------- #
# systemd service install
# --------------------------------------------------------------------------- #
def install_service(cfg):
    unit = f"""[Unit]
Description=Argus Management — Server Management Panel (FastAPI)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={HERE}
ExecStart={sys.executable} {os.path.join(HERE, 'management.py')} --serve
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    path = f"/etc/systemd/system/{SERVICE_NAME}.service"
    try:
        with open(path, "w") as f:
            f.write(unit)
    except PermissionError:
        warn(f"need root to write {path} — re-run with sudo to install the service")
        return False
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", SERVICE_NAME], check=False)
    ok(f"installed and enabled {SERVICE_NAME}.service")
    print(f"    manage it with:  systemctl {{status|restart|stop}} {SERVICE_NAME}")
    return True


# --------------------------------------------------------------------------- #
# run the panel
# --------------------------------------------------------------------------- #
def serve(cfg):
    # Credentials must be in the environment BEFORE DB.py / panel.py import,
    # because DB.py reads DB_CONFIG at import time.
    os.environ["DB_NAME"] = str(cfg["db_name"])
    os.environ["DB_USER"] = str(cfg["db_user"])
    os.environ["DB_PASSWORD"] = str(cfg["db_password"])
    os.environ["DB_HOST"] = str(cfg["db_host"])
    os.environ["DB_PORT"] = str(cfg["db_port"])
    os.environ["MGMT_BASE"] = str(cfg.get("base_path", ""))

    import uvicorn
    import panel  # the FastAPI app

    host, port = cfg["host"], int(cfg["port"])
    panel.SERVER_RUNTIME["host"], panel.SERVER_RUNTIME["port"] = host, port
    # keep the panel's own Config tab in sync with what we actually bound
    try:
        import DB
        DB.set_setting("management_host", host)
        DB.set_setting("management_port", port)
    except Exception:
        pass

    base = cfg.get("base_path", "") or "/"
    print(_c(f"\n  ► Management panel is running on http://{host}:{port}{base}", "1;32"))
    print(_c(f"    (bound to {host}:{port})\n", "2;37"))
    uvicorn.run(panel.app, host=host, port=port, log_level="info")


# --------------------------------------------------------------------------- #
# wizard
# --------------------------------------------------------------------------- #
def wizard():
    print(_c("\n  ARGUS · Management panel — deployment setup", "1;36"))
    print(_c("  " + "─" * 46, "2;36"))
    cfg = load_config()

    head("Database connection")
    cfg["db_host"] = ask("PostgreSQL host", cfg["db_host"])
    cfg["db_port"] = int(ask("PostgreSQL port", cfg["db_port"]) or cfg["db_port"])
    cfg["db_user"] = ask("PostgreSQL user", cfg["db_user"])
    pw = getpass.getpass(f"  » PostgreSQL password [{'keep' if cfg['db_password'] else 'none'}]: ")
    if pw:
        cfg["db_password"] = pw

    print("  Searching the server for databases …")
    try:
        dbs = list_databases(cfg)
    except Exception as e:
        warn(f"database search failed: {e}")
        if ask_yes("Continue anyway with the values above?", False):
            dbs = []
        else:
            sys.exit(1)

    head("Choose the database to use")
    for i, name in enumerate(dbs, 1):
        tbls = list_tables(cfg, name)
        note = f"  ({len(tbls)} tables)" if tbls else "  (empty)"
        marker = " ←" if name == cfg["db_name"] else ""
        print(f"    {_c(str(i), '1;37')}. {name}{_c(note, '2;37')}{marker}")
    print(f"    {_c('n', '1;37')}. create a NEW database (define its tables)")

    choice = ask("Select a database by number, or 'n' for new", "")
    if choice.lower() == "n":
        cfg = create_new_database_flow(cfg)
    elif choice.isdigit() and 1 <= int(choice) <= len(dbs):
        cfg["db_name"] = dbs[int(choice) - 1]
    elif choice:
        cfg["db_name"] = choice   # allow typing a name directly
    ok(f"using database: {cfg['db_name']}")

    head("Where should the panel listen?")
    cfg["host"] = ask("Bind host (localhost keeps it behind nginx)", cfg["host"])
    cfg["port"] = int(ask("Port to serve on", cfg["port"]) or cfg["port"])
    cfg["base_path"] = ask("URL base path ('' = domain root)", cfg["base_path"])

    save_config(cfg)
    ok("saved deploy.json")

    head("Run as a service?")
    if ask_yes("Install this panel as a systemd service (starts on boot)?", True):
        install_service(cfg)
        if ask_yes(f"Start {SERVICE_NAME} now via systemd?", True):
            subprocess.run(["systemctl", "restart", SERVICE_NAME], check=False)
            ok(f"{SERVICE_NAME} started — serving on port {cfg['port']}")
            print(f"    logs:  journalctl -u {SERVICE_NAME} -f")
            return
    # not a service (or declined starting it): run in the foreground now
    serve(cfg)


# --------------------------------------------------------------------------- #
def main():
    args = set(sys.argv[1:])
    if "--serve" in args:
        serve(load_config())
        return
    if "--setup" in args or sys.stdin.isatty():
        wizard()
        return
    # non-interactive with no flag: behave like a service
    serve(load_config())


if __name__ == "__main__":
    main()
