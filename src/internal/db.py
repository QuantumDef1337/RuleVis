"""
Identity & authorization store: users, tenants, and per-tenant roles.

A small relational database — separate from the existing per-tenant JSON
config files (products/managers/case_tags/paths), which stay exactly as they
are, just relocated under a tenant directory (see migrate.py).

A real (not JSON-file) database is used here specifically because this data
needs atomic, race-free writes across concurrent requests from different
users — the JSON `Config` class only has an in-process lock, which is fine
for its existing single-engineer-at-a-time use, but isn't safe once multiple
authenticated users can hit the API at once.

Backend selection:
  - By default, uses a local SQLite file at ~/.rulevis/rulevis.db — zero
    config, works out of the box for a single-process deployment.
  - Set RULEVIS_DATABASE_URL (any SQLAlchemy URL, e.g.
    "postgresql+psycopg2://user:pass@host/rulevis") to run against a real
    client-server database instead. This is what actually lets the app run
    as more than one process/host: SQLite is a single local file, so two
    processes on two machines (or even two processes with the sqlite file on
    a network share) can't safely coordinate through it. Every query in this
    module is written to be portable across both backends — no
    SQLite-specific pragmas or syntax outside of init_schema's DDL selection.

Built on SQLAlchemy Core (not the ORM) — just enough abstraction to get
connection pooling and a single portable query layer, without pulling in the
weight of a full ORM for what's fundamentally a small, flat schema.
"""

import hashlib
import json
import os
import secrets
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from sqlalchemy import create_engine, inspect as sa_inspect, text
from sqlalchemy.engine import Connection, Engine
from werkzeug.security import check_password_hash, generate_password_hash

DEFAULT_PLATFORM_SETTINGS: dict[str, Any] = {
    "audit_log_retention_days": 90,
    "deletion_log_retention_days": 90,
    "login_history_retention_days": 90,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 15,
    "password_min_length": 12,
    "password_history_depth": 5,
    "session_idle_timeout_minutes": 30,
    "mfa_backup_codes_count": 10,
}

APP_NAME = "rulevis"
ROLES = ("tenant_admin", "analyst", "viewer")  # super_admin is a platform flag, not a tenant role
DATABASE_URL_ENV_VAR = "RULEVIS_DATABASE_URL"


def app_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), f".{APP_NAME}")
    os.makedirs(d, exist_ok=True)
    return d


def db_path() -> str:
    return os.path.join(app_dir(), "rulevis.db")


def secret_key() -> str:
    """Persisted Flask session-signing key. Generated once — regenerating it
    on every process start would invalidate every existing session."""
    path = os.path.join(app_dir(), "secret_key")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as f:
        f.write(key)
    return key


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------- engine / connection management ----------------
_engines: dict[str, Engine] = {}
_engines_lock = threading.Lock()


def database_url() -> str:
    """RULEVIS_DATABASE_URL if set (e.g. Postgres for a multi-process/
    multi-host deployment), else a local SQLite file under ~/.rulevis —
    resolved fresh on every call so tests (which point HOME at a fresh temp
    dir per test) and CLI --path style overrides both just work."""
    return os.environ.get(DATABASE_URL_ENV_VAR) or f"sqlite:///{db_path()}"


def get_engine() -> Engine:
    """Returns a pooled SQLAlchemy engine for the current database_url(),
    creating one on first use. Keyed by URL (not a single global) so tests
    that point at a different SQLite file per run each get their own engine,
    while repeated calls against the same URL reuse the pool."""
    url = database_url()
    with _engines_lock:
        engine = _engines.get(url)
        if engine is None:
            connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
            engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
            _engines[url] = engine
        return engine


@contextmanager
def _ro() -> Iterator[Connection]:
    """Read-only helper. Any implicit transaction SQLAlchemy opens is simply
    dropped (rolled back) on exit — nothing to lose for a read."""
    with get_engine().connect() as conn:
        yield conn


@contextmanager
def _rw() -> Iterator[Connection]:
    """Write helper — commits on success, rolls back on exception."""
    with get_engine().begin() as conn:
        yield conn


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                    TEXT PRIMARY KEY,
    email                 TEXT NOT NULL UNIQUE COLLATE NOCASE,
    username              TEXT COLLATE NOCASE,
    password_hash         TEXT NOT NULL,
    display_name          TEXT,
    is_super_admin        INTEGER NOT NULL DEFAULT 0,
    is_active             INTEGER NOT NULL DEFAULT 1,
    mfa_secret            TEXT,
    mfa_enabled           INTEGER NOT NULL DEFAULT 0,
    mfa_required          INTEGER NOT NULL DEFAULT 0,
    mfa_backup_codes      TEXT,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until          TEXT,
    force_password_reset  INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pwhist_user ON password_history(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_email    TEXT,
    action         TEXT NOT NULL,
    target_type    TEXT,
    target_id      TEXT,
    details        TEXT,
    tenant_id      TEXT,
    ip_address     TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS login_activity (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    email_attempted TEXT NOT NULL,
    success         INTEGER NOT NULL,
    reason          TEXT,
    ip_address      TEXT,
    user_agent      TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_created ON login_activity(created_at);
CREATE INDEX IF NOT EXISTS idx_login_user ON login_activity(user_id);

CREATE TABLE IF NOT EXISTS login_ip_failures (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_ip_failures_ip ON login_ip_failures(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_ip_failures_created ON login_ip_failures(created_at);

CREATE TABLE IF NOT EXISTS platform_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    is_active  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_tenant_roles (
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role                 TEXT NOT NULL CHECK (role IN ('tenant_admin', 'analyst', 'viewer')),
    permission_overrides TEXT,
    created_at           TEXT NOT NULL,
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_utr_tenant ON user_tenant_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_utr_user ON user_tenant_roles(user_id);

CREATE TABLE IF NOT EXISTS invites (
    token      TEXT PRIMARY KEY,
    email      TEXT NOT NULL COLLATE NOCASE,
    tenant_id  TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('super_admin', 'tenant_admin', 'analyst', 'viewer')),
    invited_by TEXT NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('tenant_admin', 'analyst', 'viewer')),
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
"""

# Postgres equivalent: SERIAL instead of INTEGER PRIMARY KEY AUTOINCREMENT,
# no COLLATE NOCASE (Postgres has no such collation) — case-insensitive
# uniqueness/lookups are handled with explicit LOWER() instead, uniformly,
# in every query in this module (so behavior is identical on both backends).
POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                    TEXT PRIMARY KEY,
    email                 TEXT NOT NULL UNIQUE,
    username              TEXT,
    password_hash         TEXT NOT NULL,
    display_name          TEXT,
    is_super_admin        INTEGER NOT NULL DEFAULT 0,
    is_active             INTEGER NOT NULL DEFAULT 1,
    mfa_secret            TEXT,
    mfa_enabled           INTEGER NOT NULL DEFAULT 0,
    mfa_required          INTEGER NOT NULL DEFAULT 0,
    mfa_backup_codes      TEXT,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until          TEXT,
    force_password_reset  INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_history (
    id            SERIAL PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pwhist_user ON password_history(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id             SERIAL PRIMARY KEY,
    actor_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_email    TEXT,
    action         TEXT NOT NULL,
    target_type    TEXT,
    target_id      TEXT,
    details        TEXT,
    tenant_id      TEXT,
    ip_address     TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS login_activity (
    id              SERIAL PRIMARY KEY,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    email_attempted TEXT NOT NULL,
    success         INTEGER NOT NULL,
    reason          TEXT,
    ip_address      TEXT,
    user_agent      TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_created ON login_activity(created_at);
CREATE INDEX IF NOT EXISTS idx_login_user ON login_activity(user_id);

CREATE TABLE IF NOT EXISTS login_ip_failures (
    id         SERIAL PRIMARY KEY,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_ip_failures_ip ON login_ip_failures(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_ip_failures_created ON login_ip_failures(created_at);

CREATE TABLE IF NOT EXISTS platform_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    is_active  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_tenant_roles (
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role                 TEXT NOT NULL CHECK (role IN ('tenant_admin', 'analyst', 'viewer')),
    permission_overrides TEXT,
    created_at           TEXT NOT NULL,
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_utr_tenant ON user_tenant_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_utr_user ON user_tenant_roles(user_id);

CREATE TABLE IF NOT EXISTS invites (
    token      TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    tenant_id  TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('super_admin', 'tenant_admin', 'analyst', 'viewer')),
    invited_by TEXT NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('tenant_admin', 'analyst', 'viewer')),
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
"""


def _split_statements(script: str) -> list[str]:
    return [s.strip() for s in script.split(";") if s.strip()]


def _ensure_column(conn: Connection, table: str, column: str, decl: str) -> None:
    """Idempotently add a column to an existing table (CREATE TABLE IF NOT
    EXISTS never alters an already-created table, so schema additions to a
    live DB need this). Uses SQLAlchemy's inspector rather than SQLite's
    PRAGMA table_info so this works against Postgres too."""
    cols = [c["name"] for c in sa_inspect(conn).get_columns(table)]
    if column not in cols:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {decl}"))


def init_schema() -> None:
    engine = get_engine()
    dialect = engine.dialect.name
    script = SQLITE_SCHEMA if dialect == "sqlite" else POSTGRES_SCHEMA
    with engine.begin() as conn:
        for stmt in _split_statements(script):
            conn.execute(text(stmt))
    with engine.begin() as conn:
        # incremental column additions for DBs created before these columns existed
        _ensure_column(conn, "login_activity", "user_agent", "TEXT")
        _ensure_column(conn, "audit_log", "ip_address", "TEXT")
        _ensure_column(conn, "users", "username", "TEXT")
        _ensure_column(conn, "users", "mfa_required", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "user_tenant_roles", "permission_overrides", "TEXT")
        if dialect == "sqlite":
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) "
                "WHERE username IS NOT NULL"))
        else:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_ci ON users (LOWER(username)) "
                "WHERE username IS NOT NULL"))


def db_exists() -> bool:
    """True if the configured database already has data in it. For the
    default SQLite backend this is just a file check; for an external
    database (Postgres) migrate_if_needed()'s legacy-file check makes this
    moot in practice, but we still report honestly based on the users table."""
    if database_url().startswith("sqlite"):
        return os.path.isfile(db_path())
    try:
        return count_users() > 0
    except Exception:
        return False


# ---------------- users ----------------
def _user_row(row: Any) -> dict[str, Any]:
    keys = row.keys()
    return {
        "id": row["id"], "email": row["email"],
        "username": row["username"] if "username" in keys else None,
        "display_name": row["display_name"],
        "is_super_admin": bool(row["is_super_admin"]), "is_active": bool(row["is_active"]),
        "mfa_enabled": bool(row["mfa_enabled"]),
        "mfa_required": bool(row["mfa_required"]) if "mfa_required" in keys else False,
        "force_password_reset": bool(row["force_password_reset"]),
        "locked_until": row["locked_until"],
        "created_at": row["created_at"],
    }


def count_users() -> int:
    with _ro() as conn:
        return conn.execute(text("SELECT COUNT(*) AS c FROM users")).mappings().fetchone()["c"]


def create_user(email: str, password: str, display_name: str = "",
                is_super_admin: bool = False, force_password_reset: bool = False,
                username: Optional[str] = None, mfa_required: bool = False) -> dict[str, Any]:
    uid = uuid.uuid4().hex
    now = _now()
    pw_hash = generate_password_hash(password)
    email_norm = email.strip().lower() if email else f"{uid}@users.rulevis.local"
    uname = username.strip() if username else None
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO users (id, email, username, password_hash, display_name, is_super_admin, "
            "is_active, force_password_reset, mfa_required, created_at, updated_at) "
            "VALUES (:id, :email, :username, :password_hash, :display_name, :is_super_admin, "
            "1, :force_password_reset, :mfa_required, :created_at, :updated_at)"),
            {"id": uid, "email": email_norm, "username": uname, "password_hash": pw_hash,
             "display_name": display_name.strip(), "is_super_admin": int(is_super_admin),
             "force_password_reset": int(force_password_reset), "mfa_required": int(mfa_required),
             "created_at": now, "updated_at": now})
        conn.execute(text(
            "INSERT INTO password_history (user_id, password_hash, created_at) "
            "VALUES (:user_id, :password_hash, :created_at)"),
            {"user_id": uid, "password_hash": pw_hash, "created_at": now})
    return get_user_by_id(uid)  # type: ignore[return-value]


def get_user_by_id(user_id: str) -> Optional[dict[str, Any]]:
    with _ro() as conn:
        row = conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id}).mappings().fetchone()
        return _user_row(row) if row else None


def get_user_by_email(email: str) -> Optional[dict[str, Any]]:
    with _ro() as conn:
        row = conn.execute(
            text("SELECT * FROM users WHERE LOWER(email) = LOWER(:email)"),
            {"email": email.strip()}).mappings().fetchone()
        return _user_row(row) if row else None


def get_user_by_username(username: str) -> Optional[dict[str, Any]]:
    with _ro() as conn:
        row = conn.execute(
            text("SELECT * FROM users WHERE LOWER(username) = LOWER(:username)"),
            {"username": username.strip()}).mappings().fetchone()
        return _user_row(row) if row else None


def verify_login(identifier: str, password: str) -> Optional[dict[str, Any]]:
    """Returns the user dict if credentials are valid and the account is active.
    `identifier` may be either the account's email or its username."""
    ident = identifier.strip()
    with _ro() as conn:
        row = conn.execute(text(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(:ident) OR LOWER(username) = LOWER(:ident)"),
            {"ident": ident}).mappings().fetchone()
        if not row or not row["is_active"]:
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        return _user_row(row)


# ---------------- account lockout ----------------
def is_locked_out(identifier: str) -> Optional[str]:
    """Returns the ISO lockout-expiry timestamp if the account is currently
    locked, else None. `identifier` may be an email or a username."""
    ident = identifier.strip()
    with _ro() as conn:
        row = conn.execute(text(
            "SELECT locked_until FROM users WHERE LOWER(email) = LOWER(:ident) OR LOWER(username) = LOWER(:ident)"),
            {"ident": ident}).mappings().fetchone()
        if row and row["locked_until"] and row["locked_until"] > _now():
            return row["locked_until"]
        return None


def register_failed_login(identifier: str) -> None:
    settings = get_platform_settings()
    ident = identifier.strip()
    with _rw() as conn:
        row = conn.execute(text(
            "SELECT id, failed_login_attempts FROM users "
            "WHERE LOWER(email) = LOWER(:ident) OR LOWER(username) = LOWER(:ident)"),
            {"ident": ident}).mappings().fetchone()
        if not row:
            return
        attempts = row["failed_login_attempts"] + 1
        locked_until = None
        if attempts >= settings["lockout_threshold"]:
            locked_until = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(time.time() + settings["lockout_duration_minutes"] * 60))
        conn.execute(text(
            "UPDATE users SET failed_login_attempts = :attempts, locked_until = :locked_until WHERE id = :id"),
            {"attempts": attempts, "locked_until": locked_until, "id": row["id"]})


def reset_failed_login(user_id: str) -> None:
    with _rw() as conn:
        conn.execute(text(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id"),
            {"id": user_id})


# ---------------- password policy ----------------
def check_password_reuse(user_id: str, new_password: str) -> bool:
    """True if new_password matches one of the last N passwords (per policy)."""
    depth = get_platform_settings()["password_history_depth"]
    if depth <= 0:
        return False
    with _ro() as conn:
        rows = conn.execute(text(
            "SELECT password_hash FROM password_history WHERE user_id = :user_id "
            "ORDER BY created_at DESC LIMIT :depth"), {"user_id": user_id, "depth": depth}).mappings().fetchall()
        return any(check_password_hash(r["password_hash"], new_password) for r in rows)


def set_password(user_id: str, new_password: str, clear_force_reset: bool = True) -> None:
    depth = get_platform_settings()["password_history_depth"]
    pw_hash = generate_password_hash(new_password)
    now = _now()
    with _rw() as conn:
        set_clause = "password_hash = :password_hash, updated_at = :updated_at"
        if clear_force_reset:
            set_clause += ", force_password_reset = 0"
        conn.execute(text(f"UPDATE users SET {set_clause} WHERE id = :id"),
                     {"password_hash": pw_hash, "updated_at": now, "id": user_id})
        conn.execute(text(
            "INSERT INTO password_history (user_id, password_hash, created_at) "
            "VALUES (:user_id, :password_hash, :created_at)"),
            {"user_id": user_id, "password_hash": pw_hash, "created_at": now})
        if depth > 0:
            conn.execute(text(
                "DELETE FROM password_history WHERE user_id = :user_id AND id NOT IN "
                "(SELECT id FROM password_history WHERE user_id = :user_id ORDER BY created_at DESC LIMIT :depth)"),
                {"user_id": user_id, "depth": depth})


# ---------------- MFA ----------------
def set_mfa_secret(user_id: str, secret: Optional[str], backup_codes: Optional[list[str]] = None) -> None:
    hashed = json.dumps([generate_password_hash(c) for c in backup_codes]) if backup_codes else None
    with _rw() as conn:
        conn.execute(text("UPDATE users SET mfa_secret = :secret, mfa_backup_codes = :codes WHERE id = :id"),
                     {"secret": secret, "codes": hashed, "id": user_id})


def set_mfa_enabled(user_id: str, enabled: bool) -> None:
    with _rw() as conn:
        conn.execute(text("UPDATE users SET mfa_enabled = :enabled WHERE id = :id"),
                     {"enabled": int(enabled), "id": user_id})


def get_mfa_secret(user_id: str) -> Optional[str]:
    with _ro() as conn:
        row = conn.execute(text("SELECT mfa_secret FROM users WHERE id = :id"), {"id": user_id}).mappings().fetchone()
        return row["mfa_secret"] if row else None


def consume_backup_code(user_id: str, code: str) -> bool:
    with _rw() as conn:
        row = conn.execute(text("SELECT mfa_backup_codes FROM users WHERE id = :id"),
                            {"id": user_id}).mappings().fetchone()
        if not row or not row["mfa_backup_codes"]:
            return False
        hashes: list[str] = json.loads(row["mfa_backup_codes"])
        for i, h in enumerate(hashes):
            if check_password_hash(h, code.strip()):
                del hashes[i]
                conn.execute(text("UPDATE users SET mfa_backup_codes = :codes WHERE id = :id"),
                             {"codes": json.dumps(hashes), "id": user_id})
                return True
        return False


# ---------------- audit / login activity ----------------
def log_audit(action: str, actor_user_id: Optional[str] = None, actor_email: Optional[str] = None,
             target_type: Optional[str] = None, target_id: Optional[str] = None,
             details: Optional[str] = None, tenant_id: Optional[str] = None,
             ip_address: Optional[str] = None) -> None:
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO audit_log (actor_user_id, actor_email, action, target_type, target_id, "
            "details, tenant_id, ip_address, created_at) VALUES "
            "(:actor_user_id, :actor_email, :action, :target_type, :target_id, :details, :tenant_id, "
            ":ip_address, :created_at)"),
            {"actor_user_id": actor_user_id, "actor_email": actor_email, "action": action,
             "target_type": target_type, "target_id": target_id, "details": details,
             "tenant_id": tenant_id, "ip_address": ip_address, "created_at": _now()})


def list_audit_log(tenant_id: Optional[str] = None, deletions_only: bool = False,
                   limit: int = 200) -> list[dict[str, Any]]:
    q = "SELECT * FROM audit_log"
    where = []
    params: dict[str, Any] = {"limit": limit}
    if tenant_id:
        where.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if deletions_only:
        where.append("action LIKE 'delete_%'")
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY created_at DESC LIMIT :limit"
    with _ro() as conn:
        rows = conn.execute(text(q), params).mappings().fetchall()
        return [dict(r) for r in rows]


def record_login_activity(email: str, success: bool, reason: str = "",
                          user_id: Optional[str] = None, ip_address: Optional[str] = None,
                          user_agent: Optional[str] = None) -> None:
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO login_activity (user_id, email_attempted, success, reason, ip_address, "
            "user_agent, created_at) VALUES "
            "(:user_id, :email, :success, :reason, :ip_address, :user_agent, :created_at)"),
            {"user_id": user_id, "email": email.strip().lower(), "success": int(success), "reason": reason,
             "ip_address": ip_address, "user_agent": (user_agent or "")[:400], "created_at": _now()})


def list_login_activity(limit: int = 200) -> list[dict[str, Any]]:
    with _ro() as conn:
        rows = conn.execute(
            text("SELECT * FROM login_activity ORDER BY created_at DESC LIMIT :limit"),
            {"limit": limit}).mappings().fetchall()
        return [dict(r) for r in rows]


def sweep_retention() -> None:
    """Prunes audit/login history past their configured retention. Called
    both opportunistically (e.g. when the System settings page loads) and on
    a fixed schedule by the background retention thread in visualizer.py —
    the former no longer being the *only* way it runs is the point."""
    settings = get_platform_settings()
    with _rw() as conn:
        cutoff_audit = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - settings["audit_log_retention_days"] * 86400))
        conn.execute(text("DELETE FROM audit_log WHERE created_at < :cutoff"), {"cutoff": cutoff_audit})
        cutoff_login = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - settings["login_history_retention_days"] * 86400))
        conn.execute(text("DELETE FROM login_activity WHERE created_at < :cutoff"), {"cutoff": cutoff_login})


# ---------------- per-IP login rate limiting ----------------
# Deliberately stored in the same database as everything else (not an
# in-process dict) — an in-memory limiter only ever sees the requests that
# happened to land on that one process. The moment you run more than one
# process (multiple waitress/gunicorn workers, or multiple hosts behind a
# load balancer), each process gets its own blind spot and an attacker can
# just round-robin across them. Routing it through the DB means every
# process sees the same failure history, regardless of how many there are.
def register_ip_login_failure(ip_address: str) -> None:
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO login_ip_failures (ip_address, created_at) VALUES (:ip, :created_at)"),
            {"ip": ip_address, "created_at": _now()})


def is_ip_rate_limited(ip_address: str, max_failures: int, window_seconds: int) -> bool:
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - window_seconds))
    with _ro() as conn:
        row = conn.execute(text(
            "SELECT COUNT(*) AS c FROM login_ip_failures WHERE ip_address = :ip AND created_at >= :cutoff"),
            {"ip": ip_address, "cutoff": cutoff}).mappings().fetchone()
        return row["c"] >= max_failures


def sweep_ip_login_failures(older_than_seconds: int) -> None:
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - older_than_seconds))
    with _rw() as conn:
        conn.execute(text("DELETE FROM login_ip_failures WHERE created_at < :cutoff"), {"cutoff": cutoff})


# ---------------- platform settings ----------------
def get_platform_settings() -> dict[str, Any]:
    with _ro() as conn:
        rows = conn.execute(text("SELECT key, value FROM platform_settings")).mappings().fetchall()
        stored = {r["key"]: json.loads(r["value"]) for r in rows}
        return {**DEFAULT_PLATFORM_SETTINGS, **stored}


def set_platform_settings(patch: dict[str, Any]) -> dict[str, Any]:
    with _rw() as conn:
        for k, v in patch.items():
            if k not in DEFAULT_PLATFORM_SETTINGS:
                continue
            conn.execute(text(
                "INSERT INTO platform_settings (key, value) VALUES (:key, :value) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"),
                {"key": k, "value": json.dumps(v)})
    return get_platform_settings()


def update_user(user_id: str, **fields: Any) -> None:
    allowed = {"is_super_admin", "is_active", "display_name", "force_password_reset"}
    keys = [k for k in fields if k in allowed]
    if not keys:
        return
    params: dict[str, Any] = {k: fields[k] for k in keys}
    params["id"] = user_id
    params["updated_at"] = _now()
    set_clause = ", ".join(f"{k} = :{k}" for k in keys)
    with _rw() as conn:
        conn.execute(text(f"UPDATE users SET {set_clause}, updated_at = :updated_at WHERE id = :id"), params)


def delete_user(user_id: str) -> bool:
    with _rw() as conn:
        result = conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        return result.rowcount > 0


def list_all_users() -> list[dict[str, Any]]:
    with _ro() as conn:
        rows = conn.execute(text("SELECT * FROM users ORDER BY created_at")).mappings().fetchall()
        return [_user_row(r) for r in rows]


# ---------------- tenants ----------------
def _tenant_row(row: Any) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "slug": row["slug"],
            "is_active": bool(row["is_active"]), "created_at": row["created_at"]}


def create_tenant(name: str, tenant_id: Optional[str] = None) -> dict[str, Any]:
    tid = tenant_id or uuid.uuid4().hex[:8]
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO tenants (id, name, slug, created_at, is_active) VALUES (:id, :name, :slug, :created_at, 1)"),
            {"id": tid, "name": name, "slug": tid, "created_at": _now()})
    return get_tenant(tid)  # type: ignore[return-value]


def get_tenant(tenant_id: str) -> Optional[dict[str, Any]]:
    with _ro() as conn:
        row = conn.execute(text("SELECT * FROM tenants WHERE id = :id"), {"id": tenant_id}).mappings().fetchone()
        return _tenant_row(row) if row else None


def list_tenants() -> list[dict[str, Any]]:
    with _ro() as conn:
        rows = conn.execute(text("SELECT * FROM tenants ORDER BY created_at")).mappings().fetchall()
        result = []
        for r in rows:
            member_count = conn.execute(
                text("SELECT COUNT(*) AS c FROM user_tenant_roles WHERE tenant_id = :id"),
                {"id": r["id"]}).mappings().fetchone()["c"]
            result.append({**_tenant_row(r), "member_count": member_count})
        return result


def delete_tenant(tenant_id: str) -> bool:
    with _rw() as conn:
        result = conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        return result.rowcount > 0


# ---------------- user <-> tenant roles ----------------
def get_user_role_in_tenant(user_id: str, tenant_id: str) -> Optional[str]:
    with _ro() as conn:
        row = conn.execute(text(
            "SELECT role FROM user_tenant_roles WHERE user_id = :user_id AND tenant_id = :tenant_id"),
            {"user_id": user_id, "tenant_id": tenant_id}).mappings().fetchone()
        return row["role"] if row else None


def set_user_tenant_role(user_id: str, tenant_id: str, role: str,
                         permission_overrides: Optional[list[str]] = None) -> None:
    if role not in ROLES:
        raise ValueError(f"Invalid role '{role}'")
    overrides_json = json.dumps(permission_overrides) if permission_overrides else None
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO user_tenant_roles (user_id, tenant_id, role, permission_overrides, created_at) "
            "VALUES (:user_id, :tenant_id, :role, :overrides, :created_at) "
            "ON CONFLICT(user_id, tenant_id) DO UPDATE SET role = excluded.role, "
            "permission_overrides = excluded.permission_overrides"),
            {"user_id": user_id, "tenant_id": tenant_id, "role": role, "overrides": overrides_json,
             "created_at": _now()})


def get_user_tenant_access(user_id: str, tenant_id: str) -> Optional[dict[str, Any]]:
    """Returns {role, permission_overrides} for a user in a tenant, or None."""
    with _ro() as conn:
        row = conn.execute(text(
            "SELECT role, permission_overrides FROM user_tenant_roles "
            "WHERE user_id = :user_id AND tenant_id = :tenant_id"),
            {"user_id": user_id, "tenant_id": tenant_id}).mappings().fetchone()
        if not row:
            return None
        return {"role": row["role"],
                "permission_overrides": json.loads(row["permission_overrides"]) if row["permission_overrides"] else []}


def remove_user_tenant_role(user_id: str, tenant_id: str) -> bool:
    with _rw() as conn:
        result = conn.execute(text(
            "DELETE FROM user_tenant_roles WHERE user_id = :user_id AND tenant_id = :tenant_id"),
            {"user_id": user_id, "tenant_id": tenant_id})
        return result.rowcount > 0


def get_accessible_tenants(user: dict[str, Any]) -> list[dict[str, Any]]:
    """Tenants this user can open, with their effective role in each.
    super_admin bypasses per-tenant rows entirely and sees every tenant."""
    with _ro() as conn:
        if user["is_super_admin"]:
            rows = conn.execute(
                text("SELECT * FROM tenants WHERE is_active = 1 ORDER BY name")).mappings().fetchall()
            return [{**_tenant_row(r), "role": "super_admin"} for r in rows]
        rows = conn.execute(text(
            "SELECT t.*, utr.role AS role FROM tenants t "
            "JOIN user_tenant_roles utr ON utr.tenant_id = t.id "
            "WHERE utr.user_id = :user_id AND t.is_active = 1 ORDER BY t.name"),
            {"user_id": user["id"]}).mappings().fetchall()
        return [{**_tenant_row(r), "role": r["role"]} for r in rows]


def list_tenant_users(tenant_id: str) -> list[dict[str, Any]]:
    with _ro() as conn:
        rows = conn.execute(text(
            "SELECT u.*, utr.role AS role, utr.permission_overrides AS permission_overrides FROM users u "
            "JOIN user_tenant_roles utr ON utr.user_id = u.id "
            "WHERE utr.tenant_id = :tenant_id ORDER BY u.email"),
            {"tenant_id": tenant_id}).mappings().fetchall()
        return [{**_user_row(r), "role": r["role"],
                "permission_overrides": json.loads(r["permission_overrides"]) if r["permission_overrides"] else []}
                for r in rows]


# ---------------- invites ----------------
def create_invite(email: str, tenant_id: Optional[str], role: str,
                  invited_by: str, ttl_hours: int = 168) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_hours * 3600))
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO invites (token, email, tenant_id, role, invited_by, expires_at) "
            "VALUES (:token, :email, :tenant_id, :role, :invited_by, :expires_at)"),
            {"token": token, "email": email.strip().lower(), "tenant_id": tenant_id, "role": role,
             "invited_by": invited_by, "expires_at": expires})
    return {"token": token, "email": email, "tenant_id": tenant_id, "role": role, "expires_at": expires}


def get_invite(token: str) -> Optional[dict[str, Any]]:
    with _ro() as conn:
        row = conn.execute(text("SELECT * FROM invites WHERE token = :token"), {"token": token}).mappings().fetchone()
        return dict(row) if row else None


def consume_invite(token: str) -> None:
    with _rw() as conn:
        conn.execute(text("UPDATE invites SET used_at = :now WHERE token = :token"),
                     {"now": _now(), "token": token})


def is_invite_valid(invite: dict[str, Any]) -> bool:
    if invite.get("used_at"):
        return False
    return invite["expires_at"] > _now()


# ---------------- API keys (programmatic/public API access) ----------------
API_KEY_PREFIX = "rvk_"


def create_api_key(tenant_id: str, name: str, role: str,
                   created_by: Optional[str] = None) -> dict[str, Any]:
    """Returns the key record PLUS the one-time-visible raw_key — callers must
    show it to the user immediately and never persist it themselves; only
    its SHA-256 hash is stored, exactly like a password, but without a salt
    (unlike passwords, a high-entropy random token needs no per-value salt,
    and a deterministic hash is what makes an O(1) lookup-by-value possible
    for authenticating every API request)."""
    if role not in ROLES:
        raise ValueError(f"Invalid role '{role}'")
    raw_key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    kid = uuid.uuid4().hex
    now = _now()
    with _rw() as conn:
        conn.execute(text(
            "INSERT INTO api_keys (id, tenant_id, name, key_hash, role, created_by, created_at, revoked) "
            "VALUES (:id, :tenant_id, :name, :key_hash, :role, :created_by, :created_at, 0)"),
            {"id": kid, "tenant_id": tenant_id, "name": name.strip(), "key_hash": key_hash, "role": role,
             "created_by": created_by, "created_at": now})
    return {"id": kid, "tenant_id": tenant_id, "name": name.strip(), "role": role,
            "created_at": now, "last_used_at": None, "revoked": False, "raw_key": raw_key}


def list_api_keys(tenant_id: str) -> list[dict[str, Any]]:
    with _ro() as conn:
        rows = conn.execute(text(
            "SELECT id, tenant_id, name, role, created_at, last_used_at, revoked FROM api_keys "
            "WHERE tenant_id = :tid ORDER BY created_at DESC"),
            {"tid": tenant_id}).mappings().fetchall()
        return [{**dict(r), "revoked": bool(r["revoked"])} for r in rows]


def revoke_api_key(tenant_id: str, key_id: str) -> bool:
    with _rw() as conn:
        result = conn.execute(text(
            "UPDATE api_keys SET revoked = 1 WHERE id = :id AND tenant_id = :tid"),
            {"id": key_id, "tid": tenant_id})
        return result.rowcount > 0


def verify_api_key(raw_key: str) -> Optional[dict[str, Any]]:
    """Returns {id, tenant_id, name, role} for a live (non-revoked) key, or
    None. Updates last_used_at on every successful check, so a tenant admin
    can see which keys are actually in use vs. dead weight."""
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    with _rw() as conn:
        row = conn.execute(text(
            "SELECT * FROM api_keys WHERE key_hash = :hash AND revoked = 0"),
            {"hash": key_hash}).mappings().fetchone()
        if not row:
            return None
        conn.execute(text("UPDATE api_keys SET last_used_at = :now WHERE id = :id"),
                     {"now": _now(), "id": row["id"]})
        return {"id": row["id"], "tenant_id": row["tenant_id"], "name": row["name"], "role": row["role"]}
