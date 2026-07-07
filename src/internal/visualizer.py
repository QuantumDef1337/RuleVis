"""
RuleVis API server — multi-tenant, RBAC-enabled.

Auth (unprefixed, session-cookie based):
  GET  /api/auth/bootstrap-status              whether first-run admin setup is needed
  POST /api/auth/bootstrap                      create the first super_admin (only once)
  POST /api/auth/login | logout                 session login/logout (+ MFA challenge)
  GET  /api/auth/me                             current user + accessible tenants
  POST /api/auth/change-password                self-service password change
  POST /api/auth/mfa/setup|enable|disable        TOTP enrollment
  GET  /api/invites/<token>                      look up a pending invite
  POST /api/invites/<token>/accept               accept an invite, create/attach account

Platform admin (super_admin only):
  GET/POST/DELETE /api/super/tenants[/<id>]      tenant management
  GET/PUT/DELETE  /api/super/users[/<id>]        cross-tenant user management
  GET/PUT         /api/platform-settings         security policy (lockout, password, MFA…)
  GET             /api/super/login-activity      global login history

Everything else is tenant-scoped under /api/t/<tenant_id>/... (see README-level
comment further down for the full list — unchanged in shape from the
single-tenant version, just prefixed and permission-gated).
"""

import calendar
import json
import logging
import os
import secrets
import sys
import tempfile
import threading
import time
from collections import deque
from typing import Any, Optional, Union

from flask import Flask, Response, g, jsonify, redirect, request, send_from_directory, session
from networkx import MultiDiGraph
from werkzeug.utils import secure_filename

from internal import crypto, db, oidc, totp, webhooks
from internal.analyzer import Analyzer
from internal.authz import Permission, require_login, require_permission, require_super_admin
from internal.config import (
    Config, cache_dir, delete_tenant_dir, redact_github_source, redact_manager,
    redact_sso_config, redact_webhook, uploads_dir,
)
from internal.differ import diff_graphs, diff_rule_sets
from internal.exporter import EXPORTERS
from internal.generator import GraphGenerator
from internal.github_source import GithubApiError
from internal.github_source import client_from_config as github_client_from_config
from internal.health import compute_health
from internal.migrate import migrate_if_needed
from internal.tenancy import TenantManager
from internal.wazuh_api import WazuhApiError, client_from_config

PRECOMPUTED_BLOCK_SIZES: list[int] = [1, 10, 50, 100, 250, 500]

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
DIST_DIR = os.path.join(STATIC_DIR, "dist")

VALID_ROLES = ("tenant_admin", "analyst", "viewer")


def parse_start(idstr: Any) -> int:
    if not idstr:
        return 0
    s = str(idstr).strip()
    for sep in ("-", "–"):
        if sep in s:
            s = s.split(sep, 1)[0]
            break
    try:
        return int(s)
    except Exception:
        return 0


class Workspace:
    """Holds one tenant's loaded graph + derived data; can rebuild at runtime."""

    def __init__(self, cfg: Config, cli_paths: list[str]) -> None:
        self.cfg = cfg
        self.cli_paths = [p for p in cli_paths if p]
        self.G: MultiDiGraph = MultiDiGraph()
        self.stats: dict[str, Any] = {}
        self.health: dict[str, Any] = {}
        self.heatmaps: dict[int, Any] = {}
        self.base_blocks: list[dict[str, Any]] = []
        self.file_index: dict[str, dict[str, Any]] = {}
        self.case_nodes: set[str] = set()

    # ---------- building ----------
    def effective_paths(self) -> list[str]:
        tid = self.cfg.tenant_id
        paths = list(dict.fromkeys(self.cli_paths + self.cfg.paths))
        upl = uploads_dir(tid)
        with os.scandir(upl) as it:
            if any(it):
                paths.append(upl)
        for m in self.cfg.managers:
            if m.get("include") and m.get("id"):
                cached = cache_dir(tid, m["id"])
                if os.path.isdir(cached):
                    paths.append(cached)
        for s in self.cfg.github_sources:
            if s.get("include") and s.get("id"):
                cached = cache_dir(tid, f"gh-{s['id']}")
                if os.path.isdir(cached):
                    paths.append(cached)
        return paths

    def rebuild(self) -> dict[str, Any]:
        paths = self.effective_paths()
        logging.info(f"(Re)building graph for tenant '{self.cfg.tenant_id}' from: {paths}")
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            generator = GraphGenerator(
                paths=paths, graph_file=tmp.name,
                product_map=self.cfg.product_map())
            generator.build_graph_from_xml()
            self.G = generator.G
        finally:
            try:
                os.remove(tmp.name)
            except OSError:
                ...
        analyzer = Analyzer(graph=self.G)
        self.stats = analyzer.calculate_statistics()
        self.health = compute_health(self.G)
        heatmap = analyzer.calculate_heatmap_data()
        self.base_blocks = heatmap.get("blocks", [])
        self.heatmaps = {}
        self._precompute_heatmaps()
        self._index_files()
        self._compute_case_nodes()
        return self.overview()

    def retag_products(self) -> None:
        """Cheap product re-tagging after mapping changes (no reparse)."""
        mapping = self.cfg.product_map()
        for n in self.G.nodes:
            attrs = self.G.nodes[n]
            file = str(attrs.get("file", "") or "").lower()
            if file:
                attrs["product"] = mapping.get(file)
        self._index_files()
        self._compute_case_nodes()

    def _compute_case_nodes(self) -> None:
        """Set of rule IDs that are production/case-managed: the rule itself or
        any ancestor carries one of the tenant's case tags. Computed once here
        (cycle-safe ancestor walk) and cached, so per-product 'Production
        Rules' counts and the rule-detail 'case' flag are O(1) lookups."""
        tags = set(self.cfg.case_tags)
        if not tags:
            self.case_nodes = set()
            return
        result: set[str] = set()
        for n in self.real_nodes():
            visited: set[str] = set()
            stack = [n]
            while stack:
                cur = stack.pop()
                if cur in visited or cur == "0":
                    continue
                visited.add(cur)
                if tags.intersection(self.G.nodes[cur].get("groups", []) or []):
                    result.add(n)
                    break
                stack.extend(self.G.predecessors(cur))
        self.case_nodes = result

    def is_case_rule(self, nid: str) -> bool:
        return nid in self.case_nodes

    def _index_files(self) -> None:
        files: dict[str, dict[str, Any]] = {}
        mapping = self.cfg.product_map()
        for n in self.G.nodes:
            if n == "0":
                continue
            attrs = self.G.nodes[n]
            file = attrs.get("file")
            if not file:
                continue
            entry = files.setdefault(file, {
                "file": file,
                "path": attrs.get("path"),
                "rule_count": 0,
                "product": mapping.get(file.lower()),
                "builtin": "ruleset" in str(attrs.get("path", "")).lower(),
            })
            entry["rule_count"] += 1
        self.file_index = files

    def _precompute_heatmaps(self) -> None:
        starts_and_counts = [(parse_start(b.get("id")), int(b.get("count", 0)))
                             for b in self.base_blocks]
        max_start = max((s for s, _ in starts_and_counts), default=0)
        for bs in PRECOMPUTED_BLOCK_SIZES:
            self.heatmaps[bs] = self.compute_heatmap(bs, starts_and_counts, max_start)

    def compute_heatmap(self, bs: int,
                        starts_and_counts: Optional[list[tuple[int, int]]] = None,
                        max_start: Optional[int] = None) -> dict[str, Any]:
        if starts_and_counts is None:
            starts_and_counts = [(parse_start(b.get("id")), int(b.get("count", 0)))
                                 for b in self.base_blocks]
        if max_start is None:
            max_start = max((s for s, _ in starts_and_counts), default=0)
        if bs == 1:
            ids = sorted(str(s) for s, _ in starts_and_counts)
            return {"block_size": 1, "ids": ids}
        acc: dict[str, int] = {}
        for start, count in starts_and_counts:
            bucket = (start // bs) * bs
            key = f"{bucket}-{bucket + bs - 1}"
            acc[key] = acc.get(key, 0) + count
        blocks = [{"id": k, "count": v} for k, v in acc.items()]
        blocks.sort(key=lambda b: int(b["id"].split("-")[0]))
        return {
            "metadata": {"block_size": bs, "max_id": max_start,
                         "total_blocks": len(blocks)},
            "blocks": blocks,
        }

    # ---------- queries ----------
    def real_nodes(self) -> list[str]:
        return [n for n in self.G.nodes if n != "0"]

    def overview(self) -> dict[str, Any]:
        files = self.file_index
        levels: dict[str, int] = {}
        group_set: set[str] = set()
        builtin_rules = 0
        custom_rules = 0
        for n in self.real_nodes():
            attrs = self.G.nodes[n]
            if "conditions" not in attrs:
                continue  # phantom node (broken dependency reference)
            lvl = str(attrs.get("level", "") or "")
            if lvl:
                levels[lvl] = levels.get(lvl, 0) + 1
            for grp in attrs.get("groups", []):
                group_set.add(grp)
            if "ruleset" in str(attrs.get("path", "")).lower():
                builtin_rules += 1
            else:
                custom_rules += 1
        return {
            "total_rules": len(self.real_nodes()),
            "builtin_rules": builtin_rules,
            "custom_rules": custom_rules,
            "total_edges": self.G.number_of_edges(),
            "total_files": len(files),
            "total_groups": len(group_set),
            "total_products": len(self.cfg.products),
            "unmapped_files": sum(1 for f in files.values() if not f["product"]),
            "levels": levels,
            "paths": self.effective_paths(),
        }

    def product_nodes(self, product_name: str) -> set[str]:
        return {n for n in self.real_nodes()
                if self.G.nodes[n].get("product") == product_name}

    def file_nodes(self, basename: str) -> set[str]:
        target = basename.lower()
        return {n for n in self.real_nodes()
                if str(self.G.nodes[n].get("file", "")).lower() == target}

    def selector_nodes(self, selector: str) -> tuple[Optional[set[str]], str]:
        """Resolve 'product:X' | 'file:x.xml' | 'builtin' | 'custom' | 'all'."""
        sel = selector.strip()
        if sel in ("", "all", "local"):
            return set(self.real_nodes()), "all rules"
        if sel == "builtin":
            return ({n for n in self.real_nodes()
                     if "ruleset" in str(self.G.nodes[n].get("path", "")).lower()},
                    "built-in rules")
        if sel == "custom":
            return ({n for n in self.real_nodes()
                     if "ruleset" not in str(self.G.nodes[n].get("path", "")).lower()},
                    "custom rules")
        if sel.startswith("product:"):
            name = sel.split(":", 1)[1]
            return self.product_nodes(name), f"product {name}"
        if sel.startswith("file:"):
            name = sel.split(":", 1)[1]
            return self.file_nodes(name), f"file {name}"
        return None, sel


LOGIN_IP_RATE_LIMIT_MAX = 20
LOGIN_IP_RATE_LIMIT_WINDOW_SECONDS = 15 * 60


def _login_ip_rate_limited(ip: Optional[str]) -> bool:
    """Per-account lockout (db.is_locked_out) only stops brute-forcing one
    known account. This catches the other case — credential stuffing across
    many different accounts from a single source IP. Backed by the database
    (not an in-process dict) so it holds regardless of how many worker
    processes/hosts are serving requests — see db.py's per-IP-rate-limiting
    section for why that distinction matters."""
    if not ip:
        return False
    return db.is_ip_rate_limited(ip, LOGIN_IP_RATE_LIMIT_MAX, LOGIN_IP_RATE_LIMIT_WINDOW_SECONDS)


def _register_login_ip_failure(ip: Optional[str]) -> None:
    if not ip:
        return
    db.register_ip_login_failure(ip)


class SyncInProgress(Exception):
    """Raised when a sync is requested for a manager/source that's already
    mid-sync — e.g. the auto-sync scheduler firing while a user-triggered
    'Sync now' is still running for the same target."""


_active_syncs: set[str] = set()
_active_syncs_lock = threading.Lock()


def build_cache_graph(ws: "Workspace", cache_path: str) -> Optional[MultiDiGraph]:
    """Parses an existing on-disk rule cache into a standalone graph, for
    before/after diffing around a fetch. Returns None if the cache is
    empty/missing (e.g. first-ever sync — nothing to diff against)."""
    if not os.path.isdir(cache_path) or not any(os.scandir(cache_path)):
        return None
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    try:
        gen = GraphGenerator(paths=[cache_path], graph_file=tmp.name,
                             product_map=ws.cfg.product_map())
        gen.build_graph_from_xml()
        return gen.G
    finally:
        try:
            os.remove(tmp.name)
        except OSError:
            ...


def sync_manager_now(ws: "Workspace", tenant_id: str, mid: str,
                     actor_user_id: Optional[str], actor_email: str,
                     ip_address: Optional[str] = None, rebuild: bool = True) -> dict[str, Any]:
    """Fetches a manager's ruleset, diffs it against the previous cache, logs
    the activity/audit trail, and (optionally) rebuilds the workspace. Shared
    by the interactive '/fetch' route and the background auto-sync loop —
    neither depends on Flask's request context, so it can run from a thread."""
    manager = ws.cfg.get_manager(mid)
    if not manager:
        raise ValueError(f"Manager '{mid}' not found")
    label = manager.get("name") or manager.get("url")
    key = f"manager:{tenant_id}:{mid}"
    with _active_syncs_lock:
        if key in _active_syncs:
            db.log_audit("sync_manager_skipped", actor_user_id=actor_user_id, actor_email=actor_email,
                         target_type="manager", target_id=mid, tenant_id=tenant_id, ip_address=ip_address,
                         details=f"Sync of {label} skipped — another sync for this manager is already running")
            raise SyncInProgress(f"A sync for '{label}' is already running")
        _active_syncs.add(key)
    try:
        target_root = cache_dir(tenant_id, mid)
        before = build_cache_graph(ws, target_root)
        try:
            client = client_from_config(manager)
            result = client.download_ruleset(target_root, mid, include_builtin=True, include_custom=True)
        except WazuhApiError as e:
            manager["last_sync_status"] = "failed"
            manager["last_sync_error"] = str(e)
            manager["last_synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            ws.cfg.upsert_manager(manager)
            db.log_audit("sync_manager_failed", actor_user_id=actor_user_id, actor_email=actor_email,
                         target_type="manager", target_id=mid, tenant_id=tenant_id, ip_address=ip_address,
                         details=f"Sync of {label} failed: {e}")
            raise
        activity_msg = f"Synced {result['downloaded']}/{result['total']} rule files from {label}"
        after = build_cache_graph(ws, target_root)
        audit_details: Optional[str] = None
        if before is not None and after is not None:
            d = diff_graphs(before, after, "previous sync", "this sync")
            result["diff"] = d
            s = d["summary"]
            activity_msg += f" — +{s['added']}, -{s['removed']}, {s['changed']} changed"
            audit_details = json.dumps({
                "manager": label,
                "added": [r["id"] for r in d["added"]],
                "removed": [r["id"] for r in d["removed"]],
                "changed": [{"id": c["id"], "fields": [ch["field"] for ch in c["changes"]]}
                            for c in d["changed"]],
            })
        ws.cfg.log_activity("fetch", activity_msg)
        db.log_audit("sync_manager", actor_user_id=actor_user_id, actor_email=actor_email,
                     target_type="manager", target_id=mid, tenant_id=tenant_id, ip_address=ip_address,
                     details=audit_details or f"Synced {result['downloaded']} files from {label} (no prior snapshot to diff)")
        manager["include"] = True
        manager["last_sync_status"] = "success"
        manager["last_sync_error"] = None
        manager["last_synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ws.cfg.upsert_manager(manager)
        if rebuild:
            result["overview"] = ws.rebuild()
        return result
    finally:
        with _active_syncs_lock:
            _active_syncs.discard(key)


def sync_github_source_now(ws: "Workspace", tenant_id: str, sid: str,
                           actor_user_id: Optional[str], actor_email: str,
                           ip_address: Optional[str] = None, rebuild: bool = True) -> dict[str, Any]:
    """GitHub-source counterpart to sync_manager_now — same shared-by-route-
    and-scheduler design."""
    source = ws.cfg.get_github_source(sid)
    if not source:
        raise ValueError(f"GitHub source '{sid}' not found")
    label = source.get("name") or source.get("repo")
    key = f"github:{tenant_id}:{sid}"
    with _active_syncs_lock:
        if key in _active_syncs:
            db.log_audit("sync_github_source_skipped", actor_user_id=actor_user_id, actor_email=actor_email,
                         target_type="github_source", target_id=sid, tenant_id=tenant_id, ip_address=ip_address,
                         details=f"Sync of {label} skipped — another sync for this source is already running")
            raise SyncInProgress(f"A sync for '{label}' is already running")
        _active_syncs.add(key)
    try:
        target_root = cache_dir(tenant_id, f"gh-{sid}")
        try:
            result = github_client_from_config(source).download_ruleset(target_root, sid)
        except GithubApiError as e:
            source["last_sync_status"] = "failed"
            source["last_sync_error"] = str(e)
            source["last_synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            ws.cfg.upsert_github_source(source)
            db.log_audit("sync_github_source_failed", actor_user_id=actor_user_id, actor_email=actor_email,
                         target_type="github_source", target_id=sid, tenant_id=tenant_id, ip_address=ip_address,
                         details=f"Sync of {label} failed: {e}")
            raise
        ws.cfg.log_activity("fetch", f"Fetched {result['downloaded']}/{result['total']} rule files from GitHub {label}")
        db.log_audit("sync_github_source", actor_user_id=actor_user_id, actor_email=actor_email,
                     target_type="github_source", target_id=sid, tenant_id=tenant_id, ip_address=ip_address,
                     details=f"Fetched {result['downloaded']} files from {label}")
        source["include"] = True
        source["last_sync_status"] = "success"
        source["last_sync_error"] = None
        source["last_synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ws.cfg.upsert_github_source(source)
        if rebuild:
            result["overview"] = ws.rebuild()
        return result
    finally:
        with _active_syncs_lock:
            _active_syncs.discard(key)


def _minutes_since(iso_ts: Optional[str]) -> float:
    if not iso_ts:
        return float("inf")
    try:
        epoch = calendar.timegm(time.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ"))
        return (time.time() - epoch) / 60
    except ValueError:
        return float("inf")


def _auto_sync_loop(tenant_manager: TenantManager, poll_seconds: int = 60) -> None:
    """Background daemon thread: every `poll_seconds`, checks every tenant's
    managers/GitHub sources for auto_sync=True entries whose interval has
    elapsed, and syncs them. Runs outside any Flask request context, so
    sync_manager_now/sync_github_source_now must not depend on flask.g."""
    while True:
        time.sleep(poll_seconds)
        try:
            for t in db.list_tenants():
                tenant_id = t["id"]
                try:
                    ws = tenant_manager.get(tenant_id)
                except Exception:
                    logging.exception(f"auto-sync: failed to load workspace for tenant '{tenant_id}'")
                    continue
                for m in list(ws.cfg.managers):
                    if not m.get("auto_sync"):
                        continue
                    interval = max(5, int(m.get("sync_interval_minutes") or 60))
                    if _minutes_since(m.get("last_synced_at")) >= interval:
                        try:
                            sync_manager_now(ws, tenant_id, m["id"], None, "system:auto-sync")
                        except Exception:
                            logging.exception(f"auto-sync: manager '{m.get('id')}' in tenant '{tenant_id}' failed")
                for s in list(ws.cfg.github_sources):
                    if not s.get("auto_sync"):
                        continue
                    interval = max(5, int(s.get("sync_interval_minutes") or 60))
                    if _minutes_since(s.get("last_synced_at")) >= interval:
                        try:
                            sync_github_source_now(ws, tenant_id, s["id"], None, "system:auto-sync")
                        except Exception:
                            logging.exception(f"auto-sync: github source '{s.get('id')}' in tenant '{tenant_id}' failed")
        except Exception:
            logging.exception("auto-sync loop iteration failed")


def _retention_sweep_loop(interval_seconds: int = 3600) -> None:
    """Background daemon thread: enforces the configured audit/login-history
    retention on a fixed schedule, rather than only when a user happens to
    open the Audit log / Login activity / System settings pages (the
    previous behavior — old records could accumulate indefinitely if nobody
    visited those pages)."""
    while True:
        try:
            db.sweep_retention()
            # Keep the rate-limit table small — failures older than the
            # window can never contribute to a future rate-limit decision.
            db.sweep_ip_login_failures(LOGIN_IP_RATE_LIMIT_WINDOW_SECONDS)
        except Exception:
            logging.exception("retention sweep failed")
        time.sleep(interval_seconds)


def create_app(cli_paths: list[str]) -> Flask:
    migrate_if_needed()
    db.init_schema()  # idempotent (CREATE TABLE IF NOT EXISTS) — safe even post-migration

    tenant_manager = TenantManager(cli_paths, lambda cfg, paths: Workspace(cfg, paths))
    threading.Thread(target=_auto_sync_loop, args=(tenant_manager,), daemon=True).start()
    threading.Thread(target=_retention_sweep_loop, daemon=True).start()

    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None  # type: ignore
    app = Flask(__name__, static_folder=None)
    app.secret_key = db.secret_key()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    PUBLIC_EXACT = {"/api/ping", "/api/auth/login", "/api/auth/logout", "/api/auth/me",
                    "/api/auth/bootstrap-status", "/api/auth/bootstrap"}
    # /api/auth/sso/ establishes its own session via the IdP redirect —
    # can't require a session to reach the routes that create one.
    PUBLIC_PREFIXES = ("/api/invites/", "/api/auth/sso/")

    def error(message: str, code: int = 400) -> tuple[Response, int]:
        return jsonify({"error": message}), code

    def _log_audit(*args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("ip_address", request.remote_addr)
        db.log_audit(*args, **kwargs)
        action = args[0] if args else kwargs.get("action")
        tenant_id = kwargs.get("tenant_id")
        if tenant_id and action in webhooks.WEBHOOK_EVENTS:
            try:
                ws = tenant_manager.get(tenant_id)
            except Exception:
                return
            if not ws.cfg.webhooks:
                return
            details = {"target": kwargs.get("target_id"), "details": kwargs.get("details")}
            # Fire-and-forget: an unreachable Slack/Teams/ServiceNow endpoint
            # must never slow down or fail the request that triggered this.
            threading.Thread(target=webhooks.dispatch_event,
                            args=(ws.cfg, tenant_id, action, details), daemon=True).start()

    # ---------- auth / tenant resolution ----------
    @app.before_request
    def _resolve_context() -> Optional[tuple[Response, int]]:
        path = request.path
        if not path.startswith("/api/"):
            return None  # SPA/static assets — the frontend route-guards handle gating
        if path in PUBLIC_EXACT or any(path.startswith(p) for p in PUBLIC_PREFIXES):
            return None

        # API-key auth (for external/programmatic access — CI, ticketing
        # integrations, scripts) — an alternative to the session cookie,
        # never both. Scoped to exactly the one tenant the key was minted
        # for; can't reach /api/super/* (there's no g.user["is_super_admin"]
        # for a key, so require_super_admin rejects it) or other tenants.
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and auth_header[7:].strip().startswith(db.API_KEY_PREFIX):
            key = db.verify_api_key(auth_header[7:].strip())
            if key is None:
                return error("Invalid or revoked API key", 401)
            g.user = {"id": None, "email": f"api-key:{key['name']}", "is_super_admin": False, "is_active": True}
            g.api_key_role = key["role"]
            tenant_id = request.view_args.get("tenant_id") if request.view_args else None
            if tenant_id:
                if tenant_id != key["tenant_id"]:
                    return error("This API key is not valid for this tenant", 403)
                g.tenant_id = tenant_id
                g.ws = tenant_manager.get(tenant_id)
            return None

        user_id = session.get("user_id")
        user = db.get_user_by_id(user_id) if user_id else None
        if user is None or not user["is_active"]:
            return error("Not authenticated", 401)

        settings = db.get_platform_settings()
        last_seen = session.get("last_seen")
        if last_seen and time.time() - last_seen > settings["session_idle_timeout_minutes"] * 60:
            session.clear()
            return error("Session expired", 401)
        session["last_seen"] = time.time()
        g.user = user

        tenant_id = request.view_args.get("tenant_id") if request.view_args else None
        if tenant_id:
            if not user["is_super_admin"] and db.get_user_role_in_tenant(user["id"], tenant_id) is None:
                return error("Forbidden", 403)
            g.tenant_id = tenant_id
            g.ws = tenant_manager.get(tenant_id)
        return None

    def G() -> MultiDiGraph:
        return g.ws.G

    # =====================================================================
    # Auth
    # =====================================================================
    @app.route("/api/ping")
    def ping() -> Response:
        return jsonify({"ok": True, "service": "rulevis"})

    @app.route("/api/auth/bootstrap-status")
    def auth_bootstrap_status() -> Response:
        return jsonify({"needs_bootstrap": db.count_users() == 0})

    @app.route("/api/auth/bootstrap", methods=["POST"])
    def auth_bootstrap() -> Union[Response, tuple[Response, int]]:
        if db.count_users() > 0:
            return error("Setup has already been completed", 410)
        body = request.get_json(silent=True) or {}
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        display_name = body.get("display_name") or ""
        if not email or not password:
            return error("email and password are required", 400)
        settings = db.get_platform_settings()
        if len(password) < settings["password_min_length"]:
            return error(f"Password must be at least {settings['password_min_length']} characters", 400)

        user = db.create_user(email, password, display_name, is_super_admin=True)
        tenants = db.list_tenants()
        default = next((t for t in tenants if t["id"] == "default"), None)
        if default is None and not tenants:
            default = db.create_tenant("Default", tenant_id="default")
        if default:
            db.set_user_tenant_role(user["id"], default["id"], "tenant_admin")

        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = time.time()
        _log_audit("bootstrap_admin", actor_user_id=user["id"], actor_email=user["email"])
        return jsonify({"user": user, "tenants": db.get_accessible_tenants(user)})

    @app.route("/api/auth/login", methods=["POST"])
    def auth_login() -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        mfa_code = (body.get("mfa_code") or "").strip()
        ip = request.remote_addr
        ua = request.headers.get("User-Agent", "")

        if not email or not password:
            return error("email/username and password are required", 400)

        if _login_ip_rate_limited(ip):
            db.record_login_activity(email, False, reason="ip_rate_limited", ip_address=ip, user_agent=ua)
            return error("Too many failed sign-in attempts from this network. Try again later.", 429)

        locked_until = db.is_locked_out(email)
        if locked_until:
            db.record_login_activity(email, False, reason="locked_out", ip_address=ip, user_agent=ua)
            return error(f"Account is locked until {locked_until}", 423)

        user = db.verify_login(email, password)
        if not user:
            db.register_failed_login(email)
            _register_login_ip_failure(ip)
            db.record_login_activity(email, False, reason="bad_credentials", ip_address=ip, user_agent=ua)
            return error("Invalid email/username or password", 401)

        if user["mfa_enabled"]:
            if not mfa_code:
                return jsonify({"mfa_required": True})
            secret = db.get_mfa_secret(user["id"])
            ok = bool(secret) and totp.verify_code(secret, mfa_code)
            if not ok:
                ok = db.consume_backup_code(user["id"], mfa_code)
            if not ok:
                db.register_failed_login(email)
                _register_login_ip_failure(ip)
                db.record_login_activity(email, False, reason="bad_mfa",
                                         user_id=user["id"], ip_address=ip, user_agent=ua)
                return error("Invalid authentication code", 401)

        db.reset_failed_login(user["id"])
        db.record_login_activity(email, True, user_id=user["id"], ip_address=ip, user_agent=ua)
        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = time.time()
        session.permanent = True
        return jsonify({
            "user": user, "tenants": db.get_accessible_tenants(user),
            "mfa_setup_required": bool(user["mfa_required"] and not user["mfa_enabled"]),
        })

    @app.route("/api/auth/logout", methods=["POST"])
    def auth_logout() -> Response:
        session.clear()
        return jsonify({"ok": True})

    # ---------- SSO (OIDC) ----------
    def _sso_redirect_uri(tenant_id: str) -> str:
        return request.url_root.rstrip("/") + f"/api/auth/sso/{tenant_id}/callback"

    @app.route("/api/auth/sso/<tenant_id>/login")
    def sso_login(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        try:
            ws = tenant_manager.get(tenant_id)
        except Exception:
            return error("Unknown tenant", 404)
        sso_cfg = ws.cfg.sso
        if not sso_cfg.get("enabled"):
            return error("SSO is not enabled for this tenant", 404)
        state = oidc.new_state()
        session["sso_state"] = state
        session["sso_tenant_id"] = tenant_id
        try:
            url = oidc.login_via_sso(sso_cfg, _sso_redirect_uri(tenant_id), state)
        except oidc.OidcError as e:
            return error(str(e), 502)
        return redirect(url)

    @app.route("/api/auth/sso/<tenant_id>/callback")
    def sso_callback(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        if request.args.get("state") != session.get("sso_state") or tenant_id != session.get("sso_tenant_id"):
            return error("Invalid or expired SSO login attempt — please try again", 400)
        session.pop("sso_state", None)
        session.pop("sso_tenant_id", None)

        code = request.args.get("code")
        if not code:
            return error(request.args.get("error_description") or "SSO login was cancelled or failed", 400)

        try:
            ws = tenant_manager.get(tenant_id)
        except Exception:
            return error("Unknown tenant", 404)
        sso_cfg = ws.cfg.sso
        if not sso_cfg.get("enabled"):
            return error("SSO is not enabled for this tenant", 404)

        client_secret = crypto.decrypt(sso_cfg.get("client_secret") or "")
        try:
            claims = oidc.complete_sso(sso_cfg, client_secret, code, _sso_redirect_uri(tenant_id))
        except oidc.OidcError as e:
            return error(str(e), 502)

        email = claims["email"]
        ip = request.remote_addr
        ua = request.headers.get("User-Agent", "")
        user = db.get_user_by_email(email)
        if user is None:
            # SSO-provisioned accounts get a random, never-used local password
            # — they can only ever sign in through this tenant's IdP.
            user = db.create_user(email, secrets.token_urlsafe(32), claims.get("name") or "")
            _log_audit("sso_provision_user", actor_email=email, target_type="user",
                         target_id=user["id"], tenant_id=tenant_id)
        if db.get_user_tenant_access(user["id"], tenant_id) is None:
            db.set_user_tenant_role(user["id"], tenant_id, sso_cfg.get("auto_provision_role") or "viewer")

        db.reset_failed_login(user["id"])
        db.record_login_activity(email, True, reason="sso", user_id=user["id"], ip_address=ip, user_agent=ua)
        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = time.time()
        session.permanent = True
        return redirect(f"/t/{tenant_id}")

    @app.route("/api/auth/me")
    def auth_me() -> Union[Response, tuple[Response, int]]:
        user_id = session.get("user_id")
        user = db.get_user_by_id(user_id) if user_id else None
        if not user:
            return error("Not authenticated", 401)
        return jsonify({"user": user, "tenants": db.get_accessible_tenants(user)})

    @app.route("/api/auth/change-password", methods=["POST"])
    @require_login
    def auth_change_password() -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        new_password = body.get("new_password") or ""
        settings = db.get_platform_settings()
        if len(new_password) < settings["password_min_length"]:
            return error(f"Password must be at least {settings['password_min_length']} characters", 400)
        if db.check_password_reuse(g.user["id"], new_password):
            return error(f"Cannot reuse any of your last {settings['password_history_depth']} passwords", 400)
        db.set_password(g.user["id"], new_password)
        _log_audit("change_password", actor_user_id=g.user["id"], actor_email=g.user["email"])
        return jsonify({"ok": True})

    @app.route("/api/auth/mfa/setup", methods=["POST"])
    @require_login
    def auth_mfa_setup() -> Response:
        secret = totp.generate_secret()
        codes = totp.generate_backup_codes(db.get_platform_settings()["mfa_backup_codes_count"])
        db.set_mfa_secret(g.user["id"], secret, codes)
        uri = totp.provisioning_uri(secret, g.user["email"])
        return jsonify({"secret": secret, "uri": uri, "backup_codes": codes})

    @app.route("/api/auth/mfa/enable", methods=["POST"])
    @require_login
    def auth_mfa_enable() -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        code = (body.get("code") or "").strip()
        secret = db.get_mfa_secret(g.user["id"])
        if not secret or not totp.verify_code(secret, code):
            return error("Invalid code", 400)
        db.set_mfa_enabled(g.user["id"], True)
        _log_audit("enable_mfa", actor_user_id=g.user["id"], actor_email=g.user["email"])
        return jsonify({"ok": True})

    @app.route("/api/auth/mfa/disable", methods=["POST"])
    @require_login
    def auth_mfa_disable() -> Response:
        db.set_mfa_enabled(g.user["id"], False)
        db.set_mfa_secret(g.user["id"], None, None)
        _log_audit("disable_mfa", actor_user_id=g.user["id"], actor_email=g.user["email"])
        return jsonify({"ok": True})

    # ---------- invites ----------
    @app.route("/api/invites/<token>")
    def invite_get(token: str) -> Union[Response, tuple[Response, int]]:
        inv = db.get_invite(token)
        if not inv or not db.is_invite_valid(inv):
            return error("Invite not found or expired", 404)
        tenant = db.get_tenant(inv["tenant_id"]) if inv["tenant_id"] else None
        return jsonify({"email": inv["email"], "role": inv["role"],
                        "tenant_name": tenant["name"] if tenant else None})

    @app.route("/api/invites/<token>/accept", methods=["POST"])
    def invite_accept(token: str) -> Union[Response, tuple[Response, int]]:
        inv = db.get_invite(token)
        if not inv or not db.is_invite_valid(inv):
            return error("Invite not found or expired", 404)
        body = request.get_json(silent=True) or {}
        password = body.get("password") or ""
        display_name = body.get("display_name") or ""
        settings = db.get_platform_settings()
        if len(password) < settings["password_min_length"]:
            return error(f"Password must be at least {settings['password_min_length']} characters", 400)

        user = db.get_user_by_email(inv["email"])
        if not user:
            user = db.create_user(inv["email"], password, display_name,
                                  is_super_admin=(inv["role"] == "super_admin"))
        if inv["role"] != "super_admin" and inv["tenant_id"]:
            db.set_user_tenant_role(user["id"], inv["tenant_id"], inv["role"])
        db.consume_invite(token)
        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = time.time()
        _log_audit("accept_invite", actor_user_id=user["id"], actor_email=user["email"],
                     tenant_id=inv["tenant_id"])
        return jsonify({"user": user, "tenants": db.get_accessible_tenants(user)})

    # =====================================================================
    # Platform admin (super_admin only)
    # =====================================================================
    @app.route("/api/super/tenants", methods=["GET", "POST"])
    @require_super_admin
    def super_tenants() -> Union[Response, tuple[Response, int]]:
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            name = (body.get("name") or "").strip()
            if not name:
                return error("Tenant 'name' is required", 400)
            t = db.create_tenant(name)
            _log_audit("create_tenant", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="tenant", target_id=t["id"], tenant_id=t["id"])
            return jsonify(t)
        tenants = db.list_tenants()
        for t in tenants:
            try:
                t["rule_count"] = tenant_manager.get(t["id"]).overview()["total_rules"]
            except Exception:
                t["rule_count"] = None
        return jsonify({"tenants": tenants})

    @app.route("/api/super/tenants/<tid>", methods=["DELETE"])
    @require_super_admin
    def super_tenant_delete(tid: str) -> Union[Response, tuple[Response, int]]:
        if tid == "default":
            return error("The default tenant cannot be deleted", 400)
        deleted = db.delete_tenant(tid)
        tenant_manager.invalidate(tid)
        if deleted:
            # Removing the DB row alone would leave config.json/cache/uploads
            # orphaned on disk forever — clean those up too.
            delete_tenant_dir(tid)
        _log_audit("delete_tenant", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="tenant", target_id=tid)
        return jsonify({"deleted": deleted})

    @app.route("/api/super/users")
    @require_super_admin
    def super_users() -> Response:
        return jsonify({"users": db.list_all_users()})

    @app.route("/api/super/users/<uid>", methods=["PUT"])
    @require_super_admin
    def super_user_update(uid: str) -> Response:
        body = request.get_json(silent=True) or {}
        patch = {k: v for k, v in body.items()
                if k in ("is_super_admin", "is_active", "display_name")}
        db.update_user(uid, **patch)
        _log_audit("update_user", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="user", target_id=uid, details=json.dumps(patch))
        return jsonify(db.get_user_by_id(uid))

    @app.route("/api/super/users/<uid>", methods=["DELETE"])
    @require_super_admin
    def super_user_delete(uid: str) -> Response:
        deleted = db.delete_user(uid)
        _log_audit("delete_user", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="user", target_id=uid)
        return jsonify({"deleted": deleted})

    @app.route("/api/super/login-activity")
    @require_super_admin
    def super_login_activity() -> Response:
        db.sweep_retention()
        return jsonify({"entries": db.list_login_activity()})

    @app.route("/api/super/audit-log")
    @require_super_admin
    def super_audit_log() -> Response:
        db.sweep_retention()
        deletions_only = request.args.get("deletions_only") == "1"
        return jsonify({"entries": db.list_audit_log(deletions_only=deletions_only)})

    @app.route("/api/platform-settings", methods=["GET", "PUT"])
    @require_super_admin
    def platform_settings_route() -> Response:
        if request.method == "PUT":
            db.set_platform_settings(request.get_json(silent=True) or {})
        return jsonify(db.get_platform_settings())

    # =====================================================================
    # Tenant-scoped: users & activity
    # =====================================================================
    @app.route("/api/t/<tenant_id>/users")
    @require_permission(Permission.MANAGE_TENANT_USERS)
    def tenant_users(tenant_id: str) -> Response:
        return jsonify({"users": db.list_tenant_users(tenant_id)})

    @app.route("/api/t/<tenant_id>/users/invite", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_USERS)
    def tenant_user_invite(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        email = (body.get("email") or "").strip()
        role = body.get("role") or "viewer"
        if not email or role not in VALID_ROLES:
            return error("Valid 'email' and 'role' are required", 400)
        inv = db.create_invite(email, tenant_id, role, g.user["id"])
        _log_audit("invite_user", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="invite", tenant_id=tenant_id, details=f"{email} as {role}")
        return jsonify({"invite_url": f"/accept-invite?token={inv['token']}", **inv})

    @app.route("/api/t/<tenant_id>/users/create", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_USERS)
    def tenant_user_create(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        username = (body.get("username") or "").strip()
        display_name = (body.get("display_name") or "").strip()
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        role = body.get("role") or "viewer"
        overrides = [p for p in (body.get("permission_overrides") or []) if p in [pm.value for pm in Permission]]
        force_password_reset = bool(body.get("force_password_reset"))
        require_mfa = bool(body.get("require_mfa"))

        if not username:
            return error("'username' is required", 400)
        if role not in VALID_ROLES:
            return error(f"Invalid role '{role}'", 400)
        settings = db.get_platform_settings()
        if len(password) < settings["password_min_length"]:
            return error(f"Password must be at least {settings['password_min_length']} characters", 400)
        if db.get_user_by_username(username):
            return error(f"Username '{username}' is already taken", 409)
        if email and db.get_user_by_email(email):
            return error(f"Email '{email}' is already in use", 409)

        user = db.create_user(email, password, display_name, username=username,
                              force_password_reset=force_password_reset, mfa_required=require_mfa)
        db.set_user_tenant_role(user["id"], tenant_id, role, permission_overrides=overrides)
        _log_audit("create_user", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="user", target_id=user["id"], tenant_id=tenant_id,
                     details=f"{username} as {role}")
        return jsonify({"user": user})

    @app.route("/api/t/<tenant_id>/users/<uid>", methods=["PUT"])
    @require_permission(Permission.MANAGE_TENANT_USERS)
    def tenant_user_role_update(tenant_id: str, uid: str) -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        role = body.get("role")
        if role not in VALID_ROLES:
            return error("Valid 'role' is required", 400)
        overrides = body.get("permission_overrides")
        if overrides is not None:
            overrides = [p for p in overrides if p in [pm.value for pm in Permission]]
        db.set_user_tenant_role(uid, tenant_id, role, permission_overrides=overrides)
        _log_audit("update_user_role", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="user", target_id=uid, tenant_id=tenant_id, details=role)
        return jsonify({"ok": True})

    @app.route("/api/t/<tenant_id>/users/<uid>", methods=["DELETE"])
    @require_permission(Permission.MANAGE_TENANT_USERS)
    def tenant_user_remove(tenant_id: str, uid: str) -> Response:
        removed = db.remove_user_tenant_role(uid, tenant_id)
        _log_audit("delete_user_access", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="user", target_id=uid, tenant_id=tenant_id)
        return jsonify({"deleted": removed})

    @app.route("/api/t/<tenant_id>/audit-log")
    @require_permission(Permission.VIEW_ACTIVITY)
    def tenant_audit_log(tenant_id: str) -> Response:
        db.sweep_retention()
        deletions_only = request.args.get("deletions_only") == "1"
        return jsonify({"entries": db.list_audit_log(tenant_id=tenant_id, deletions_only=deletions_only)})

    # =====================================================================
    # API keys — programmatic/public API access (see db.verify_api_key and
    # the before_request Authorization: Bearer handling above)
    # =====================================================================
    @app.route("/api/t/<tenant_id>/api-keys", methods=["GET", "POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def tenant_api_keys(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            name = (body.get("name") or "").strip()
            role = body.get("role") or "viewer"
            if not name:
                return error("API key 'name' is required", 400)
            if role not in VALID_ROLES:
                return error(f"Invalid role '{role}'", 400)
            created = db.create_api_key(tenant_id, name, role, created_by=g.user["id"])
            _log_audit("create_api_key", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="api_key", target_id=created["id"], tenant_id=tenant_id,
                         details=f"{name} ({role})")
            return jsonify(created)  # raw_key is only ever returned here, once
        return jsonify({"api_keys": db.list_api_keys(tenant_id)})

    @app.route("/api/t/<tenant_id>/api-keys/<kid>", methods=["DELETE"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def tenant_api_key_revoke(tenant_id: str, kid: str) -> Response:
        revoked = db.revoke_api_key(tenant_id, kid)
        if revoked:
            _log_audit("revoke_api_key", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="api_key", target_id=kid, tenant_id=tenant_id)
        return jsonify({"revoked": revoked})

    @app.route("/api/t/<tenant_id>/sso-config", methods=["GET", "PUT"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def tenant_sso_config(tenant_id: str) -> Response:
        if request.method == "PUT":
            patch = request.get_json(silent=True) or {}
            updated = g.ws.cfg.set_sso_config(patch)
            _log_audit("update_sso_config", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="sso_config", tenant_id=tenant_id)
            return jsonify(redact_sso_config(updated))
        return jsonify(redact_sso_config(g.ws.cfg.sso))

    # ---------- shared per-request helpers (close over g.ws via G()) ----------
    def serialize_node(nid: str, displayed: Optional[set[str]] = None) -> dict[str, Any]:
        attrs = G().nodes[nid]
        slim = {k: v for k, v in attrs.items()
                if k not in ("expandable", "conditions", "raw", "raw_overwrite", "path")}
        if displayed is None:
            return {"id": nid, **slim}
        expandable = any(child not in displayed for child in G().successors(nid))
        return {"id": nid, **slim, "expandable": expandable}

    def relation_type(u: str, v: str) -> str:
        data = G().get_edge_data(u, v)
        if not data:
            return "unknown"
        return next(iter(data.values()), {}).get("relation_type", "unknown")

    def make_edge(u: str, v: str) -> dict[str, Any]:
        return {"source": u, "target": v, "relation_type": relation_type(u, v)}

    def rule_type(attrs: dict[str, Any]) -> str:
        """Atomic (one log -> one alert) vs correlation (aggregates prior
        matches over a frequency/timeframe window, or keys off if_matched_*)."""
        if attrs.get("frequency") or attrs.get("timeframe"):
            return "correlation"
        if any(c["tag"] in ("if_matched_sid", "if_matched_group")
               for c in attrs.get("conditions", [])):
            return "correlation"
        return "atomic"

    def is_case_rule(nid: str) -> bool:
        """True if this rule or any ancestor carries one of the tenant's
        case/production tags — served from g.ws's cached case_nodes set."""
        return g.ws.is_case_rule(nid)

    def related_rule(nid: str, other: str, direction: str) -> dict[str, Any]:
        a = G().nodes[other]
        return {
            "id": other,
            "relation_type": relation_type(*((other, nid) if direction == "parent" else (nid, other))),
            "description": a.get("description"),
            "level": a.get("level"),
            "frequency": a.get("frequency"),
            "timeframe": a.get("timeframe"),
            "groups": a.get("groups", []),
            "conditions": a.get("conditions", []),
        }

    def condition_chain(nid: str) -> list[dict[str, Any]]:
        """
        Every ancestor's conditions, furthest-first down to the immediate
        parent, followed by this rule's own conditions last — i.e. the full,
        cumulative set of matches Wazuh must make (parent-first evaluation)
        for this rule's alert to actually fire. Ancestors are picked via
        shortest hop count when a rule has multiple parents (if_group fan-in).
        """
        depth: dict[str, int] = {}
        queue: deque[str] = deque([nid])
        depth[nid] = 0
        while queue:
            cur = queue.popleft()
            for p in G().predecessors(cur):
                if p == "0" or p in depth:
                    continue
                depth[p] = depth[cur] + 1
                queue.append(p)
        ancestors = sorted((n for n in depth if n != nid), key=lambda n: -depth[n])
        chain = [{
            "id": a,
            "description": G().nodes[a].get("description"),
            "level": G().nodes[a].get("level"),
            "conditions": G().nodes[a].get("conditions", []),
        } for a in ancestors]
        chain.append({
            "id": nid,
            "description": G().nodes[nid].get("description"),
            "level": G().nodes[nid].get("level"),
            "conditions": G().nodes[nid].get("conditions", []),
        })
        return chain

    def rule_detail(nid: str) -> dict[str, Any]:
        attrs = G().nodes[nid]
        parents = [related_rule(nid, p, "parent") for p in G().predecessors(nid) if p != "0"]
        children = [related_rule(nid, c, "child") for c in G().successors(nid)]
        level = attrs.get("level")
        return {
            "id": nid,
            "description": attrs.get("description"),
            "groups": attrs.get("groups", []),
            "level": level,
            "file": attrs.get("file"),
            "path": attrs.get("path"),
            "product": attrs.get("product"),
            "source": attrs.get("source"),
            "mitre": attrs.get("mitre", []),
            "conditions": attrs.get("conditions", []),
            "raw": attrs.get("raw"),
            "overwritten": attrs.get("overwritten", False),
            "raw_overwrite": attrs.get("raw_overwrite"),
            "frequency": attrs.get("frequency"),
            "timeframe": attrs.get("timeframe"),
            "ignore": attrs.get("ignore"),
            "noalert": attrs.get("noalert"),
            "rule_type": rule_type(attrs),
            "alerts": bool(level is not None and str(level).isdigit() and int(level) >= 3),
            "case": is_case_rule(nid),
            "parents": parents,
            "children": children,
            "condition_chain": condition_chain(nid),
        }

    def scoped_graph(nodes: set[str]) -> dict[str, Any]:
        """Subgraph of the given nodes plus boundary neighbors outside the scope."""
        boundary: set[str] = set()
        edges: list[dict[str, Any]] = []
        for n in nodes:
            for parent in G().predecessors(n):
                if parent == "0":
                    continue
                if parent not in nodes:
                    boundary.add(parent)
                edges.append(make_edge(parent, n))
            for child in G().successors(n):
                if child in nodes:
                    continue  # in-scope edge already added via the child's parents
                boundary.add(child)
                edges.append(make_edge(n, child))

        seen: set[tuple[str, str]] = set()
        unique_edges = []
        for e in edges:
            key = (e["source"], e["target"])
            if key not in seen:
                seen.add(key)
                unique_edges.append(e)

        node_objs = [{**serialize_node(n), "external": False} for n in sorted(nodes)]
        node_objs += [{**serialize_node(b), "external": True} for b in sorted(boundary)]
        return {"nodes": node_objs, "edges": unique_edges}

    # =====================================================================
    # Overview / catalog
    # =====================================================================
    @app.route("/api/t/<tenant_id>/overview")
    @require_permission(Permission.VIEW_RULES)
    def overview(tenant_id: str) -> Response:
        return jsonify(g.ws.overview())

    @app.route("/api/t/<tenant_id>/health")
    @require_permission(Permission.VIEW_RULES)
    def health(tenant_id: str) -> Response:
        return jsonify(g.ws.health)

    @app.route("/api/t/<tenant_id>/activity")
    @require_permission(Permission.VIEW_RULES)
    def activity(tenant_id: str) -> Response:
        return jsonify({"activity": g.ws.cfg.activity})

    @app.route("/api/t/<tenant_id>/products")
    @require_permission(Permission.VIEW_RULES)
    def products(tenant_id: str) -> Response:
        catalog = []
        for p in g.ws.cfg.products:
            nodes = g.ws.product_nodes(p["name"])
            files = [{"file": f, **({k: v for k, v in g.ws.file_index.get(f, {}).items() if k != "file"})}
                     for f in p.get("files", [])]
            levels: dict[str, int] = {}
            for n in nodes:
                lvl = str(G().nodes[n].get("level", "") or "")
                if lvl:
                    levels[lvl] = levels.get(lvl, 0) + 1
            catalog.append({
                **p,
                "rule_count": len(nodes),
                "production_rules": len(nodes & g.ws.case_nodes),
                "file_details": files,
                "levels": levels,
            })
        unmapped = [f for f in g.ws.file_index.values() if not f["product"]]
        unmapped.sort(key=lambda f: (-f["rule_count"], f["file"]))
        return jsonify({"products": catalog, "unmapped_files": unmapped})

    @app.route("/api/t/<tenant_id>/files")
    @require_permission(Permission.VIEW_RULES)
    def files(tenant_id: str) -> Response:
        items = sorted(g.ws.file_index.values(), key=lambda f: f["file"])
        return jsonify({"files": items})

    # =====================================================================
    # Graphs
    # =====================================================================
    @app.route("/api/t/<tenant_id>/products/<pid>/graph")
    @require_permission(Permission.VIEW_RULES)
    def product_graph(tenant_id: str, pid: str) -> Union[Response, tuple[Response, int]]:
        product = next((p for p in g.ws.cfg.products if p.get("id") == pid
                        or p.get("name") == pid), None)
        if not product:
            return error(f"Product '{pid}' not found", 404)
        nodes = g.ws.product_nodes(product["name"])
        return jsonify({"product": product, **scoped_graph(nodes)})

    @app.route("/api/t/<tenant_id>/graph")
    @require_permission(Permission.VIEW_RULES)
    def graph_by_scope(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        selector = request.args.get("scope", "").strip()
        node_ids, label = g.ws.selector_nodes(selector)
        if node_ids is None:
            return error(f"Unknown scope '{selector}'", 400)
        if len(node_ids) > 3000:
            return error(f"Scope '{label}' has {len(node_ids)} rules — too large "
                         "for a full render. Use the progressive all-rules view.", 400)
        return jsonify({"scope": selector, "label": label, **scoped_graph(node_ids)})

    def _handle_root(displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        root = "0"
        if root not in G():
            return error("Root node not found", 404)
        children = list(G().successors(root))
        nodes = [serialize_node(root, displayed)] + \
            [serialize_node(c, displayed) for c in children]
        edges = [{"source": root, "target": c, "relation_type": "no_parent"}
                 for c in children]
        return jsonify({"nodes": nodes, "edges": edges})

    def _handle_batch(ids_param: str, displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        node_ids = [nid for nid in ids_param.split(",") if nid]
        if not node_ids:
            return jsonify({"nodes": [], "edges": []})
        nodes = [serialize_node(nid, displayed) for nid in node_ids if nid in G()]
        all_relevant = set(node_ids) | displayed
        sub_edges = [
            make_edge(u, v)
            for u, v in G().subgraph(all_relevant).edges()
            if u in node_ids or v in node_ids
        ]
        return jsonify({"nodes": nodes, "edges": sub_edges})

    def _handle_search(node_id: str, displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        if node_id not in G():
            return error(f"Node '{node_id}' not found", 404)
        node_obj = serialize_node(node_id, displayed)
        edges = []
        for p in G().predecessors(node_id):
            if p in displayed:
                edges.append(make_edge(p, node_id))
        for c in G().successors(node_id):
            if c in displayed:
                edges.append(make_edge(node_id, c))
        return jsonify({"nodes": [node_obj], "edges": edges})

    def _handle_single_node(node_id: str, neighbor_mode: str,
                            include_details: bool,
                            displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        if node_id not in G():
            return error(f"Node '{node_id}' not found", 404)
        if include_details:
            return jsonify(rule_detail(node_id))
        nodes = [serialize_node(node_id, displayed)]
        edges = []
        if neighbor_mode in {"parents", "both"}:
            for p in G().predecessors(node_id):
                nodes.append(serialize_node(p, displayed))
                edges.append(make_edge(p, node_id))
        if neighbor_mode in {"children", "both"}:
            for c in G().successors(node_id):
                nodes.append(serialize_node(c, displayed))
                edges.append(make_edge(node_id, c))
        return jsonify({"nodes": nodes, "edges": edges})

    @app.route("/api/t/<tenant_id>/nodes", methods=["GET"])
    @require_permission(Permission.VIEW_RULES)
    def nodes(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        mode = request.args.get("mode", "").strip().lower()
        node_id = request.args.get("id", "").strip()
        ids_param = request.args.get("ids", "").strip()
        neighbor_mode = request.args.get("neighbors", "").strip().lower() or \
            ("children" if node_id else "none")
        include_details = request.args.get("include", "").strip().lower() == "details"
        displayed: set[str] = set(
            filter(None, request.args.get("displayed", "").split(",")))

        if mode == "root":
            return _handle_root(displayed)
        if ids_param:
            return _handle_batch(ids_param, displayed)
        if mode == "search":
            if not node_id:
                return error("mode=search requires an 'id' parameter", 400)
            return _handle_search(node_id, displayed)
        if node_id:
            return _handle_single_node(node_id, neighbor_mode, include_details, displayed)
        return error("Specify one of: mode=root | mode=search&id=... | id=... | ids=...", 400)

    @app.route("/api/t/<tenant_id>/edges", methods=["POST"])
    @require_permission(Permission.VIEW_RULES)
    def edges(tenant_id: str) -> Response:
        payload = request.get_json(silent=True) or {}
        node_ids = payload.get("ids", [])
        if not node_ids:
            return jsonify({"nodes": [], "edges": []})
        edges_list = [make_edge(u, v) for u, v in G().subgraph(node_ids).edges()]
        return jsonify({"nodes": [], "edges": edges_list})

    # =====================================================================
    # Search + rule detail
    # =====================================================================
    @app.route("/api/t/<tenant_id>/rules/search")
    @require_permission(Permission.VIEW_RULES)
    def search(tenant_id: str) -> Response:
        q = request.args.get("q", "").strip()
        product = request.args.get("product", "").strip()
        limit = min(request.args.get("limit", 50, type=int), 200)
        if not q:
            return jsonify({"results": [], "total": 0})

        ql = q.lower()
        scope = g.ws.product_nodes(product) if product else None
        results: list[dict[str, Any]] = []
        total = 0
        for n in g.ws.real_nodes():
            if scope is not None and n not in scope:
                continue
            attrs = G().nodes[n]
            desc = str(attrs.get("description", "") or "")
            groups = attrs.get("groups", [])
            match = (
                n.startswith(q)
                or ql in desc.lower()
                or any(ql in grp.lower() for grp in groups)
            )
            if not match:
                continue
            total += 1
            if len(results) < limit:
                results.append({
                    "id": n,
                    "description": desc,
                    "level": attrs.get("level"),
                    "groups": groups,
                    "file": attrs.get("file"),
                    "product": attrs.get("product"),
                })
        # exact id match first, then numeric id order
        results.sort(key=lambda r: (r["id"] != q, not r["id"].startswith(q),
                                    parse_start(r["id"])))
        return jsonify({"results": results, "total": total})

    @app.route("/api/t/<tenant_id>/rules/<rid>")
    @require_permission(Permission.VIEW_RULES)
    def rule(tenant_id: str, rid: str) -> Union[Response, tuple[Response, int]]:
        if rid not in G() or rid == "0":
            return error(f"Rule '{rid}' not found", 404)
        return jsonify(rule_detail(rid))

    # =====================================================================
    # Stats / heatmap
    # =====================================================================
    @app.route("/api/t/<tenant_id>/stats")
    @require_permission(Permission.VIEW_RULES)
    def stats(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        product = request.args.get("product", "").strip()
        if not product:
            return jsonify(g.ws.stats)
        nodes = g.ws.product_nodes(product)
        if not nodes:
            return error(f"No rules for product '{product}'", 404)
        sub = G().subgraph(nodes | {"0"}).copy()
        analyzer = Analyzer(graph=sub)
        return jsonify(analyzer.calculate_statistics())

    @app.route("/api/t/<tenant_id>/heatmap")
    @require_permission(Permission.VIEW_RULES)
    def heatmap(tenant_id: str) -> Response:
        bs = request.args.get("block_size", type=int)
        if not bs or bs < 1:
            bs = 1
        if bs in g.ws.heatmaps:
            return jsonify(g.ws.heatmaps[bs])
        return jsonify(g.ws.compute_heatmap(bs))

    # =====================================================================
    # Export
    # =====================================================================
    @app.route("/api/t/<tenant_id>/export/<fmt>")
    @require_permission(Permission.EXPORT)
    def export(tenant_id: str, fmt: str) -> Union[Response, tuple[Response, int]]:
        fmt = fmt.lower()
        if fmt not in EXPORTERS:
            return error(f"Unknown format '{fmt}'. Use: {', '.join(EXPORTERS)}", 400)
        selector = request.args.get("scope", "") or \
            (f"product:{request.args.get('product')}" if request.args.get("product") else "all")
        node_ids, label = g.ws.selector_nodes(selector)
        if node_ids is None:
            return error(f"Unknown scope '{selector}'", 400)
        fn, mime, ext = EXPORTERS[fmt]
        try:
            payload = fn(G(), node_ids)
        except Exception as e:
            logging.error(f"Export failed: {e}", exc_info=True)
            return error(f"Export failed: {e}", 500)
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
        g.ws.cfg.log_activity("export", f"{fmt.upper()} export — {label} ({len(node_ids)} rules)")
        _log_audit("export", actor_user_id=g.user["id"], actor_email=g.user["email"],
                     target_type="export", details=f"{fmt} {label}", tenant_id=tenant_id)
        return Response(payload, mimetype=mime, headers={
            "Content-Disposition": f"attachment; filename=rulevis_{safe}.{ext}"})

    # =====================================================================
    # Settings / products / managers / github sources (tenant admin only)
    # =====================================================================
    @app.route("/api/t/<tenant_id>/settings", methods=["GET"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def settings_get(tenant_id: str) -> Response:
        data = dict(g.ws.cfg.data)
        data["managers"] = [redact_manager(m) for m in g.ws.cfg.managers]
        data["github_sources"] = [redact_github_source(s) for s in g.ws.cfg.github_sources]
        return jsonify(data)

    @app.route("/api/t/<tenant_id>/settings", methods=["PUT"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def settings_put(tenant_id: str) -> Response:
        patch = request.get_json(silent=True) or {}
        g.ws.cfg.update(patch)
        g.ws.retag_products()
        data = dict(g.ws.cfg.data)
        data["managers"] = [redact_manager(m) for m in g.ws.cfg.managers]
        data["github_sources"] = [redact_github_source(s) for s in g.ws.cfg.github_sources]
        return jsonify(data)

    @app.route("/api/t/<tenant_id>/products-config", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def product_upsert(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        body = request.get_json(silent=True) or {}
        if not body.get("name"):
            return error("Product 'name' is required", 400)
        product = g.ws.cfg.upsert_product(body)
        g.ws.retag_products()
        return jsonify(product)

    @app.route("/api/t/<tenant_id>/products-config/<pid>", methods=["DELETE"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def product_delete(tenant_id: str, pid: str) -> Response:
        deleted = g.ws.cfg.delete_product(pid)
        g.ws.retag_products()
        if deleted:
            _log_audit("delete_product", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="product", target_id=pid, tenant_id=tenant_id)
        return jsonify({"deleted": deleted})

    @app.route("/api/t/<tenant_id>/managers", methods=["GET", "POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def managers(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            if not body.get("url"):
                return error("Manager 'url' is required", 400)
            saved = g.ws.cfg.upsert_manager(body)
            return jsonify(redact_manager(saved))
        return jsonify({"managers": [redact_manager(m) for m in g.ws.cfg.managers]})

    @app.route("/api/t/<tenant_id>/managers/<mid>", methods=["DELETE"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def manager_delete(tenant_id: str, mid: str) -> Response:
        deleted = g.ws.cfg.delete_manager(mid)
        if deleted:
            _log_audit("delete_manager", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="manager", target_id=mid, tenant_id=tenant_id)
        return jsonify({"deleted": deleted})

    @app.route("/api/t/<tenant_id>/managers/<mid>/test", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def manager_test(tenant_id: str, mid: str) -> Union[Response, tuple[Response, int]]:
        manager = g.ws.cfg.get_manager(mid)
        if not manager:
            return error("Manager not found", 404)
        try:
            info = client_from_config(manager).info()
            return jsonify({"ok": True, "info": info})
        except WazuhApiError as e:
            return jsonify({"ok": False, "error": str(e)})

    @app.route("/api/t/<tenant_id>/managers/<mid>/fetch", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def manager_fetch(tenant_id: str, mid: str) -> Union[Response, tuple[Response, int]]:
        if not g.ws.cfg.get_manager(mid):
            return error("Manager not found", 404)
        body = request.get_json(silent=True) or {}
        try:
            result = sync_manager_now(
                g.ws, tenant_id, mid, g.user["id"], g.user["email"],
                ip_address=request.remote_addr, rebuild=body.get("rebuild", True))
        except SyncInProgress as e:
            return error(str(e), 409)
        except (WazuhApiError, ValueError) as e:
            return error(str(e), 502)
        return jsonify(result)

    @app.route("/api/t/<tenant_id>/github-sources", methods=["GET", "POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def github_sources(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            if not body.get("repo"):
                return error("GitHub source 'repo' (owner/name) is required", 400)
            saved = g.ws.cfg.upsert_github_source(body)
            return jsonify(redact_github_source(saved))
        return jsonify({"github_sources": [redact_github_source(s) for s in g.ws.cfg.github_sources]})

    @app.route("/api/t/<tenant_id>/github-sources/<sid>", methods=["DELETE"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def github_source_delete(tenant_id: str, sid: str) -> Response:
        deleted = g.ws.cfg.delete_github_source(sid)
        if deleted:
            _log_audit("delete_github_source", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="github_source", target_id=sid, tenant_id=tenant_id)
        return jsonify({"deleted": deleted})

    @app.route("/api/t/<tenant_id>/github-sources/<sid>/test", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def github_source_test(tenant_id: str, sid: str) -> Union[Response, tuple[Response, int]]:
        source = g.ws.cfg.get_github_source(sid)
        if not source:
            return error("GitHub source not found", 404)
        try:
            info = github_client_from_config(source).info()
            return jsonify({"ok": True, "info": info})
        except GithubApiError as e:
            return jsonify({"ok": False, "error": str(e)})

    @app.route("/api/t/<tenant_id>/github-sources/<sid>/fetch", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def github_source_fetch(tenant_id: str, sid: str) -> Union[Response, tuple[Response, int]]:
        if not g.ws.cfg.get_github_source(sid):
            return error("GitHub source not found", 404)
        body = request.get_json(silent=True) or {}
        try:
            result = sync_github_source_now(
                g.ws, tenant_id, sid, g.user["id"], g.user["email"],
                ip_address=request.remote_addr, rebuild=body.get("rebuild", True))
        except SyncInProgress as e:
            return error(str(e), 409)
        except (GithubApiError, ValueError) as e:
            return error(str(e), 502)
        return jsonify(result)

    # =====================================================================
    # Webhooks — outbound notifications for rule-change events
    # =====================================================================
    @app.route("/api/t/<tenant_id>/webhooks", methods=["GET", "POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def tenant_webhooks(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            if not body.get("url"):
                return error("Webhook 'url' is required", 400)
            invalid_events = [e for e in (body.get("events") or []) if e not in webhooks.WEBHOOK_EVENTS]
            if invalid_events:
                return error(f"Unknown event(s): {', '.join(invalid_events)}", 400)
            saved = g.ws.cfg.upsert_webhook(body)
            return jsonify(redact_webhook(saved))
        return jsonify({
            "webhooks": [redact_webhook(w) for w in g.ws.cfg.webhooks],
            "available_events": list(webhooks.WEBHOOK_EVENTS),
        })

    @app.route("/api/t/<tenant_id>/webhooks/<wid>", methods=["DELETE"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def webhook_delete(tenant_id: str, wid: str) -> Response:
        deleted = g.ws.cfg.delete_webhook(wid)
        if deleted:
            _log_audit("delete_webhook", actor_user_id=g.user["id"], actor_email=g.user["email"],
                         target_type="webhook", target_id=wid, tenant_id=tenant_id)
        return jsonify({"deleted": deleted})

    @app.route("/api/t/<tenant_id>/webhooks/<wid>/test", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def webhook_test(tenant_id: str, wid: str) -> Union[Response, tuple[Response, int]]:
        webhook = g.ws.cfg.get_webhook(wid)
        if not webhook:
            return error("Webhook not found", 404)
        ok, message = webhooks.send_test(webhook)
        return jsonify({"ok": ok, "message": message})

    @app.route("/api/t/<tenant_id>/upload", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def upload(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        files_in = request.files.getlist("files")
        if not files_in:
            return error("No files provided (expected multipart field 'files')", 400)
        target = uploads_dir(tenant_id)
        saved: list[str] = []
        rejected: list[str] = []
        for f in files_in:
            name = secure_filename(f.filename or "")
            if not name or not name.lower().endswith(".xml"):
                rejected.append(f.filename or "(unnamed)")
                continue
            f.save(os.path.join(target, name))
            saved.append(name)
        if not saved:
            return error("No valid .xml files in upload", 400)
        ov = g.ws.rebuild()
        g.ws.cfg.log_activity("import", f"Uploaded {len(saved)} rule file(s): {', '.join(saved)}")
        return jsonify({"saved": saved, "rejected": rejected, "overview": ov})

    @app.route("/api/t/<tenant_id>/rebuild", methods=["POST"])
    @require_permission(Permission.MANAGE_TENANT_SETTINGS)
    def rebuild(tenant_id: str) -> Response:
        ov = g.ws.rebuild()
        g.ws.cfg.log_activity("import", f"Rebuilt workspace — {ov['total_rules']} rules "
                                        f"from {ov['total_files']} files")
        return jsonify(ov)

    # =====================================================================
    # Diff
    # =====================================================================
    @app.route("/api/t/<tenant_id>/diff")
    @require_permission(Permission.VIEW_RULES)
    def diff(tenant_id: str) -> Union[Response, tuple[Response, int]]:
        left = request.args.get("left", "").strip()
        right = request.args.get("right", "").strip()
        if not left or not right:
            return error("Both 'left' and 'right' selectors are required "
                         "(product:<name> | file:<name> | builtin | custom | manager:<id>)", 400)

        def resolve(sel: str) -> tuple[Optional[MultiDiGraph], Optional[set[str]], str]:
            if sel.startswith("manager:"):
                mid = sel.split(":", 1)[1]
                manager = g.ws.cfg.get_manager(mid)
                if not manager:
                    return None, None, sel
                cached = cache_dir(tenant_id, mid)
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.close()
                try:
                    gen = GraphGenerator(paths=[cached], graph_file=tmp.name,
                                         product_map=g.ws.cfg.product_map(),
                                         source=manager.get("name", mid))
                    gen.build_graph_from_xml()
                finally:
                    try:
                        os.remove(tmp.name)
                    except OSError:
                        ...
                return gen.G, None, manager.get("name", mid)
            node_ids, label = g.ws.selector_nodes(sel)
            if node_ids is None:
                return None, None, sel
            return G(), node_ids, label

        lg, lids, llabel = resolve(left)
        rg, rids, rlabel = resolve(right)
        if lg is None or rg is None:
            return error("Could not resolve one of the selectors", 400)

        if lg is rg:
            result = diff_rule_sets(lg, lids or set(), rids or set(), llabel, rlabel)
        else:
            result = diff_graphs(lg, rg, llabel, rlabel, lids, rids)
        g.ws.cfg.log_activity("compare", f"Compared {llabel} vs {rlabel} — "
                                        f"{len(result['added'])} added, {len(result['removed'])} removed, "
                                        f"{len(result['changed'])} changed")
        return jsonify(result)

    # =====================================================================
    # SPA serving
    # =====================================================================
    @app.route("/")
    @app.route("/<path:path>")
    def spa(path: str = "") -> Union[Response, tuple[Response, int]]:
        if path.startswith("api/"):
            return jsonify({"error": "Not found"}), 404
        if path and os.path.isfile(os.path.join(DIST_DIR, path)):
            return send_from_directory(DIST_DIR, path)
        index = os.path.join(DIST_DIR, "index.html")
        if os.path.isfile(index):
            return send_from_directory(DIST_DIR, "index.html")
        return Response(
            "<h1>RuleVis</h1><p>Frontend build not found. "
            "Run <code>npm run build</code> inside <code>web/</code>.</p>",
            mimetype="text/html")

    return app
