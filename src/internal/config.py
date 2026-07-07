"""
Persistent per-tenant configuration for RuleVis.

Stores product->file mappings, Wazuh manager connections, rule paths and UI
preferences in a per-tenant JSON file at
~/.rulevis/tenants/<tenant_id>/config.json.

Fetched manager rulesets are cached under
~/.rulevis/tenants/<tenant_id>/cache/<manager_id>/.

Identity/authorization (users, tenants, roles) lives separately in the
SQLite database managed by db.py — this module only ever handles the
per-tenant rule-workspace settings, unchanged in shape from the pre-RBAC,
single-tenant version of RuleVis (only the on-disk location moved).
"""

import json
import logging
import os
import shutil
import threading
import time
import uuid
from typing import Any, Final, Optional

from internal import crypto

APP_NAME: Final[str] = "rulevis"
ENCODING: Final[str] = "utf-8"

_LOCK = threading.Lock()

DEFAULT_CONFIG: Final[dict[str, Any]] = {
    "version": 1,
    "paths": [],          # local rule directories
    "products": [],       # [{id, name, icon, description, files: [basename,...]}]
    "managers": [],       # [{id, name, url, username, password, verify_tls}]
    "github_sources": [], # [{id, name, repo, branch, path, token, include}]
    "webhooks": [],        # [{id, name, url, format, events: [...], secret, enabled}]
    # Per-tenant OIDC SSO — each customer can bring their own IdP.
    "sso": {"enabled": False, "issuer": "", "client_id": "", "client_secret": "",
            "auto_provision_role": "viewer"},
    "ui": {"theme": "dark"},
    "activity": [],       # [{ts, kind, detail}] — most recent first, capped
    # Group names that mark a rule (or one of its ancestors) as a
    # production/case-managed rule — user-defined in Settings.
    "case_tags": ["soar-alert", "case"],
}

ACTIVITY_CAP: Final[int] = 30


def app_root() -> str:
    # A dotdir in the user's home on every platform. Deliberately NOT
    # %LocalAppData% on Windows: Microsoft Store Python silently virtualizes
    # AppData writes into its package sandbox, which makes the config file
    # appear and disappear depending on how the process is launched.
    d = os.path.join(os.path.expanduser("~"), f".{APP_NAME}")
    os.makedirs(d, exist_ok=True)
    return d


def tenants_root() -> str:
    d = os.path.join(app_root(), "tenants")
    os.makedirs(d, exist_ok=True)
    return d


def delete_tenant_dir(tenant_id: str) -> None:
    """Removes a tenant's entire on-disk directory (config.json, cache/,
    uploads/). Deleting a tenant's DB row alone leaves this behind forever —
    call this right after the DB row is removed so nothing is orphaned."""
    d = os.path.join(tenants_root(), tenant_id)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)


def config_dir(tenant_id: str) -> str:
    d = os.path.join(tenants_root(), tenant_id)
    os.makedirs(d, exist_ok=True)
    return d


def config_path(tenant_id: str) -> str:
    return os.path.join(config_dir(tenant_id), "config.json")


def cache_dir(tenant_id: str, manager_id: Optional[str] = None) -> str:
    d = os.path.join(config_dir(tenant_id), "cache")
    if manager_id:
        d = os.path.join(d, manager_id)
    os.makedirs(d, exist_ok=True)
    return d


def uploads_dir(tenant_id: str) -> str:
    d = os.path.join(config_dir(tenant_id), "uploads")
    os.makedirs(d, exist_ok=True)
    return d


class Config:
    """Thread-safe wrapper around one tenant's JSON config file."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._data: dict[str, Any] = self._load()

    # ---------- persistence ----------
    def _load(self) -> dict[str, Any]:
        path = config_path(self.tenant_id)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding=ENCODING) as f:
                    data = json.load(f)
                merged = {**DEFAULT_CONFIG, **data}
                return merged
            except (json.JSONDecodeError, OSError) as e:
                logging.error(f"Config file corrupted, using defaults: {e}")
        return json.loads(json.dumps(DEFAULT_CONFIG))

    def save(self) -> None:
        with _LOCK:
            path = config_path(self.tenant_id)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding=ENCODING) as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp, path)

    # ---------- generic access ----------
    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def update(self, patch: dict[str, Any]) -> dict[str, Any]:
        """Shallow-merge a patch of top-level keys (paths, products, managers,
        github_sources, ui, case_tags)."""
        for key in ("paths", "products", "managers", "github_sources", "ui", "case_tags"):
            if key in patch:
                self._data[key] = patch[key]
        self.save()
        return self._data

    # ---------- case / production tags ----------
    @property
    def case_tags(self) -> list[str]:
        return list(self._data.get("case_tags", []))

    def set_case_tags(self, tags: list[str]) -> None:
        self._data["case_tags"] = [t.strip() for t in tags if t.strip()]
        self.save()

    # ---------- paths ----------
    @property
    def paths(self) -> list[str]:
        return list(self._data.get("paths", []))

    def set_paths(self, paths: list[str]) -> None:
        self._data["paths"] = [p for p in paths if p.strip()]
        self.save()

    # ---------- products ----------
    @property
    def products(self) -> list[dict[str, Any]]:
        return list(self._data.get("products", []))

    def product_map(self) -> dict[str, str]:
        """lowercase file basename -> product name."""
        mapping: dict[str, str] = {}
        for product in self._data.get("products", []):
            for fn in product.get("files", []):
                mapping[str(fn).lower()] = product["name"]
        return mapping

    def upsert_product(self, product: dict[str, Any]) -> dict[str, Any]:
        products = self._data.setdefault("products", [])
        pid = product.get("id") or str(uuid.uuid4())[:8]
        product["id"] = pid
        product.setdefault("files", [])
        for i, existing in enumerate(products):
            if existing.get("id") == pid:
                products[i] = {**existing, **product}
                self.save()
                return products[i]
        products.append(product)
        self.save()
        return product

    def delete_product(self, product_id: str) -> bool:
        products = self._data.get("products", [])
        before = len(products)
        self._data["products"] = [p for p in products if p.get("id") != product_id]
        self.save()
        return len(self._data["products"]) < before

    # ---------- managers ----------
    @property
    def managers(self) -> list[dict[str, Any]]:
        return list(self._data.get("managers", []))

    def get_manager(self, manager_id: str) -> Optional[dict[str, Any]]:
        for m in self._data.get("managers", []):
            if m.get("id") == manager_id:
                return m
        return None

    def upsert_manager(self, manager: dict[str, Any]) -> dict[str, Any]:
        managers = self._data.setdefault("managers", [])
        mid = manager.get("id") or str(uuid.uuid4())[:8]
        manager["id"] = mid
        manager.setdefault("verify_tls", False)
        for i, existing in enumerate(managers):
            if existing.get("id") == mid:
                # keep stored (already-encrypted) password when the client
                # sends a blank one; otherwise encrypt the new plaintext
                # value before it ever touches disk.
                if not manager.get("password"):
                    manager["password"] = existing.get("password", "")
                else:
                    manager["password"] = crypto.encrypt(manager["password"])
                managers[i] = {**existing, **manager}
                self.save()
                return managers[i]
        if manager.get("password"):
            manager["password"] = crypto.encrypt(manager["password"])
        managers.append(manager)
        self.save()
        return manager

    def delete_manager(self, manager_id: str) -> bool:
        managers = self._data.get("managers", [])
        before = len(managers)
        self._data["managers"] = [m for m in managers if m.get("id") != manager_id]
        self.save()
        return len(self._data["managers"]) < before

    # ---------- github sources ----------
    @property
    def github_sources(self) -> list[dict[str, Any]]:
        return list(self._data.get("github_sources", []))

    def get_github_source(self, source_id: str) -> Optional[dict[str, Any]]:
        for s in self._data.get("github_sources", []):
            if s.get("id") == source_id:
                return s
        return None

    def upsert_github_source(self, source: dict[str, Any]) -> dict[str, Any]:
        sources = self._data.setdefault("github_sources", [])
        sid = source.get("id") or str(uuid.uuid4())[:8]
        source["id"] = sid
        for i, existing in enumerate(sources):
            if existing.get("id") == sid:
                # keep stored (already-encrypted) token when the client
                # sends a blank one; otherwise encrypt the new plaintext
                # value before it ever touches disk.
                if not source.get("token"):
                    source["token"] = existing.get("token", "")
                else:
                    source["token"] = crypto.encrypt(source["token"])
                sources[i] = {**existing, **source}
                self.save()
                return sources[i]
        if source.get("token"):
            source["token"] = crypto.encrypt(source["token"])
        sources.append(source)
        self.save()
        return source

    def delete_github_source(self, source_id: str) -> bool:
        sources = self._data.get("github_sources", [])
        before = len(sources)
        self._data["github_sources"] = [s for s in sources if s.get("id") != source_id]
        self.save()
        return len(self._data["github_sources"]) < before

    # ---------- webhooks ----------
    @property
    def webhooks(self) -> list[dict[str, Any]]:
        return list(self._data.get("webhooks", []))

    def get_webhook(self, webhook_id: str) -> Optional[dict[str, Any]]:
        for w in self._data.get("webhooks", []):
            if w.get("id") == webhook_id:
                return w
        return None

    def upsert_webhook(self, webhook: dict[str, Any]) -> dict[str, Any]:
        webhooks = self._data.setdefault("webhooks", [])
        wid = webhook.get("id") or str(uuid.uuid4())[:8]
        webhook["id"] = wid
        webhook.setdefault("format", "generic")
        webhook.setdefault("events", [])
        webhook.setdefault("enabled", True)
        for i, existing in enumerate(webhooks):
            if existing.get("id") == wid:
                # keep stored (already-encrypted) secret when the client
                # sends a blank one; otherwise encrypt the new value.
                if not webhook.get("secret"):
                    webhook["secret"] = existing.get("secret", "")
                else:
                    webhook["secret"] = crypto.encrypt(webhook["secret"])
                webhooks[i] = {**existing, **webhook}
                self.save()
                return webhooks[i]
        if webhook.get("secret"):
            webhook["secret"] = crypto.encrypt(webhook["secret"])
        webhooks.append(webhook)
        self.save()
        return webhook

    def delete_webhook(self, webhook_id: str) -> bool:
        webhooks = self._data.get("webhooks", [])
        before = len(webhooks)
        self._data["webhooks"] = [w for w in webhooks if w.get("id") != webhook_id]
        self.save()
        return len(self._data["webhooks"]) < before

    # ---------- SSO (OIDC) ----------
    @property
    def sso(self) -> dict[str, Any]:
        return dict(self._data.get("sso", DEFAULT_CONFIG["sso"]))

    def set_sso_config(self, patch: dict[str, Any]) -> dict[str, Any]:
        current = self._data.setdefault("sso", dict(DEFAULT_CONFIG["sso"]))
        # keep stored (already-encrypted) secret when the client sends a
        # blank one; otherwise encrypt the new plaintext value.
        if not patch.get("client_secret"):
            patch.pop("client_secret", None)
        else:
            patch["client_secret"] = crypto.encrypt(patch["client_secret"])
        current.update(patch)
        self.save()
        return dict(current)

    # ---------- ui ----------
    @property
    def ui(self) -> dict[str, Any]:
        return dict(self._data.get("ui", {}))

    def set_ui(self, ui: dict[str, Any]) -> None:
        self._data["ui"] = {**self._data.get("ui", {}), **ui}
        self.save()

    # ---------- activity ----------
    @property
    def activity(self) -> list[dict[str, Any]]:
        return list(self._data.get("activity", []))

    def log_activity(self, kind: str, detail: str) -> None:
        """kind: import | compare | export | fetch"""
        entries = self._data.setdefault("activity", [])
        entries.insert(0, {"ts": time.time(), "kind": kind, "detail": detail})
        del entries[ACTIVITY_CAP:]
        self.save()


def redact_manager(manager: dict[str, Any]) -> dict[str, Any]:
    """Never send passwords to the frontend."""
    out = dict(manager)
    if out.get("password"):
        out["password"] = ""
        out["has_password"] = True
    return out


def redact_github_source(source: dict[str, Any]) -> dict[str, Any]:
    """Never send access tokens to the frontend."""
    out = dict(source)
    if out.get("token"):
        out["token"] = ""
        out["has_token"] = True
    return out


def redact_webhook(webhook: dict[str, Any]) -> dict[str, Any]:
    """Never send signing secrets to the frontend."""
    out = dict(webhook)
    if out.get("secret"):
        out["secret"] = ""
        out["has_secret"] = True
    return out


def redact_sso_config(sso: dict[str, Any]) -> dict[str, Any]:
    """Never send the OIDC client secret to the frontend."""
    out = dict(sso)
    if out.get("client_secret"):
        out["client_secret"] = ""
        out["has_client_secret"] = True
    return out
