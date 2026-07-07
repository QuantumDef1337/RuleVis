"""
Multi-tenant workspace management.

Each tenant gets its own Config (products/managers/paths/case_tags) and its
own Workspace (rule graph + stats/health/heatmaps) — never a single shared
graph with a tenant_id filter. Two independent reasons:

  1. Analyzer/compute_health/heatmap precompute all run once over the whole
     graph and cache their results on Workspace itself. Filtering a shared
     graph per-tenant at query time would mean recomputing those expensive
     aggregates on every request, or maintaining a parallel per-tenant cache
     anyway — at which point you've built this module, just worse.
  2. Wazuh rule IDs are only unique *within* one ruleset. Two tenants' Wazuh
     managers can and will emit colliding node IDs; a single shared graph
     would silently clobber nodes across tenants unless every ID were
     namespaced everywhere (routes, diff, export). Separate graphs sidestep
     this entirely.

Workspaces are built lazily on first access (not eagerly for every tenant at
boot) so one tenant's slow Wazuh manager doesn't block readiness for anyone
else, and are cached until explicitly invalidated (e.g. a tenant's paths
change enough to warrant a full rebuild rather than the existing in-place
ws.rebuild()).
"""

import threading
from typing import TYPE_CHECKING

from internal.config import Config

if TYPE_CHECKING:
    from internal.visualizer import Workspace


class TenantManager:
    def __init__(self, cli_paths: list[str], workspace_factory) -> None:
        """`workspace_factory(cfg, cli_paths) -> Workspace` is injected rather
        than imported directly to avoid a circular import (Workspace lives in
        visualizer.py, which imports this module)."""
        self._cli_paths = [p for p in cli_paths if p]
        self._factory = workspace_factory
        self._workspaces: dict[str, "Workspace"] = {}
        self._lock = threading.Lock()

    def get(self, tenant_id: str) -> "Workspace":
        ws = self._workspaces.get(tenant_id)
        if ws is not None:
            return ws
        with self._lock:
            ws = self._workspaces.get(tenant_id)
            if ws is None:
                cfg = Config(tenant_id)
                # CLI --path rules are a single-tenant/dev convenience and seed
                # only the "default" tenant. Every other tenant is fully isolated
                # and draws rules solely from its own uploads/managers/GitHub
                # sources — a CLI path must never leak across tenants.
                cli_paths = self._cli_paths if tenant_id == "default" else []
                ws = self._factory(cfg, cli_paths)
                ws.rebuild()
                self._workspaces[tenant_id] = ws
            return ws

    def invalidate(self, tenant_id: str) -> None:
        with self._lock:
            self._workspaces.pop(tenant_id, None)

    def loaded_tenant_ids(self) -> list[str]:
        return list(self._workspaces.keys())
