"""
Role-based access control.

super_admin is a platform-wide flag on the user row (db.py: users.is_super_admin)
and bypasses per-tenant role lookups entirely. Every other role is scoped to a
specific tenant via user_tenant_roles — the same user can be tenant_admin in one
tenant and viewer in another.
"""

from enum import Enum
from functools import wraps
from typing import Any, Callable

from flask import g, jsonify

from internal import db


class Role(str, Enum):
    TENANT_ADMIN = "tenant_admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    # super_admin deliberately excluded — it's a platform flag, not a tenant role


class Permission(str, Enum):
    VIEW_RULES = "view_rules"
    EXPORT = "export"
    MANAGE_TENANT_SETTINGS = "manage_tenant_settings"
    MANAGE_TENANT_USERS = "manage_tenant_users"
    VIEW_ACTIVITY = "view_activity"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.TENANT_ADMIN: {
        Permission.VIEW_RULES, Permission.EXPORT,
        Permission.MANAGE_TENANT_SETTINGS, Permission.MANAGE_TENANT_USERS,
        Permission.VIEW_ACTIVITY,
    },
    Role.ANALYST: {Permission.VIEW_RULES, Permission.EXPORT},
    Role.VIEWER: {Permission.VIEW_RULES},
}


def _error(message: str, code: int):
    return jsonify({"error": message}), code


def role_has_permission(role: str, perm: Permission, overrides: list[str] = ()) -> bool:  # type: ignore[assignment]
    if perm.value in overrides:
        return True
    try:
        return perm in ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return False


def require_permission(perm: Permission) -> Callable:
    """Route decorator: the current caller must be super_admin, hold a role
    (optionally with per-user permission overrides) in g.tenant_id that
    grants `perm`, or present an API key (g.api_key_role) whose role grants
    it. Must run after the before_request hook that sets g.user / g.tenant_id
    / g.api_key_role."""
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapped(*args: Any, **kwargs: Any):
            user = getattr(g, "user", None)
            if user is None:
                return _error("Not authenticated", 401)
            api_key_role = getattr(g, "api_key_role", None)
            if api_key_role is not None:
                if not role_has_permission(api_key_role, perm):
                    return _error("Forbidden", 403)
                g.role = api_key_role
                return fn(*args, **kwargs)
            if user["is_super_admin"]:
                return fn(*args, **kwargs)
            tenant_id = kwargs.get("tenant_id") or getattr(g, "tenant_id", None)
            if not tenant_id:
                return _error("No tenant context", 400)
            access = db.get_user_tenant_access(user["id"], tenant_id)
            if access is None or not role_has_permission(access["role"], perm, access["permission_overrides"]):
                return _error("Forbidden", 403)
            g.role = access["role"]
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def require_super_admin(fn: Callable) -> Callable:
    """Route decorator for platform-only routes (cross-tenant admin)."""
    @wraps(fn)
    def wrapped(*args: Any, **kwargs: Any):
        user = getattr(g, "user", None)
        if user is None:
            return _error("Not authenticated", 401)
        if not user["is_super_admin"]:
            return _error("Forbidden", 403)
        return fn(*args, **kwargs)
    return wrapped


def require_login(fn: Callable) -> Callable:
    """Route decorator for routes with no tenant scoping that still need a
    logged-in user (e.g. /api/auth/me)."""
    @wraps(fn)
    def wrapped(*args: Any, **kwargs: Any):
        if getattr(g, "user", None) is None:
            return _error("Not authenticated", 401)
        return fn(*args, **kwargs)
    return wrapped
