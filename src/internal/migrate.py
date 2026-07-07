"""
One-time migration from the pre-RBAC single-tenant layout to the multi-tenant
layout.

Before: ~/.rulevis/config.json, ~/.rulevis/cache/, ~/.rulevis/uploads/
After:  ~/.rulevis/rulevis.db (users/tenants/roles)
        ~/.rulevis/tenants/default/config.json (same content, moved)
        ~/.rulevis/tenants/default/cache/, .../uploads/ (moved)

Runs synchronously at the very top of create_app(), before any route is
registered — never lazily on first request, which would race under
threaded=True. Idempotency marker is simply "does rulevis.db already exist";
once it does, this is a no-op on every subsequent startup.
"""

import logging
import os
import shutil

from internal import db
from internal.config import app_root, config_dir

DEFAULT_TENANT_ID = "default"


def migrate_if_needed() -> None:
    if db.db_exists():
        return  # already migrated (or a fresh install that already bootstrapped)

    db.init_schema()

    legacy_config = os.path.join(app_root(), "config.json")
    legacy_cache = os.path.join(app_root(), "cache")
    legacy_uploads = os.path.join(app_root(), "uploads")

    if not os.path.isfile(legacy_config):
        logging.info("No legacy config.json found — fresh install, nothing to migrate.")
        return

    logging.info("Legacy single-tenant config.json found — migrating into tenant 'default'.")
    new_dir = config_dir(DEFAULT_TENANT_ID)  # creates ~/.rulevis/tenants/default/

    shutil.move(legacy_config, os.path.join(new_dir, "config.json"))
    if os.path.isdir(legacy_cache):
        shutil.move(legacy_cache, os.path.join(new_dir, "cache"))
    if os.path.isdir(legacy_uploads):
        shutil.move(legacy_uploads, os.path.join(new_dir, "uploads"))

    db.create_tenant("Default", tenant_id=DEFAULT_TENANT_ID)
    logging.info(
        "Migration complete: tenant 'default' now holds your existing products, "
        "managers, GitHub sources and rules. No users exist yet — the app will "
        "prompt to create the first administrator account on next load.")
