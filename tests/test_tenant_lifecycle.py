import os

from internal import config, db


def test_delete_tenant_dir_removes_config_cache_and_uploads():
    db.init_schema()
    t = db.create_tenant("Cleanup Test")
    tenant_id = t["id"]

    # Simulate a tenant that has actually been used: config file + a cached
    # manager download + an uploaded rule file.
    cfg_dir = config.config_dir(tenant_id)
    with open(os.path.join(cfg_dir, "config.json"), "w", encoding="utf-8") as f:
        f.write("{}")
    cache_subdir = config.cache_dir(tenant_id, "some-manager")
    with open(os.path.join(cache_subdir, "rules.xml"), "w", encoding="utf-8") as f:
        f.write("<group></group>")
    uploads_subdir = config.uploads_dir(tenant_id)
    with open(os.path.join(uploads_subdir, "uploaded.xml"), "w", encoding="utf-8") as f:
        f.write("<group></group>")

    tenant_root = os.path.join(config.tenants_root(), tenant_id)
    assert os.path.isdir(tenant_root)

    assert db.delete_tenant(tenant_id) is True
    # Deleting the DB row alone must not be enough to call this "cleaned up" —
    # the on-disk directory has to actually be gone too.
    config.delete_tenant_dir(tenant_id)
    assert not os.path.isdir(tenant_root)


def test_delete_tenant_dir_is_a_no_op_when_nothing_exists():
    # Should never raise, even if the tenant never wrote anything to disk.
    config.delete_tenant_dir("never-existed")
