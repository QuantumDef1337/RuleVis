from internal import db
from internal.authz import Permission, role_has_permission


def test_login_by_email_is_case_insensitive():
    db.init_schema()
    u = db.create_user("alice@example.com", "correct-horse-battery-1", "Alice")
    assert db.verify_login("alice@example.com", "correct-horse-battery-1")["id"] == u["id"]
    assert db.verify_login("Alice@Example.com", "correct-horse-battery-1")["id"] == u["id"]
    assert db.verify_login("alice@example.com", "wrong-password") is None


def test_login_by_username_when_email_is_optional():
    db.init_schema()
    u = db.create_user("", "another-strong-pass-1", "Bob", username="bobby")
    # No real email given -> a synthesized placeholder is stored, never a blank string.
    assert u["email"].endswith("@users.rulevis.local")
    assert db.verify_login("bobby", "another-strong-pass-1")["id"] == u["id"]
    # username lookups are explicitly case-insensitive (LOWER() on both sides).
    assert db.verify_login("BOBBY", "another-strong-pass-1")["id"] == u["id"]
    assert db.verify_login("bobby", "wrong-password") is None


def test_duplicate_username_is_rejected_at_the_db_layer():
    db.init_schema()
    db.create_user("", "some-strong-password-1", "First", username="dupe")
    # The unique index is partial (WHERE username IS NOT NULL) — enforced by the DB.
    from sqlalchemy.exc import IntegrityError
    try:
        db.create_user("", "some-strong-password-2", "Second", username="dupe")
        assert False, "expected a uniqueness violation"
    except IntegrityError:
        pass


def test_role_permissions_are_scoped_correctly():
    assert role_has_permission("viewer", Permission.VIEW_RULES) is True
    assert role_has_permission("viewer", Permission.EXPORT) is False
    assert role_has_permission("analyst", Permission.EXPORT) is True
    assert role_has_permission("analyst", Permission.MANAGE_TENANT_USERS) is False
    assert role_has_permission("tenant_admin", Permission.MANAGE_TENANT_USERS) is True


def test_permission_overrides_grant_extra_access_without_changing_role():
    # A viewer normally can't export — an override should be the only thing
    # that changes that, not a role bump.
    assert role_has_permission("viewer", Permission.EXPORT) is False
    assert role_has_permission("viewer", Permission.EXPORT, overrides=["export"]) is True
    # The override is additive, not a full grant — unrelated permissions stay denied.
    assert role_has_permission("viewer", Permission.MANAGE_TENANT_USERS, overrides=["export"]) is False
