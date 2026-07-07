import pytest

from internal import db
from internal.visualizer import create_app


@pytest.fixture
def client():
    app = create_app([])
    return app.test_client()


def _bootstrap(client):
    return client.post("/api/auth/bootstrap", json={
        "email": "admin@test.local", "password": "supersecretpassword123", "display_name": "Admin",
    })


def test_create_and_verify_api_key_roundtrip():
    db.init_schema()
    t = db.create_tenant("Acme")
    created = db.create_api_key(t["id"], "CI pipeline", "analyst")
    assert created["raw_key"].startswith("rvk_")

    verified = db.verify_api_key(created["raw_key"])
    assert verified is not None
    assert verified["tenant_id"] == t["id"]
    assert verified["role"] == "analyst"


def test_revoked_api_key_no_longer_verifies():
    db.init_schema()
    t = db.create_tenant("Acme")
    created = db.create_api_key(t["id"], "old key", "viewer")
    assert db.verify_api_key(created["raw_key"]) is not None

    assert db.revoke_api_key(t["id"], created["id"]) is True
    assert db.verify_api_key(created["raw_key"]) is None


def test_unknown_api_key_does_not_verify():
    db.init_schema()
    assert db.verify_api_key("rvk_not-a-real-key") is None


def test_api_key_grants_scoped_tenant_access_over_http(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]

    r = client.post(f"/api/t/{tenant_id}/api-keys", json={"name": "CI key", "role": "analyst"})
    raw_key = r.get_json()["raw_key"]

    # Without any session cookie at all — this is the whole point of an API key.
    client.delete_cookie("session")
    headers = {"Authorization": f"Bearer {raw_key}"}
    r = client.get(f"/api/t/{tenant_id}/overview", headers=headers)
    assert r.status_code == 200


def test_api_key_cannot_access_a_different_tenant(client):
    _bootstrap(client)
    r1 = client.post("/api/super/tenants", json={"name": "Tenant One"})
    tenant_one = r1.get_json()["id"]
    r2 = client.post("/api/super/tenants", json={"name": "Tenant Two"})
    tenant_two = r2.get_json()["id"]

    r = client.post(f"/api/t/{tenant_one}/api-keys", json={"name": "scoped key", "role": "viewer"})
    raw_key = r.get_json()["raw_key"]

    client.delete_cookie("session")
    headers = {"Authorization": f"Bearer {raw_key}"}
    r = client.get(f"/api/t/{tenant_two}/overview", headers=headers)
    assert r.status_code == 403


def test_api_key_cannot_reach_super_admin_routes(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]
    r = client.post(f"/api/t/{tenant_id}/api-keys", json={"name": "key", "role": "tenant_admin"})
    raw_key = r.get_json()["raw_key"]

    client.delete_cookie("session")
    headers = {"Authorization": f"Bearer {raw_key}"}
    r = client.get("/api/super/tenants", headers=headers)
    assert r.status_code == 403


def test_viewer_role_api_key_cannot_manage_settings(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]
    r = client.post(f"/api/t/{tenant_id}/api-keys", json={"name": "read-only key", "role": "viewer"})
    raw_key = r.get_json()["raw_key"]

    client.delete_cookie("session")
    headers = {"Authorization": f"Bearer {raw_key}"}
    r = client.get(f"/api/t/{tenant_id}/overview", headers=headers)
    assert r.status_code == 200  # view_rules — allowed for viewer
    r = client.post(f"/api/t/{tenant_id}/managers", json={"url": "https://x:55000"}, headers=headers)
    assert r.status_code == 403  # manage_tenant_settings — not allowed for viewer
