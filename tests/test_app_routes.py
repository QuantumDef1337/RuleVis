import os

import pytest

from internal.visualizer import create_app


@pytest.fixture
def client():
    app = create_app([])
    return app.test_client()


def _bootstrap(client):
    return client.post("/api/auth/bootstrap", json={
        "email": "admin@test.local", "password": "supersecretpassword123", "display_name": "Admin",
    })


def test_default_tenant_cannot_be_deleted(client):
    _bootstrap(client)
    r = client.delete("/api/super/tenants/default")
    assert r.status_code == 400
    assert "default" in r.get_json()["error"].lower()


def test_deleting_a_tenant_removes_its_on_disk_directory(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Throwaway"})
    tid = r.get_json()["id"]

    from internal import config
    tenant_dir = os.path.join(config.tenants_root(), tid)
    os.makedirs(tenant_dir, exist_ok=True)
    with open(os.path.join(tenant_dir, "config.json"), "w", encoding="utf-8") as f:
        f.write("{}")
    assert os.path.isdir(tenant_dir)

    r = client.delete(f"/api/super/tenants/{tid}")
    assert r.get_json()["deleted"] is True
    assert not os.path.isdir(tenant_dir)


def test_login_ip_rate_limit_returns_429_after_repeated_failures(client):
    _bootstrap(client)
    # No manual reset needed — the fixture's isolated_app_dir gives each test
    # its own database, so login_ip_failures starts empty every time.
    last = None
    for _ in range(21):
        last = client.post(
            "/api/auth/login", json={"email": "nouser@example.com", "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": "198.51.100.7"})
    assert last.status_code == 429
