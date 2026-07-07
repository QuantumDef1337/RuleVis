import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt as jose_jwt
from jose.utils import long_to_base64

from internal import db
from internal.config import Config
from internal.visualizer import create_app

KID = "test-key-1"


def _rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def _mock_idp(private_key, public_key):
    """A tiny local OpenID Provider: real discovery doc, real JWKS, and a
    real RS256-signed ID token — so verify_id_token() is exercised against
    actual cryptographic signature verification, not a stub."""

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, obj, status=200):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            base = f"http://{self.headers['Host']}"
            if self.path == "/.well-known/openid-configuration":
                self._send_json({
                    "issuer": base,
                    "authorization_endpoint": f"{base}/authorize",
                    "token_endpoint": f"{base}/token",
                    "jwks_uri": f"{base}/jwks",
                })
            elif self.path == "/jwks":
                pub = public_key.public_numbers()
                jwk_entry = {
                    "kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
                    "n": long_to_base64(pub.n).decode("ascii"),
                    "e": long_to_base64(pub.e).decode("ascii"),
                }
                self._send_json({"keys": [jwk_entry]})
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == "/token":
                length = int(self.headers.get("Content-Length", 0))
                body = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
                base = f"http://{self.headers['Host']}"
                claims = {
                    "iss": base, "aud": body["client_id"][0], "sub": "user-123",
                    "email": "sso-user@acme-corp.example", "name": "SSO User",
                    "iat": int(time.time()), "exp": int(time.time()) + 300,
                }
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption())
                id_token = jose_jwt.encode(claims, pem, algorithm="RS256", headers={"kid": KID})
                self._send_json({"access_token": "mock-access-token", "id_token": id_token, "token_type": "Bearer"})
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def client():
    app = create_app([])
    return app.test_client()


def _bootstrap(client):
    return client.post("/api/auth/bootstrap", json={
        "email": "admin@test.local", "password": "supersecretpassword123", "display_name": "Admin",
    })


def test_sso_login_redirects_to_idp_authorize_endpoint(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]

    priv, pub = _rsa_keypair()
    idp = _mock_idp(priv, pub)
    try:
        issuer = f"http://127.0.0.1:{idp.server_port}"
        client.put(f"/api/t/{tenant_id}/sso-config", json={
            "enabled": True, "issuer": issuer, "client_id": "rulevis-client", "client_secret": "shh",
        })
        r = client.get(f"/api/auth/sso/{tenant_id}/login")
        assert r.status_code == 302
        assert r.location.startswith(f"{issuer}/authorize")
        assert "client_id=rulevis-client" in r.location
    finally:
        idp.shutdown()


def test_sso_disabled_returns_404(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]
    r = client.get(f"/api/auth/sso/{tenant_id}/login")
    assert r.status_code == 404


def test_sso_callback_completes_login_and_provisions_a_new_user(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]

    priv, pub = _rsa_keypair()
    idp = _mock_idp(priv, pub)
    try:
        issuer = f"http://127.0.0.1:{idp.server_port}"
        client.put(f"/api/t/{tenant_id}/sso-config", json={
            "enabled": True, "issuer": issuer, "client_id": "rulevis-client", "client_secret": "shh",
            "auto_provision_role": "analyst",
        })

        # Kick off the flow (sets session state), then simulate the IdP
        # redirecting back with a code, matching the state we were given.
        login_resp = client.get(f"/api/auth/sso/{tenant_id}/login")
        state = urllib.parse.parse_qs(urllib.parse.urlparse(login_resp.location).query)["state"][0]

        r = client.get(f"/api/auth/sso/{tenant_id}/callback?code=mock-code&state={state}")
        assert r.status_code == 302
        assert r.location == f"/t/{tenant_id}"

        user = db.get_user_by_email("sso-user@acme-corp.example")
        assert user is not None
        access = db.get_user_tenant_access(user["id"], tenant_id)
        assert access == {"role": "analyst", "permission_overrides": []}

        # The session cookie set by the callback should now be authenticated.
        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.get_json()["user"]["email"] == "sso-user@acme-corp.example"
    finally:
        idp.shutdown()


def test_sso_callback_rejects_mismatched_state(client):
    _bootstrap(client)
    r = client.post("/api/super/tenants", json={"name": "Acme"})
    tenant_id = r.get_json()["id"]
    priv, pub = _rsa_keypair()
    idp = _mock_idp(priv, pub)
    try:
        issuer = f"http://127.0.0.1:{idp.server_port}"
        client.put(f"/api/t/{tenant_id}/sso-config", json={
            "enabled": True, "issuer": issuer, "client_id": "rulevis-client", "client_secret": "shh",
        })
        client.get(f"/api/auth/sso/{tenant_id}/login")
        r = client.get(f"/api/auth/sso/{tenant_id}/callback?code=mock-code&state=wrong-state")
        assert r.status_code == 400
    finally:
        idp.shutdown()


def test_sso_client_secret_is_encrypted_at_rest():
    db.init_schema()
    cfg = Config("tenant-sso-test")
    saved = cfg.set_sso_config({"enabled": True, "issuer": "https://idp.example",
                                "client_id": "abc", "client_secret": "super-secret-oidc"})
    assert saved["client_secret"] != "super-secret-oidc"
    from internal import crypto
    assert crypto.decrypt(saved["client_secret"]) == "super-secret-oidc"
