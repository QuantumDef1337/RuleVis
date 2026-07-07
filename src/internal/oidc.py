"""
OpenID Connect (Authorization Code flow) SSO client.

Each tenant can configure its own IdP (Okta, Azure AD / Entra ID, Google
Workspace, Auth0, Keycloak, or anything else that speaks standard OIDC) —
see Config.get_sso_config()/set_sso_config(). This is what actually gets an
enterprise buyer to say yes: most won't adopt a tool that only supports
local email+password, no matter how solid the RBAC underneath it is.

Deliberately does NOT implement SAML — that's a separate, much larger
undertaking (XML signing/parsing, metadata exchange, an ACS endpoint) that
deserves its own dedicated effort. OIDC covers the same enterprise IdPs
(Okta/Azure AD/Google all speak both), with a much smaller, JSON-based
protocol surface.

Signature verification of the IdP's ID token uses `python-jose` (a vetted
library) against the IdP's published JWKS — this is exactly the kind of
cryptographic code that should never be hand-rolled.
"""

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from jose import jwt as jose_jwt
from jose.exceptions import JOSEError

TIMEOUT_SECONDS = 10


class OidcError(Exception):
    ...


def _get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError) as e:
        raise OidcError(f"Cannot reach identity provider: {e}") from e


def discover(issuer: str) -> dict[str, Any]:
    """Fetches the IdP's /.well-known/openid-configuration document —
    everything else (authorize/token/jwks endpoints) is derived from it, so
    a tenant admin only ever has to type in the issuer URL."""
    return _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")


def new_state() -> str:
    return secrets.token_urlsafe(24)


def build_authorize_url(discovery: dict[str, Any], client_id: str, redirect_uri: str, state: str) -> str:
    params = {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": "openid email profile", "state": state,
    }
    return f"{discovery['authorization_endpoint']}?{urllib.parse.urlencode(params)}"


def exchange_code(discovery: dict[str, Any], client_id: str, client_secret: str,
                  code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchanges an authorization code for tokens at the IdP's token endpoint."""
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": client_id, "client_secret": client_secret,
    }).encode("utf-8")
    req = urllib.request.Request(
        discovery["token_endpoint"], data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise OidcError(f"Token exchange failed: HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:300]}") from e
    except (urllib.error.URLError, OSError) as e:
        raise OidcError(f"Cannot reach identity provider token endpoint: {e}") from e


def verify_id_token(id_token: str, discovery: dict[str, Any], client_id: str, issuer: str) -> dict[str, Any]:
    """Verifies the ID token's signature against the IdP's published JWKS and
    standard claims (issuer, audience, expiry) — returns the decoded claims
    (sub, email, name, ...) only if everything checks out."""
    jwks = _get_json(discovery["jwks_uri"])
    try:
        return jose_jwt.decode(id_token, jwks, algorithms=["RS256"], audience=client_id, issuer=issuer)
    except JOSEError as e:
        raise OidcError(f"ID token verification failed: {e}") from e


def login_via_sso(sso_cfg: dict[str, Any], redirect_uri: str, state: str) -> str:
    """Returns the URL to redirect the browser to, to start the SSO flow."""
    discovery = discover(sso_cfg["issuer"])
    return build_authorize_url(discovery, sso_cfg["client_id"], redirect_uri, state)


def complete_sso(sso_cfg: dict[str, Any], client_secret: str, code: str,
                 redirect_uri: str) -> dict[str, Any]:
    """Runs the callback half of the flow: exchanges the code, verifies the
    ID token, and returns its claims (at minimum: sub, email)."""
    discovery = discover(sso_cfg["issuer"])
    tokens = exchange_code(discovery, sso_cfg["client_id"], client_secret, code, redirect_uri)
    id_token = tokens.get("id_token")
    if not id_token:
        raise OidcError("Identity provider did not return an id_token")
    claims = verify_id_token(id_token, discovery, sso_cfg["client_id"], sso_cfg["issuer"])
    if not claims.get("email"):
        raise OidcError("Identity provider did not include an 'email' claim")
    return claims
