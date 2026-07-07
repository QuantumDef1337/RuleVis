"""
Encrypts secrets (Wazuh manager passwords, GitHub tokens) before they're
written to a tenant's config.json on disk.

Previously these were stored as plain text — the single biggest security gap
found in a review of this codebase: anyone with read access to
~/.rulevis/tenants/<id>/config.json (a backup, a misconfigured file share, a
compromised host) got every connected Wazuh manager's credentials and every
GitHub token for free.

Uses Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography` package),
keyed by a value derived from the app's existing persisted secret_key
(db.secret_key()) — there's no separate key to generate, rotate, or lose.

Backward compatible with existing plaintext values: decrypt() falls back to
returning the input unchanged if it doesn't look like a valid Fernet token
(InvalidToken), so upgrading doesn't break already-configured managers/
GitHub sources. They're transparently re-encrypted the next time they're
saved through the Settings UI (config.py encrypts on every upsert).
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from internal import db


def _fernet() -> Fernet:
    key = hashlib.sha256(db.secret_key().encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(plaintext: str) -> str:
    """Empty strings pass through unchanged — an empty password/token means
    'not set', not a secret worth encrypting."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        # Pre-encryption plaintext value from before this feature existed.
        return value
