"""
TOTP (RFC 6238) two-factor authentication — stdlib only, no `pyotp` dependency.

A TOTP code is just an HOTP (RFC 4226) code where the counter is the current
Unix time divided into 30-second steps: HMAC-SHA1(secret, step) truncated to
a 6-digit code. Verifying allows the previous/next step too, to tolerate
clock drift between server and authenticator app.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Final

DIGITS: Final[int] = 6
STEP_SECONDS: Final[int] = 30


def generate_secret() -> str:
    """Base32 secret, compatible with any standard authenticator app."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def current_code(secret_b32: str, at: float | None = None) -> str:
    counter = int((at if at is not None else time.time()) // STEP_SECONDS)
    return _hotp(secret_b32, counter)


def verify_code(secret_b32: str, code: str, window: int = 1) -> bool:
    """Accepts the code for the current step and `window` steps on either
    side, to tolerate modest clock drift."""
    code = code.strip()
    if not code.isdigit():
        return False
    counter = int(time.time() // STEP_SECONDS)
    return any(hmac.compare_digest(_hotp(secret_b32, counter + delta), code)
               for delta in range(-window, window + 1))


def provisioning_uri(secret_b32: str, email: str, issuer: str = "RuleVis") -> str:
    """otpauth:// URI most authenticator apps can render as a QR code."""
    import urllib.parse
    label = urllib.parse.quote(f"{issuer}:{email}")
    params = urllib.parse.urlencode({"secret": secret_b32, "issuer": issuer, "digits": DIGITS})
    return f"otpauth://totp/{label}?{params}"


def generate_backup_codes(count: int = 10) -> list[str]:
    """Human-typeable one-time-use recovery codes, e.g. 'a1b2-c3d4'."""
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(count)]
