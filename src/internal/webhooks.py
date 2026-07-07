"""
Outbound webhooks: push rule-change events (manager/GitHub syncs, deletions)
to Slack, Microsoft Teams, or a generic JSON endpoint (ServiceNow, Jira,
n8n/Zapier, or a customer's own listener) — so a customer doesn't have to sit
in the Audit Log tab to notice something changed.

Each tenant can configure any number of webhooks (see Config.upsert_webhook),
each subscribed to a subset of event types. Every payload is HMAC-SHA256
signed (when a per-webhook secret is set) via an X-RuleVis-Signature header,
the same pattern GitHub/Stripe use, so a receiver can verify the request
actually came from this RuleVis instance and not a spoofed source.

Dispatch is fire-and-forget from a background thread (see
visualizer.py:_log_audit) — a slow or dead webhook endpoint must never slow
down or fail the request that triggered the event.
"""

import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from internal import crypto
from internal.config import Config

TIMEOUT_SECONDS = 8

# Events a webhook can subscribe to. Kept to the things a SOC manager
# actually wants pushed — rule-affecting changes and deletions — rather than
# every single audit action (routine logins, settings tweaks, etc).
WEBHOOK_EVENTS = (
    "sync_manager", "sync_manager_failed", "sync_manager_skipped",
    "sync_github_source", "sync_github_source_failed", "sync_github_source_skipped",
    "delete_product", "delete_manager", "delete_github_source", "delete_tenant", "delete_user",
)


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _summary(event: str, tenant_id: Optional[str], details: dict[str, Any]) -> str:
    label = event.replace("_", " ")
    target = details.get("target") or details.get("manager") or details.get("repo") or ""
    suffix = f" — {target}" if target else ""
    tenant_suffix = f" (tenant {tenant_id})" if tenant_id else ""
    return f"RuleVis: {label}{suffix}{tenant_suffix}"


def _build_payload(fmt: str, event: str, tenant_id: Optional[str], details: dict[str, Any]) -> dict[str, Any]:
    summary = _summary(event, tenant_id, details)
    if fmt == "slack":
        return {"text": summary}
    if fmt == "teams":
        return {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": summary, "text": summary,
        }
    return {
        "event": event, "tenant_id": tenant_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data": details,
    }


def _post(url: str, payload: dict[str, Any], secret: str) -> tuple[bool, str]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-RuleVis-Signature"] = f"sha256={_sign(secret, body)}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:300]}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"unreachable: {e}"


def send_test(webhook: dict[str, Any]) -> tuple[bool, str]:
    """Sends a one-off test payload to a single webhook — used by the
    Settings UI's 'Send test' button. Returns (ok, message)."""
    fmt = webhook.get("format", "generic")
    payload = _build_payload(fmt, "test_event", None, {"target": "this is a test notification from RuleVis"})
    secret = crypto.decrypt(webhook.get("secret") or "")
    return _post(webhook["url"], payload, secret)


def dispatch_event(cfg: Config, tenant_id: str, event: str, details: dict[str, Any]) -> None:
    """Fires `event` to every enabled webhook in this tenant subscribed to
    it. Safe to call from a background thread; logs (not raises) on
    delivery failure so one broken webhook never affects request handling
    or other webhooks."""
    for webhook in cfg.webhooks:
        if not webhook.get("enabled", True):
            continue
        events = webhook.get("events") or []
        if events and event not in events:
            continue
        fmt = webhook.get("format", "generic")
        payload = _build_payload(fmt, event, tenant_id, details)
        secret = crypto.decrypt(webhook.get("secret") or "")
        ok, message = _post(webhook["url"], payload, secret)
        if not ok:
            logging.warning(f"webhook '{webhook.get('name') or webhook['url']}' delivery failed "
                           f"for event '{event}': {message}")
