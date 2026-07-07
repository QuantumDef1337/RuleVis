import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from internal import db, webhooks
from internal.config import Config


def _local_webhook_server():
    """A tiny local HTTP server standing in for Slack/Teams/ServiceNow —
    captures whatever RuleVis POSTs to it so tests can assert on it."""
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            received.append({
                "body": json.loads(body),
                "signature": self.headers.get("X-RuleVis-Signature"),
                "raw_body": body,
            })
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass  # keep test output quiet

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, received


def test_generic_webhook_delivers_event_payload():
    db.init_schema()
    server, received = _local_webhook_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        cfg = Config("tenant-webhook-test")
        cfg.upsert_webhook({"url": url, "format": "generic", "events": ["sync_manager"]})

        webhooks.dispatch_event(cfg, "tenant-webhook-test", "sync_manager", {"target": "wazuh-prod"})

        assert len(received) == 1
        payload = received[0]["body"]
        assert payload["event"] == "sync_manager"
        assert payload["tenant_id"] == "tenant-webhook-test"
        assert payload["data"]["target"] == "wazuh-prod"
    finally:
        server.shutdown()


def test_webhook_only_fires_for_subscribed_events():
    db.init_schema()
    server, received = _local_webhook_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        cfg = Config("tenant-webhook-test-2")
        cfg.upsert_webhook({"url": url, "events": ["delete_manager"]})  # not subscribed to sync_manager

        webhooks.dispatch_event(cfg, "tenant-webhook-test-2", "sync_manager", {"target": "x"})
        assert received == []

        webhooks.dispatch_event(cfg, "tenant-webhook-test-2", "delete_manager", {"target": "x"})
        assert len(received) == 1
    finally:
        server.shutdown()


def test_disabled_webhook_never_fires():
    db.init_schema()
    server, received = _local_webhook_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        cfg = Config("tenant-webhook-test-3")
        cfg.upsert_webhook({"url": url, "enabled": False})

        webhooks.dispatch_event(cfg, "tenant-webhook-test-3", "sync_manager", {"target": "x"})
        assert received == []
    finally:
        server.shutdown()


def test_webhook_payload_is_hmac_signed_with_the_configured_secret():
    db.init_schema()
    server, received = _local_webhook_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        cfg = Config("tenant-webhook-test-4")
        cfg.upsert_webhook({"url": url, "secret": "shhh-signing-secret"})

        webhooks.dispatch_event(cfg, "tenant-webhook-test-4", "sync_manager", {"target": "x"})

        assert len(received) == 1
        expected = "sha256=" + hmac.new(
            b"shhh-signing-secret", received[0]["raw_body"], hashlib.sha256).hexdigest()
        assert received[0]["signature"] == expected
    finally:
        server.shutdown()


def test_slack_and_teams_formats_produce_expected_shapes():
    db.init_schema()
    server, received = _local_webhook_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        cfg = Config("tenant-webhook-test-5")
        cfg.upsert_webhook({"url": url, "format": "slack"})
        webhooks.dispatch_event(cfg, "tenant-webhook-test-5", "sync_manager", {"target": "wazuh-prod"})
        assert "text" in received[-1]["body"]

        cfg.upsert_webhook({"url": url, "format": "teams", "id": "teams-1"})
        webhooks.dispatch_event(cfg, "tenant-webhook-test-5", "sync_manager", {"target": "wazuh-prod"})
        assert received[-1]["body"]["@type"] == "MessageCard"
    finally:
        server.shutdown()


def test_secret_is_encrypted_at_rest_but_signature_still_verifies():
    db.init_schema()
    server, received = _local_webhook_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        cfg = Config("tenant-webhook-test-6")
        saved = cfg.upsert_webhook({"url": url, "secret": "on-disk-should-be-encrypted"})
        assert saved["secret"] != "on-disk-should-be-encrypted"

        webhooks.dispatch_event(cfg, "tenant-webhook-test-6", "sync_manager", {"target": "x"})
        expected = "sha256=" + hmac.new(
            b"on-disk-should-be-encrypted", received[0]["raw_body"], hashlib.sha256).hexdigest()
        assert received[0]["signature"] == expected
    finally:
        server.shutdown()
