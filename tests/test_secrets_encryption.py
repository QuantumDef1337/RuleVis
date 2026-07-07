from internal import crypto, db
from internal.config import Config, config_path, redact_github_source, redact_manager


def test_encrypt_decrypt_roundtrip():
    db.init_schema()
    secret = "super-secret-wazuh-password-1"
    token = crypto.encrypt(secret)
    assert token != secret  # never stored as plaintext
    assert crypto.decrypt(token) == secret


def test_decrypt_falls_back_to_plaintext_for_pre_encryption_values():
    # Upgrade path: values saved before this feature existed are plain text
    # and must keep working until they're next saved through the UI.
    db.init_schema()
    assert crypto.decrypt("already-plaintext-password") == "already-plaintext-password"


def test_encrypt_of_empty_string_is_a_noop():
    db.init_schema()
    assert crypto.encrypt("") == ""
    assert crypto.decrypt("") == ""


def test_manager_password_is_encrypted_on_disk():
    db.init_schema()
    cfg = Config("tenant-crypto-test")
    saved = cfg.upsert_manager({"url": "https://wazuh.example.com:55000",
                                "username": "wazuh-wui", "password": "hunter2-plaintext"})
    # What upsert_manager returns/keeps in memory is already the encrypted form.
    assert saved["password"] != "hunter2-plaintext"
    assert crypto.decrypt(saved["password"]) == "hunter2-plaintext"

    # What actually landed in config.json must never contain the plaintext.
    with open(config_path(cfg.tenant_id), "r", encoding="utf-8") as f:
        raw_json = f.read()
    assert "hunter2-plaintext" not in raw_json

    # The API-facing redaction still blanks it out entirely either way.
    assert redact_manager(saved)["password"] == ""


def test_github_source_token_is_encrypted_on_disk():
    db.init_schema()
    cfg = Config("tenant-crypto-test-2")
    saved = cfg.upsert_github_source({"repo": "acme/rules", "token": "ghp_plaintexttoken123"})
    assert saved["token"] != "ghp_plaintexttoken123"
    assert crypto.decrypt(saved["token"]) == "ghp_plaintexttoken123"

    with open(config_path(cfg.tenant_id), "r", encoding="utf-8") as f:
        raw_json = f.read()
    assert "ghp_plaintexttoken123" not in raw_json
    assert redact_github_source(saved)["token"] == ""


def test_blank_password_on_update_keeps_the_existing_encrypted_value():
    db.init_schema()
    cfg = Config("tenant-crypto-test-3")
    saved = cfg.upsert_manager({"url": "https://wazuh.example.com:55000", "password": "original-secret"})
    mid = saved["id"]

    # Editing the manager without touching the password field (blank password
    # in the update payload) must not wipe or re-encrypt-to-garbage the secret.
    updated = cfg.upsert_manager({"id": mid, "url": "https://wazuh.example.com:55000",
                                  "name": "renamed", "password": ""})
    assert crypto.decrypt(updated["password"]) == "original-secret"
