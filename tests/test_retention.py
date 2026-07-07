import time

from sqlalchemy import text

from internal import db


def _backdate_all(table: str, days_ago: float) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days_ago * 86400))
    with db.get_engine().begin() as conn:
        conn.execute(text(f"UPDATE {table} SET created_at = :ts"), {"ts": ts})


def test_sweep_retention_prunes_old_audit_log_entries():
    db.init_schema()
    db.set_platform_settings({"audit_log_retention_days": 1})
    db.log_audit("test_action", actor_email="someone@example.com")
    assert len(db.list_audit_log()) == 1

    _backdate_all("audit_log", days_ago=2)
    db.sweep_retention()
    assert db.list_audit_log() == []


def test_sweep_retention_keeps_entries_within_the_window():
    db.init_schema()
    db.set_platform_settings({"audit_log_retention_days": 30})
    db.log_audit("recent_action", actor_email="someone@example.com")

    db.sweep_retention()
    assert len(db.list_audit_log()) == 1


def test_sweep_retention_prunes_old_login_activity():
    db.init_schema()
    db.set_platform_settings({"login_history_retention_days": 1})
    db.record_login_activity("someone@example.com", True)
    assert len(db.list_login_activity()) == 1

    _backdate_all("login_activity", days_ago=5)
    db.sweep_retention()
    assert db.list_login_activity() == []
