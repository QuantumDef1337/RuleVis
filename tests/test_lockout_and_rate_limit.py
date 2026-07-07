from internal import db


def test_account_lockout_after_threshold_failed_attempts():
    db.init_schema()
    db.set_platform_settings({"lockout_threshold": 3, "lockout_duration_minutes": 15})
    db.create_user("locked@example.com", "some-strong-password-1")

    assert db.is_locked_out("locked@example.com") is None
    for _ in range(3):
        db.register_failed_login("locked@example.com")
    assert db.is_locked_out("locked@example.com") is not None


def test_reset_failed_login_clears_lockout():
    db.init_schema()
    db.set_platform_settings({"lockout_threshold": 2, "lockout_duration_minutes": 15})
    u = db.create_user("reset-me@example.com", "some-strong-password-1")
    db.register_failed_login("reset-me@example.com")
    db.register_failed_login("reset-me@example.com")
    assert db.is_locked_out("reset-me@example.com") is not None
    db.reset_failed_login(u["id"])
    assert db.is_locked_out("reset-me@example.com") is None


def test_ip_rate_limit_catches_credential_stuffing_across_accounts():
    """Account lockout alone only stops brute-forcing ONE known account —
    this is the other half: many different accounts hammered from one IP.
    Backed by the DB (not an in-process dict), so this holds true no matter
    how many worker processes are handling requests."""
    db.init_schema()
    ip = "203.0.113.5"
    for _ in range(20):
        assert db.is_ip_rate_limited(ip, max_failures=20, window_seconds=900) is False
        db.register_ip_login_failure(ip)
    assert db.is_ip_rate_limited(ip, max_failures=20, window_seconds=900) is True


def test_ip_rate_limit_is_scoped_per_ip():
    db.init_schema()
    noisy_ip = "203.0.113.9"
    quiet_ip = "203.0.113.10"
    for _ in range(20):
        db.register_ip_login_failure(noisy_ip)
    assert db.is_ip_rate_limited(noisy_ip, max_failures=20, window_seconds=900) is True
    assert db.is_ip_rate_limited(quiet_ip, max_failures=20, window_seconds=900) is False


def test_ip_rate_limit_sweep_removes_old_failures():
    db.init_schema()
    ip = "203.0.113.20"
    for _ in range(20):
        db.register_ip_login_failure(ip)
    assert db.is_ip_rate_limited(ip, max_failures=20, window_seconds=900) is True
    # A negative "older than" window pushes the cutoff a few seconds into the
    # future, guaranteeing every failure just inserted counts as "old".
    db.sweep_ip_login_failures(older_than_seconds=-5)
    assert db.is_ip_rate_limited(ip, max_failures=20, window_seconds=900) is False
