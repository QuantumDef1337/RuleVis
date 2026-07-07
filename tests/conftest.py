import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest


@pytest.fixture(autouse=True)
def isolated_app_dir(tmp_path, monkeypatch):
    """Every test gets its own throwaway ~/.rulevis (db.py/config.py resolve
    it from HOME/USERPROFILE at call time) — tests never touch the real
    developer's data, and never see state left behind by another test."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    yield
