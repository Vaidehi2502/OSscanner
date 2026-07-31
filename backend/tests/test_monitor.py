"""Tests for the optional background monitor thread.

_loop() is patched out in every test so nothing here actually sleeps for
a real interval or touches scan_service/the database - these tests only
cover start()/status()'s decision logic and thread orchestration.
"""
import time

import pytest

import monitor


@pytest.fixture(autouse=True)
def reset_monitor_state(monkeypatch):
    # _STARTED/_STARTED_INTERVAL are module-level singletons so the
    # monitor is only ever started once per real process; reset them
    # between tests so each test starts from "not running".
    monkeypatch.setattr(monitor, "_STARTED", False)
    monkeypatch.setattr(monitor, "_STARTED_INTERVAL", 0)


def test_start_is_a_noop_when_no_interval_configured(monkeypatch):
    monkeypatch.delenv("MONITOR_INTERVAL_SECONDS", raising=False)
    assert monitor.start() is False
    assert monitor.status() == {"enabled": False, "interval_seconds": 0}


def test_start_is_a_noop_for_zero_or_negative_interval():
    assert monitor.start(0) is False
    assert monitor.start(-5) is False


def test_start_reads_interval_from_env_var(monkeypatch):
    monkeypatch.setattr(monitor, "_loop", lambda interval: None)
    monkeypatch.setenv("MONITOR_INTERVAL_SECONDS", "300")

    assert monitor.start() is True
    assert monitor.status() == {"enabled": True, "interval_seconds": 300}


def test_start_launches_background_thread_for_positive_interval(monkeypatch):
    calls = []
    monkeypatch.setattr(monitor, "_loop", lambda interval: calls.append(interval))

    assert monitor.start(5) is True
    time.sleep(0.05)  # let the (patched, instant) daemon thread actually run

    assert calls == [5]
    assert monitor.status() == {"enabled": True, "interval_seconds": 5}


def test_start_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr(monitor, "_loop", lambda interval: calls.append(interval))

    monitor.start(5)
    monitor.start(10)  # already running - should be ignored
    time.sleep(0.05)

    assert calls == [5]
    assert monitor.status()["interval_seconds"] == 5


def test_run_once_safely_survives_a_failing_scan(monkeypatch, capsys):
    def _boom():
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(monitor.scan_service, "run_and_persist_scan", _boom)

    monitor._run_once_safely()  # should not raise

    assert "background monitor scan failed" in capsys.readouterr().out
