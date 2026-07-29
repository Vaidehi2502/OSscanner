"""Tests for process_scanner.py's rule matching and CPU-sampling logic.

Rule-matching tests go through the /proc fallback path (HAVE_PSUTIL=False)
with canned process dicts, since it has no priming/sleep behavior to fake.
The psutil-specific CPU-sampling tests use fake process objects instead.
"""
import scanners.process_scanner as process_scanner


def _proc(name, exe="", cpu_percent=0, cmdline=""):
    return {"pid": 1, "name": name, "exe": exe, "cpu_percent": cpu_percent, "cmdline": cmdline}


def _run_scan_with_procs(monkeypatch, procs):
    monkeypatch.setattr(process_scanner, "HAVE_PSUTIL", False)
    monkeypatch.setattr(process_scanner, "_iter_processes_proc", lambda: iter(procs))
    return process_scanner.scan()


def test_scan_flags_exact_suspicious_name(monkeypatch):
    findings = _run_scan_with_procs(monkeypatch, [_proc("nc")])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_scan_does_not_flag_substring_match(monkeypatch):
    # Regression test: "nc" is a suspicious name, but process names that
    # merely *contain* "nc" (like real processes systemd-timesyncd,
    # *-launcher) are not the same as being named "nc" and must not match.
    findings = _run_scan_with_procs(
        monkeypatch,
        [_proc("systemd-timesyncd"), _proc("at-spi-bus-launcher"), _proc("sync")],
    )
    assert findings == []


def test_scan_flags_suspicious_path(monkeypatch):
    findings = _run_scan_with_procs(monkeypatch, [_proc("weird_tool", exe="/tmp/weird_tool")])
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_scan_does_not_flag_normal_path(monkeypatch):
    findings = _run_scan_with_procs(monkeypatch, [_proc("bash", exe="/usr/bin/bash")])
    assert findings == []


def test_scan_flags_high_cpu_usage(monkeypatch):
    findings = _run_scan_with_procs(monkeypatch, [_proc("some_app", cpu_percent=95)])
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


def test_scan_does_not_flag_normal_cpu_usage(monkeypatch):
    findings = _run_scan_with_procs(monkeypatch, [_proc("some_app", cpu_percent=50)])
    assert findings == []


class _FakeProcess:
    """Mimics enough of psutil.Process for _iter_processes_psutil: an
    `.info` dict plus a cpu_percent() that returns 0.0 on first call
    (psutil's real "priming" behavior) and a real value on the second."""

    def __init__(self, pid, name, readings):
        self.info = {"pid": pid, "name": name, "exe": "", "cmdline": []}
        self._readings = iter(readings)

    def cpu_percent(self, interval=None):
        return next(self._readings)


def test_iter_processes_psutil_primes_before_reading_real_value(monkeypatch):
    # First cpu_percent() call is the "prime" (psutil returns 0.0/garbage
    # here always); the second call is the real reading after the sleep.
    fake_high_cpu = _FakeProcess(1, "xmrig", readings=[0.0, 97.5])
    monkeypatch.setattr(process_scanner.psutil, "process_iter", lambda attrs: [fake_high_cpu])
    monkeypatch.setattr(process_scanner.time, "sleep", lambda seconds: None)

    procs = list(process_scanner._iter_processes_psutil())
    assert len(procs) == 1
    assert procs[0]["cpu_percent"] == 97.5


def test_iter_processes_psutil_skips_process_that_exits_mid_sample(monkeypatch):
    import psutil as real_psutil

    class _DyingProcess(_FakeProcess):
        def cpu_percent(self, interval=None):
            raise real_psutil.NoSuchProcess(pid=1)

    monkeypatch.setattr(process_scanner.psutil, "process_iter", lambda attrs: [_DyingProcess(1, "gone", [])])
    monkeypatch.setattr(process_scanner.time, "sleep", lambda seconds: None)

    assert list(process_scanner._iter_processes_psutil()) == []
