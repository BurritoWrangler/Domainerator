"""Tests for the ProgressTracker and status formatting."""

from __future__ import annotations

import threading

from domainerator.progress import KeypressStatus, ProgressTracker, _fmt_duration


def test_fmt_duration():
    assert _fmt_duration(5) == "5s"
    assert _fmt_duration(63) == "1m03s"
    assert _fmt_duration(3725) == "1h02m"


def test_start_finish_counts():
    t = ProgressTracker()
    t.set_total(3)
    a = t.start_unit("unauthenticated@10.0.0.10")
    b = t.start_unit("authenticated@10.0.0.10")
    snap = t.snapshot()
    assert snap["total"] == 3
    assert snap["completed"] == 0
    assert len(snap["running"]) == 2
    t.finish_unit(a)
    t.finish_unit(b)
    snap = t.snapshot()
    assert snap["completed"] == 2
    assert snap["running"] == []


def test_format_status_contains_expected_fields():
    t = ProgressTracker()
    t.set_total(2)
    t.start_unit("adcs@dc01")
    status = t.format_status()
    assert "Stats:" in status
    assert "0/2" in status
    assert "adcs@dc01" in status
    assert "Running" in status


def test_format_status_no_running_units():
    t = ProgressTracker()
    t.set_total(1)
    tok = t.start_unit("x@h")
    t.finish_unit(tok)
    status = t.format_status()
    assert "no units currently running" in status


def test_thread_safety_under_concurrent_updates():
    t = ProgressTracker()
    n = 200
    t.set_total(n)

    def worker():
        for _ in range(n // 10):
            tok = t.start_unit("w")
            t.finish_unit(tok)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    snap = t.snapshot()
    assert snap["completed"] == n
    assert snap["running"] == []


def test_keypress_status_noop_when_disabled():
    # Explicitly disabled -> context manager does nothing and does not touch
    # the terminal.
    t = ProgressTracker()
    ks = KeypressStatus(t, enabled=False)
    assert ks.enabled is False
    with ks:
        pass  # should not raise


def test_keypress_status_interactive_over_pty():
    """End-to-end: over a real pty, pressing Enter prints a status snapshot.

    We drain the startup hint before injecting the keystroke so the test is not
    subject to the terminal echo race (a real operator's terminal behaves this
    way naturally).
    """
    import os
    import select
    import sys as _sys
    import time

    if not hasattr(os, "fork") or not hasattr(_sys, "platform") or os.name != "posix":
        import pytest as _pytest

        _pytest.skip("pty test requires POSIX")

    import pty

    def child():
        # pytest may replace sys.stdin with a non-TTY capture object; rebind it
        # to the pty slave (fd 0) so isatty() reflects the real terminal.
        _sys.stdin = os.fdopen(0, "r")
        import domainerator.progress as prog

        t = prog.ProgressTracker()
        t.set_total(2)
        t.start_unit("unauthenticated@10.0.0.10")
        # Write status to the pty (fd 1), not pytest-captured stderr.
        ks = prog.KeypressStatus(t, enabled=True, stream=os.fdopen(1, "w"))
        ks.__enter__()
        time.sleep(1.5)
        ks.stop()
        os.write(1, b"CHILD_DONE\n")
        os._exit(0)

    pid, fd = pty.fork()
    if pid == 0:
        child()
        return  # unreachable

    out = b""
    start = time.time()
    sent = False
    while time.time() - start < 4:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                data = os.read(fd, 1024)
            except OSError:
                break
            if not data:
                break
            out += data
        if not sent and b"press Enter" in out:
            time.sleep(0.2)
            os.write(fd, b"\r")
            sent = True
        if b"CHILD_DONE" in out:
            break
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass

    text = out.decode(errors="replace")
    assert "Stats:" in text
    assert "unauthenticated@10.0.0.10" in text


def test_keypress_status_disabled_without_tty(monkeypatch):
    # Even if enabled=True, a non-TTY stdin must keep it disabled.
    import domainerator.progress as prog

    class FakeStdin:
        def isatty(self):
            return False

    monkeypatch.setattr(prog.sys, "stdin", FakeStdin())
    ks = KeypressStatus(ProgressTracker(), enabled=True)
    assert ks.enabled is False
