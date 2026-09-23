"""Live status reporting (nmap-style).

While a scan runs, the operator can press Enter to print a status snapshot:
elapsed time, how many work units have completed, and what is currently
running (with per-unit elapsed time). This mirrors nmap's interactive status
line.

Design
------
* :class:`ProgressTracker` is a thread-safe registry. Because scans run across
  a ``ThreadPoolExecutor``, multiple worker threads update it concurrently, so
  every mutation is guarded by a lock.
* A work "unit" here is a *(host, category)* pair (e.g. ``authenticated`` checks
  against ``10.0.0.10``). This gives meaningful, low-overhead granularity
  without threading state through every individual check.
* :class:`KeypressStatus` runs a background thread that watches stdin and, on
  Enter, prints the tracker's snapshot. It only engages on an interactive TTY;
  otherwise it is a safe no-op, so piped input, ``--dry-run`` previews, and CI
  are unaffected.

The keypress listener uses POSIX ``termios`` raw mode (the tool targets Linux /
Kali). On any platform without ``termios`` it degrades to a no-op.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass, field

try:  # POSIX only; absence -> listener becomes a no-op.
    import select
    import termios
    import tty

    _HAVE_TERMIOS = True
except ImportError:  # pragma: no cover - non-POSIX fallback
    _HAVE_TERMIOS = False


def _fmt_duration(seconds: float) -> str:
    """Human-friendly elapsed time, e.g. '5s', '1m03s', '1h02m'."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


@dataclass
class _RunningUnit:
    label: str
    started_at: float


@dataclass
class ProgressTracker:
    """Thread-safe progress state for an in-flight scan."""

    total: int = 0
    completed: int = 0
    started_at: float = field(default_factory=time.monotonic)
    _running: dict[str, _RunningUnit] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    # Monotonic counter to give each unit a unique key even if labels repeat.
    _seq: int = 0

    def set_total(self, total: int) -> None:
        with self._lock:
            self.total = total

    def add_total(self, n: int) -> None:
        with self._lock:
            self.total += n

    def start_unit(self, label: str) -> str:
        """Register a unit as running. Returns a token to pass to finish_unit."""
        with self._lock:
            self._seq += 1
            token = f"{self._seq}:{label}"
            self._running[token] = _RunningUnit(label=label, started_at=time.monotonic())
            return token

    def finish_unit(self, token: str) -> None:
        with self._lock:
            if token in self._running:
                del self._running[token]
                self.completed += 1

    def snapshot(self) -> dict:
        """Return a consistent copy of current progress for rendering."""
        with self._lock:
            now = time.monotonic()
            running = [
                (u.label, now - u.started_at)
                for u in sorted(self._running.values(), key=lambda x: x.started_at)
            ]
            return {
                "elapsed": now - self.started_at,
                "total": self.total,
                "completed": self.completed,
                "running": running,
            }

    def format_status(self) -> str:
        """Render an nmap-style status block from the current snapshot."""
        snap = self.snapshot()
        elapsed = _fmt_duration(snap["elapsed"])
        total = snap["total"]
        completed = snap["completed"]
        pct = f"{(completed / total * 100):.0f}%" if total else "?"

        lines = [
            f"Stats: {elapsed} elapsed; "
            f"{completed}/{total} units done ({pct})"
        ]
        running = snap["running"]
        if running:
            lines.append(f"  Running ({len(running)}):")
            for label, dur in running[:12]:
                lines.append(f"    {label}  ({_fmt_duration(dur)})")
            if len(running) > 12:
                lines.append(f"    ... and {len(running) - 12} more")
        else:
            lines.append("  (no units currently running)")
        return "\n".join(lines)

    def format_final(self) -> str:
        snap = self.snapshot()
        return (
            f"Completed {snap['completed']}/{snap['total']} units in "
            f"{_fmt_duration(snap['elapsed'])}"
        )


class KeypressStatus:
    """Background stdin watcher that prints tracker status on Enter.

    Use as a context manager::

        with KeypressStatus(tracker):
            ... run the scan ...

    On a non-interactive stdin (pipe, CI, no TTY) it does nothing.
    """

    def __init__(self, tracker: ProgressTracker, enabled: bool = True, stream=None):
        self.tracker = tracker
        self.stream = stream or sys.stderr
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._old_termios = None
        self._fd = -1
        # File descriptor we write status to. We use the terminal fd directly
        # via os.write rather than a buffered ``print`` to sys.stderr: mixing
        # buffered TTY writes with the raw cbreak-mode reads below can strand or
        # swallow input, so keeping all terminal I/O at the fd level avoids that.
        try:
            self._out_fd = self.stream.fileno()
        except (AttributeError, OSError, ValueError):
            self._out_fd = 2  # stderr
        # Only engage on a real interactive terminal with termios available.
        self.enabled = bool(
            enabled
            and _HAVE_TERMIOS
            and sys.stdin is not None
            and sys.stdin.isatty()
        )

    def _write(self, text: str) -> None:
        """Write directly to the terminal fd (bypasses buffered streams)."""
        try:
            os.write(self._out_fd, text.encode(errors="replace"))
        except OSError:
            pass

    def __enter__(self) -> KeypressStatus:
        if self.enabled:
            self._print_hint()
            self._start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _print_hint(self) -> None:
        self._write("[*] Scan running - press Enter for a status update.\n")

    def _start(self) -> None:
        try:
            self._fd = sys.stdin.fileno()
            self._old_termios = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)  # char-at-a-time, no echo of control keys
        except (termios.error, ValueError, OSError):
            # Could not put terminal in cbreak mode; disable gracefully.
            self.enabled = False
            self._old_termios = None
            return
        self._thread = threading.Thread(target=self._loop, name="status-listener", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        # Operate on the raw file descriptor (not the buffered sys.stdin object)
        # so select() and read() agree and no data is stranded in a buffer.
        fd = self._fd
        while not self._stop.is_set():
            try:
                # Wait up to 0.25s for input so we can check the stop flag.
                ready, _, _ = select.select([fd], [], [], 0.25)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                data = os.read(fd, 1)
            except (OSError, ValueError):
                break
            if data == b"":  # EOF
                break
            # Any Enter / newline triggers a status print.
            if data in (b"\n", b"\r"):
                self._write("\n" + self.tracker.format_status() + "\n")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        # Restore the terminal to its original mode.
        if self._old_termios is not None:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_termios)
            except (termios.error, ValueError, OSError):
                pass
            self._old_termios = None
