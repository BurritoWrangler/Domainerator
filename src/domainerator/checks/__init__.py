"""Security check modules for Domainerator.

Each check module exposes a ``run(runner, target, timeout=...)`` style set of
functions that return :class:`~domainerator.runner.CheckResult` objects. The
CLI orchestrates which modules run based on the credentials supplied.
"""

from __future__ import annotations

from ..runner import CheckResult, ToolRunner


def skipped_result(name: str, category: str, reason: str) -> CheckResult:
    """Convenience factory for a check that could not run."""
    return CheckResult(
        name=name,
        category=category,
        skipped=True,
        skip_reason=reason,
    )


def require_tool(
    runner: ToolRunner, tool: str, name: str, category: str
) -> CheckResult | None:
    """Return a skipped CheckResult if ``tool`` is missing, else ``None``."""
    if not runner.is_available(tool):
        return skipped_result(name, category, f"required tool '{tool}' not found on PATH")
    return None


# Signals in tool output that indicate we failed to reach/authenticate the
# target, meaning a "no finding" result is inconclusive rather than clean.
_FAILURE_SIGNALS = (
    "connection refused",
    "connection timed out",
    "timed out",
    "no route to host",
    "unable to connect",
    "could not connect",
    "authentication failed",
    "logon_failure",
    "status_logon_failure",
    "access_denied",
    "status_access_denied",
    "error",
    "traceback",
    # NetExec prints "[-]" for a negative/failed result and "[+]"/"[*]" for a
    # positive one. A "[-]" line means the module did not succeed, so a check
    # that parsed no finding cannot be called clean. Listing it here also stops
    # a negative line that happens to mention a keyword (e.g. "[-] no sccm")
    # from defeating the per-check "no recognizable output" guard.
    "[-]",
)


def looks_like_failure(output: str) -> str | None:
    """Return the matched failure signal in ``output``, or None.

    Used to mark a check inconclusive: if a check found nothing *and* the
    output shows a connection/auth failure, we cannot conclude the target is
    clean - the tool never got far enough to tell.
    """
    lowered = output.lower()
    for signal in _FAILURE_SIGNALS:
        if signal in lowered:
            return signal
    return None
