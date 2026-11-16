"""Security check modules for Domainerator.

Each check module exposes a ``run(runner, target, timeout=...)`` style set of
functions that return :class:`~domainerator.runner.CheckResult` objects. The
CLI orchestrates which modules run based on the credentials supplied.
"""

from __future__ import annotations

import enum

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


# Signals in tool output that indicate we failed to reach the target (or the
# tool errored), meaning a "no finding" result is inconclusive rather than
# clean. A bare "[-]" is handled as a separate fallback in classify_failure.
_CONNECTIVITY_FAILURE_SIGNALS = (
    "connection refused",
    "connection timed out",
    "timed out",
    "no route to host",
    "unable to connect",
    "could not connect",
    "authentication failed",
    "error",
    "traceback",
)

# Signals showing the target answered but refused the login. For a null-session
# probe this is a legitimate "anonymous access denied" result, not a failure to
# reach the host.
_ACCESS_DENIED_SIGNALS = (
    "access_denied",
    "status_access_denied",
    "logon_failure",
    "status_logon_failure",
)


class FailureKind(enum.Enum):
    """Why a tool run produced no usable result."""

    CONNECTIVITY = "connectivity"
    ACCESS_DENIED = "access_denied"


def classify_failure(output: str) -> tuple[FailureKind, str] | None:
    """Classify a failure in ``output`` as ``(kind, matched_signal)``, or None.

    Connectivity signals win over access-denied signals when both appear. A
    bare NetExec ``[-]`` line with no other signal is treated as connectivity,
    so a negative line that mentions a keyword (e.g. "[-] no sccm") cannot
    defeat the per-check "no recognizable output" guard.
    """
    lowered = output.lower()
    for signal in _CONNECTIVITY_FAILURE_SIGNALS:
        if signal in lowered:
            return FailureKind.CONNECTIVITY, signal
    for signal in _ACCESS_DENIED_SIGNALS:
        if signal in lowered:
            return FailureKind.ACCESS_DENIED, signal
    if "[-]" in lowered:
        return FailureKind.CONNECTIVITY, "[-]"
    return None


def looks_like_failure(output: str) -> str | None:
    """Return the matched failure signal in ``output``, or None.

    Thin wrapper over :func:`classify_failure` that ignores the kind.
    """
    result = classify_failure(output)
    return result[1] if result else None
