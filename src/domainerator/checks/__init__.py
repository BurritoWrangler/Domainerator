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
