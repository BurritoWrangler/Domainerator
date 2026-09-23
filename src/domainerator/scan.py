"""Per-target scan orchestration.

``scan_target`` runs the configured checks against a single target and returns
its :class:`~domainerator.runner.CheckResult` list. Keeping this separate from
the CLI lets us run many targets concurrently (see ``scan_targets``) while the
CLI stays focused on argument handling and reporting.

An optional :class:`~domainerator.progress.ProgressTracker` may be supplied to
record live progress at *(host, category)* granularity, which powers the
interactive status feature.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import bloodhound
from .checks import adcs, authenticated, sccm, unauthenticated
from .progress import ProgressTracker
from .runner import CheckResult, Target, ToolRunner


@dataclass
class ScanOptions:
    """Everything that controls what a scan runs (independent of target)."""

    timeout: int = 300
    skip_unauth: bool = False
    skip_auth: bool = False
    skip_adcs: bool = False
    skip_sccm: bool = False
    userlist: str | None = None
    bloodhound_collect: bool = False
    bloodhound_output: str = "bloodhound-output"
    bloodhound_data: str | None = None


def _phases(target: Target, opts: ScanOptions):
    """Yield (category, callable) work units applicable to this target.

    Each phase runs one check module's ``run_all``. Structuring the scan as
    discrete phases lets the progress tracker report which category is running
    against which host.
    """
    if not opts.skip_unauth:
        yield "unauthenticated", lambda r, t: unauthenticated.run_all(
            r, t, timeout=opts.timeout, userlist=opts.userlist
        )
    if target.authenticated:
        if not opts.skip_auth:
            yield "authenticated", lambda r, t: authenticated.run_all(
                r, t, timeout=opts.timeout
            )
        if not opts.skip_adcs:
            yield "adcs", lambda r, t: adcs.run_all(r, t, timeout=opts.timeout)
    # SCCM runs regardless of auth: AD discovery needs creds (self-skips when
    # absent) while PXE/NAA probing can work against an open responder.
    if not opts.skip_sccm:
        yield "sccm", lambda r, t: sccm.run_all(r, t, timeout=opts.timeout)


def count_units(targets: list[Target], opts: ScanOptions) -> int:
    """Total number of (host, category) work units across all targets."""
    return sum(len(list(_phases(t, opts))) for t in targets)


def scan_target(
    runner: ToolRunner,
    target: Target,
    opts: ScanOptions,
    tracker: ProgressTracker | None = None,
) -> list[CheckResult]:
    """Run all applicable checks against one target."""
    results: list[CheckResult] = []

    for category, run_phase in _phases(target, opts):
        token = None
        if tracker is not None:
            token = tracker.start_unit(f"{category}@{target.host}")
        try:
            results += run_phase(runner, target)
        finally:
            if tracker is not None and token is not None:
                tracker.finish_unit(token)

    # BloodHound collection/ingestion is domain-wide, so it is done once by the
    # CLI rather than per-target; see cli.py.
    _ = bloodhound  # imported for callers that may collect explicitly
    return results


def scan_targets(
    runner: ToolRunner,
    targets: list[Target],
    opts: ScanOptions,
    max_workers: int = 5,
    tracker: ProgressTracker | None = None,
) -> dict[str, list[CheckResult]]:
    """Scan multiple targets concurrently.

    Returns a mapping of target host -> its check results. A worker pool bounds
    concurrency so we don't overwhelm the network or the DC. Each target gets
    the same ToolRunner (its scope check and tool cache are safe to share; the
    subprocess calls are independent).
    """
    out: dict[str, list[CheckResult]] = {}
    if not targets:
        return out
    if len(targets) == 1:
        out[targets[0].host] = scan_target(runner, targets[0], opts, tracker)
        return out

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_host = {
            pool.submit(scan_target, runner, tgt, opts, tracker): tgt.host
            for tgt in targets
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                out[host] = future.result()
            except Exception as exc:  # never let one host abort the batch
                cr = CheckResult(name="scan", category="scan", error=f"scan failed: {exc}")
                out[host] = [cr]
    return out
