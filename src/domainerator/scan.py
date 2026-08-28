"""Per-target scan orchestration.

``scan_target`` runs the configured checks against a single target and returns
its :class:`~domainerator.runner.CheckResult` list. Keeping this separate from
the CLI lets us run many targets concurrently (see ``scan_targets``) while the
CLI stays focused on argument handling and reporting.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import bloodhound
from .checks import adcs, authenticated, unauthenticated
from .runner import CheckResult, Target, ToolRunner


@dataclass
class ScanOptions:
    """Everything that controls what a scan runs (independent of target)."""

    timeout: int = 300
    skip_unauth: bool = False
    skip_auth: bool = False
    skip_adcs: bool = False
    userlist: str | None = None
    bloodhound_collect: bool = False
    bloodhound_output: str = "bloodhound-output"
    bloodhound_data: str | None = None


def scan_target(
    runner: ToolRunner, target: Target, opts: ScanOptions
) -> list[CheckResult]:
    """Run all applicable checks against one target."""
    results: list[CheckResult] = []

    if not opts.skip_unauth:
        results += unauthenticated.run_all(
            runner, target, timeout=opts.timeout, userlist=opts.userlist
        )

    if target.authenticated:
        if not opts.skip_auth:
            results += authenticated.run_all(runner, target, timeout=opts.timeout)
        if not opts.skip_adcs:
            results += adcs.run_all(runner, target, timeout=opts.timeout)

    # BloodHound collection/ingestion is domain-wide, so it is done once by the
    # CLI rather than per-target; see cli.py. scan_target intentionally does not
    # collect BloodHound to avoid repeating a domain-wide collection per host.
    _ = bloodhound  # imported for callers that may collect explicitly
    return results


def scan_targets(
    runner: ToolRunner,
    targets: list[Target],
    opts: ScanOptions,
    max_workers: int = 5,
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
        out[targets[0].host] = scan_target(runner, targets[0], opts)
        return out

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_host = {
            pool.submit(scan_target, runner, tgt, opts): tgt.host for tgt in targets
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                out[host] = future.result()
            except Exception as exc:  # never let one host abort the batch
                cr = CheckResult(name="scan", category="scan", error=f"scan failed: {exc}")
                out[host] = [cr]
    return out
