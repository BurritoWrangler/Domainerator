# Design Document: Console Scan-All-Targets

## Overview

This feature adds a `scanall` console command that runs the existing concurrent
multi-host scan primitive (`scan.scan_targets`) against every target in
`session.targets`, instead of requiring the operator to `target <id>` + `scan`
through each host by hand. It is implemented entirely inside
`src/domainerator/console/console.py` (new `cmd_scanall` command method plus a
new `_run_scan_all` helper, mirroring the existing `cmd_scan`/`_run_scan` pair)
and reuses `scan.ScanOptions`/`scan.scan_targets` and `session.add_results`/
`session.recompute_paths` unchanged. No new modules, classes, or data models
are introduced — the design's job is entirely to get the per-host merge,
evidence, scope-warning, and output-formatting semantics to match what
`_run_scan` already does for a single target, applied once per host in a
loop around the single `scan_targets` call. Technology stack: pure Python
stdlib (`concurrent.futures` already used inside `scan_targets`); no new
dependencies.

## Architecture

```
cmd_scanall(args)
   │  parses optional <category>, validates against _SCAN_CATEGORIES
   ▼
_run_scan_all(category)
   │  1. snapshot session.targets (session.target is never reassigned)
   │  2. print header line
   │  3. scope warning pass: for each target, warn if out of scope (don't skip)
   │  4. build one ScanOptions (same fields as _run_scan)
   │  5. per_host = scan_targets(runner, targets, opts, max_workers=5)
   │  6. for each host in original target order:
   │       - replace-by-(name, category) merge into session.check_results
   │       - session.add_results(host_results)
   │       - write evidence for that host (if configured)
   │       - print one per-host summary line (or "no checks applicable")
   │       - accumulate running totals
   │  7. session.recompute_paths()   <- once, after the loop
   │  8. print aggregate summary (totals + the paths hint, once)
```

`scan_targets` already provides concurrency (`ThreadPoolExecutor`,
`max_workers=5`) and per-host exception isolation (a failed host's exception
is caught inside `scan_targets` and turned into an error `CheckResult`, never
raised to the caller). `_run_scan_all` therefore only needs to (a) call it
once with the full target list and (b) do the same sequential per-host
merge/evidence/print work `_run_scan` does today for a single host, repeated
host-by-host over the dict `scan_targets` returns. This keeps `scanall`'s
console-side logic almost entirely a thin iteration wrapper, so there is only
one place (`scan_targets`) that owns concurrency and failure isolation.

**Decision — where host-by-host replace-merge happens.** Requirement 4.1 notes
`CheckResult` has no host field, so "drop stale results for this host, add
fresh ones" can't be done by filtering `session.check_results` on a host
attribute. `scan_targets` already returns `dict[str, list[CheckResult]]`
keyed by host, so the fix is procedural, not a data model change: process one
host's entry from that dict at a time, compute `fresh_keys = {(r.name,
r.category) for r in host_results}` for *that host's* fresh results only, and
filter `session.check_results` by `(name, category) not in fresh_keys` before
calling `session.add_results(host_results)` for that host — exactly the two
lines `_run_scan` already runs, just invoked once per host in a `for host,
host_results in per_host.items()` loop instead of once for the active target.
Because this filter only removes entries whose `(name, category)` key matches
one of the keys the host currently reports, and categories are host-specific
runs (a check module is invoked once per host, never shared across hosts in
one `scan_target` call), this cannot cross-contaminate a different host's
results sharing the same `(name, category)` pair in the global list — the
filter is applied, and the replacement added, immediately after each host's
own fresh keys are computed, before the next host's results are read from
the dict. No ordering requirement on `per_host.items()` is needed for
correctness; order only affects print order, so I iterate in
`session.targets` order (not dict iteration order) to make per-host summary
lines deterministic and match the `targets`/`show targets` listing order.

**Decision — single `recompute_paths()` call.** `recompute_paths` rebuilds
`session.attack_paths` from the full accumulated `session.check_results`
(see `session.py` lines ~149-163); it does not take a host parameter and is
order-independent over the merged list. Calling it once after the per-host
merge loop (rather than once per host) produces an identical final
`attack_paths` value with O(1) path-engine runs instead of O(n), matching
Requirement 4.3's reasoning exactly. This mirrors `_run_scan`'s single call,
just moved to after the loop instead of after a single merge.

**Decision — scope handling.** Requirement 5 explicitly keeps the existing
console convention of "warn, don't pre-skip". `_run_scan` does this check
only for `session.target`; `_run_scan_all` runs the same `scope.contains`
check in a loop over `session.targets` before calling `scan_targets`, printing
one warning line per out-of-scope host, then still includes every host
(in-scope or not) in the single `scan_targets(...)` call. The `ToolRunner`'s
own per-command scope enforcement (shared by all hosts, since `scan_targets`
passes the same `runner` to every worker) is what actually refuses tool
invocations for out-of-scope hosts; this is unchanged, existing behavior.

**Decision — progress UI.** Per the requirements' Out of Scope list, no live
progress bar is added. `scan_targets` accepts an optional `tracker:
ProgressTracker | None` parameter used by the CLI's batch path
(`cli.py`) together with `KeypressStatus` for an interactive terminal status
line. `_run_scan_all` does not pass a tracker (defaults to `None`), matching
`_run_scan`'s existing choice not to use one — the console already gives
immediate per-host print lines as each host's scan completes conceptually
(in practice, because `scan_targets` blocks until all futures resolve, prints
happen in a tight loop right after the single blocking call returns, not
incrementally as each future completes; this matches the requirement that a
live progress bar is explicitly out of scope, and avoids adding incremental
callback plumbing that `scan_targets` does not currently expose).

## Components and Interfaces

### 1. `cmd_scanall`

Added next to `cmd_scan`/`cmd_rescan` (around line 1286 in
`console.py`, directly after `cmd_rescan`):

```python
def cmd_scanall(self, args: list[str]) -> None:
    """Run checks against every loaded target (session.targets).

    Usage:
      scanall              Run all applicable checks against every target
      scanall <category>   Run one category against every target:
                            unauthenticated | authenticated | adcs | sccm

    Unlike 'scan'/'rescan', which only touch the active target, this scans
    every host in 'targets' concurrently (same worker pool scan_targets()
    uses for the CLI's initial batch pass), merges each host's results into
    the session the same way 'scan' does, and recomputes attack paths once
    at the end. The active target (session.target) is left unchanged.
    """
    category = None
    if args:
        category = args[0].lower()
        if category not in self._SCAN_CATEGORIES:
            print(f"Unknown category: {category}")
            print("Categories: " + ", ".join(self._SCAN_CATEGORIES))
            return
    self._run_scan_all(category)
```

This reuses the existing `_SCAN_CATEGORIES` class tuple and the identical
unknown-category message `cmd_scan` already prints, satisfying Requirement
1.4 by construction (same code path, same strings).

Registration: added to `self.commands` dict in `__init__` immediately after
the `"rescan": self.cmd_rescan,` entry:

```python
"scan": self.cmd_scan,
"rescan": self.cmd_rescan,
"scanall": self.cmd_scanall,
```

Tab completion: `scanall` needs no special-case branch in `_setup_completion`
beyond what already exists — the `len(parts) <= 1` branch that completes
command names from `self.commands` automatically includes `scanall` once it
is registered there (the same mechanism that already completes `scan`,
`rescan`, `targets`). No change is needed to the `elif parts[0] == "show"`-style
per-argument completion lists, since `scanall`'s only argument is a category
name, which is short and not currently tab-completed for `scan` either (for
consistency, `scanall <category>` is deliberately left uncompleted, matching
`scan <category>`'s existing behavior — adding category completion to one and
not the other would be an unrelated, unrequested enhancement).

### 2. `_run_scan_all`

Added directly after `_run_scan` (after the existing evidence-write block,
before `cmd_save`):

```python
def _run_scan_all(self, category: str | None) -> None:
    """Scan every target in session.targets, merge per host, recompute once.

    Mirrors ``_run_scan``'s per-host merge/evidence/summary logic, but calls
    ``scan_targets`` once for the whole target list (reusing its worker pool
    and per-host exception isolation) instead of looping calls to
    ``scan_target``. ``session.target`` (the active target) is never
    reassigned by this method.
    """
    from ..scan import ScanOptions, scan_targets

    targets = self.session.targets
    label = category or "all applicable"

    if not targets:
        print("No targets to scan. Use 'targets' to check the loaded target list.")
        return

    print()
    print(f"Running {label} checks against {len(targets)} target(s): "
          + ", ".join(t.host for t in targets))

    scope = self.session.runner.scope
    if scope is not None and scope.active:
        for t in targets:
            if not scope.contains(t.host):
                print(f"WARNING: {t.host} is outside the configured scope; "
                      "checks targeting it will be refused.")

    opts = ScanOptions(
        timeout=self.session.runner.timeout,
        skip_unauth=category not in (None, "unauthenticated"),
        skip_auth=category not in (None, "authenticated"),
        skip_adcs=category not in (None, "adcs"),
        skip_sccm=category not in (None, "sccm"),
    )

    try:
        per_host = scan_targets(self.session.runner, targets, opts, max_workers=5)
    except Exception as exc:  # never let a batch scan crash the console
        print(f"Scan error: {exc}")
        return

    total_checks = 0
    total_findings = 0
    total_steps = 0
    for t in targets:
        host = t.host
        results = per_host.get(host, [])
        if not results:
            print(f"  {host}: no checks applicable")
            continue

        # Merge: drop this host's prior (name, category) results, add fresh.
        fresh_keys = {(r.name, r.category) for r in results}
        self.session.check_results = [
            r for r in self.session.check_results
            if (r.name, r.category) not in fresh_keys
        ]
        self.session.add_results(results)

        findings = sum(len(r.findings) for r in results)
        steps = sum(len(r.path_steps or []) for r in results)
        total_checks += len(results)
        total_findings += findings
        total_steps += steps
        print(f"  {host}: ran {len(results)} check(s), {findings} finding(s), "
              f"{steps} path step(s)")

        if self.session.evidence is not None:
            try:
                self.session.evidence.write_results(results, target=host)
            except OSError as exc:
                print(f"  {host}: (could not write evidence: {exc})")

    self.session.recompute_paths()

    print()
    print(f"Scanned {len(targets)} target(s): {total_checks} check(s) total, "
          f"{total_findings} finding(s), {total_steps} path step(s).")
    print(f"Capabilities: {len(self.session.capabilities)}  "
          f"Attack paths: {len(self.session.attack_paths)}")
    if self.session.attack_paths:
        print("Use 'show paths' to view them.")
    else:
        print("No complete escalation path yet. 'show findings' and "
              "'show capabilities' show what was discovered; some paths "
              "need extra capabilities (e.g. ESC8 needs a relay target + "
              "coercion) before they close.")
```

`session.target` is read only through the `targets` list snapshot; neither
`switch_target` nor any assignment to `self.session.target` appears anywhere
in this method, satisfying Requirement 8.

### 3. Printed output format

Exact lines, in order (host lines shown for a 2-host example):

```
Running all applicable checks against 2 target(s): 10.0.0.10, 10.0.0.20
WARNING: 10.0.0.20 is outside the configured scope; checks targeting it will be refused.
  10.0.0.10: ran 4 check(s), 2 finding(s), 1 path step(s)
  10.0.0.20: no checks applicable

Scanned 2 target(s): 4 check(s) total, 2 finding(s), 1 path step(s).
Capabilities: 3  Attack paths: 1
Use 'show paths' to view them.
```

- Header line format string: `f"Running {label} checks against {len(targets)} target(s): " + ", ".join(t.host for t in targets)`.
  `label` is `category or "all applicable"`, matching `_run_scan`'s own
  `label = category or "all applicable"` line verbatim (Requirement 1's note
  that help/behavior stays consistent with `cmd_scan`).
- Scope warning line: identical wording to `_run_scan`'s existing warning,
  just looped per host: `f"WARNING: {t.host} is outside the configured scope; checks targeting it will be refused."`.
- Per-host result line: two-space indent (visually subordinate to the batch
  header, consistent with how `cmd_targets` indents its table rows under a
  header), `f"  {host}: ran {len(results)} check(s), {findings} finding(s), {steps} path step(s)"`.
- Per-host no-result line: `f"  {host}: no checks applicable"` — satisfies
  Requirement 6.3 (every target gets a line, none silently omitted).
- Evidence-error line: `f"  {host}: (could not write evidence: {exc})"` — same
  message body as `_run_scan`'s `f"(could not write evidence: {exc})"`, with
  the two-space/host prefix added since multiple hosts could each fail
  independently and the operator needs to know which one.
- Aggregate summary: two lines, blank line before them to visually separate
  from the per-host block, then totals and the same two closing lines
  `_run_scan` already prints (paths-hint or no-path guidance), printed
  exactly once — satisfying Requirement 6.4/6.5.
- Empty-targets message (Requirement 9.1): `"No targets to scan. Use 'targets' to check the loaded target list."`, printed before anything else and before any call to `scan_targets`.

### 4. Help text

`cmd_help`'s "Scanning:" block (around line 237) gains one line directly
after the existing `scan [check]` line:

```python
print("Scanning:")
print("  scan [check]         Run checks (all or specific check name)")
print("  scanall [check]      Run checks against every loaded target")
print("  rescan               Re-run all checks with current capabilities")
```

Placed between `scan` and `rescan` since it's a closer sibling of `scan`
(both take an optional category) than of `rescan` (which takes none).

## Edge Cases

- **Empty `session.targets`** (Requirement 9.1): `_run_scan_all` returns
  immediately after printing the no-targets message; `scan_targets` is never
  called, `session.check_results`/`attack_paths` are untouched (this is a
  purely theoretical case in practice, since `Session.__post_init__` always
  seeds `targets` with at least the active target — but the guard is cheap
  and matches the explicit requirement).
- **Single target** (Requirement 9.2): `scan_targets` already special-cases
  `len(targets) == 1` to skip spinning up a `ThreadPoolExecutor` and call
  `scan_target` directly (see `scan.py` lines ~113-115); `_run_scan_all` does
  not need its own special case — the same per-host loop (now iterating one
  item) and the same aggregate summary print unconditionally, so output shape
  stays identical regardless of target count, as required.
- **A host whose category doesn't apply to its auth state** (e.g.
  `scanall authenticated` against an unauthenticated-only target): `_phases`
  yields nothing for that host, so `scan_target` returns `[]`, `per_host[host]
  == []`, and the per-host loop prints the "no checks applicable" line and
  `continue`s without touching `session.check_results` for that host (no
  stale-result deletion happens either, which is correct — there is nothing
  fresh to replace stale entries with, so prior results for that host/category
  combination, if any existed from an earlier run with a different category
  filter, are left alone rather than wiped by an empty replacement set).
- **A host whose scan raises inside the worker pool**: `scan_targets` already
  wraps this per `Requirement 3`/the existing `except Exception` block in
  `scan.py`'s `scan_targets`, producing `[CheckResult(name="scan", category="scan", error="scan failed: ...")]` for that host. `_run_scan_all` treats this
  like any other non-empty result list: it merges it (replacing any prior
  `("scan", "scan")` entry for that host), counts it in `total_checks` (1
  check, 0 findings, 0 steps), and prints the normal per-host summary line —
  the error text itself is not printed on its own line by `_run_scan_all`,
  but it is visible via `show findings`/the merged `CheckResult.error` field,
  consistent with how a single-target scan error surfaces today (`_run_scan`
  does not special-print `CheckResult.error` either; it only special-cases a
  *raised* exception escaping `scan_target` itself, which is the "Scan
  error: ..." message. This design keeps that same split: an exception
  escaping `scan_targets` itself -> `"Scan error: {exc}"` and an early
  `return`; a per-host wrapped error inside the returned dict -> merged
  silently into results like any other `CheckResult`).
- **Evidence write failure for one host does not abort the others**: the
  `try/except OSError` is inside the per-host loop body, so a failure writing
  host A's evidence prints that host's error line and the loop proceeds to
  host B; this matches Requirement 7.2 exactly.
- **Duplicate hosts in `session.targets`** (not explicitly required, but
  possible if the operator's target list has two `Target` objects with the
  same `.host`): `scan_targets`' returned dict is keyed by host string, so a
  duplicate host is scanned once and both `Target` entries in the loop read
  the same `per_host[host]` entry, printing the same summary line twice and
  merging the same fresh keys twice (the second merge is a no-op since the
  first merge already removed the stale `(name, category)` entries and added
  the fresh ones, and re-adding the same `CheckResult` objects via
  `add_results` a second time would double-count findings). This is an
  existing ambiguity in `session.targets` itself (nothing today prevents
  duplicate hosts, and `cmd_targets`/`target <id>` already don't deduplicate),
  so it is explicitly not fixed here — introducing host de-duplication would
  be a behavior change to `session.targets` beyond this feature's scope, and
  is not called out in the requirements.

## Data Models

This feature introduces no new persisted data model, dataclass, or schema. It
reuses existing types unchanged:

- `domainerator.runner.Target` — read from `session.targets`; never mutated
  or constructed by this feature.
- `domainerator.runner.CheckResult` — produced by `scan.scan_target` (via
  `scan.scan_targets`) exactly as it is today for single-target scans; no new
  fields are added, and the design explicitly does not add a `host` field to
  it (see the "where host-by-host replace-merge happens" decision above) —
  host association is tracked procedurally via the `dict[str, list[CheckResult]]`
  that `scan_targets` already returns, not by extending the dataclass.
- `domainerator.scan.ScanOptions` — one instance is built per `scanall`
  invocation, identical in shape and construction to the one `_run_scan`
  builds today; no new fields.
- `domainerator.console.session.Session` — no new fields. `check_results`,
  `capabilities`, `attack_paths`, `target`, `targets`, and `evidence` are all
  read/updated through existing methods (`add_results`, `recompute_paths`,
  `evidence.write_results`); `target` is read-only from this feature's
  perspective.

Because no new state is introduced, there is nothing new to persist, migrate,
or version — `scanall`'s output is entirely a different way of populating the
same `Session` fields that `scan`/`rescan` already populate, so saved session
state (`save`/`--state`) round-trips through the existing `State`/session
serialization unchanged.

## Correctness Properties

A property is a characteristic or behavior that should hold true across all valid executions of a system — a formal statement about what the system should do, independent of any particular test case.

### Property 1: Per-host replace-not-append merge

For any host scanned by `scanall`, after the merge step, `session.check_results` contains no two entries with the same `(name, category)` key that both originated from that host — the fresh result for a given `(name, category)` always fully replaces any prior one for that same host, never accumulating duplicates across repeated `scanall` runs.

**Validates: Requirements 4.1**

### Property 2: Result-count conservation

For any `scanall` invocation, the number of `CheckResult` entries added to `session.check_results` for a given host equals exactly the number of entries `scan_targets` returned for that host (no silent drops, no duplication), except where an identical `(name, category)` pair already existed for that host before the run, in which case the old entry is removed before the new one is added — so the net count change per host equals the fresh count minus the number of stale entries it replaced.

**Validates: Requirements 4.1, 4.2**

### Property 3: Single recomputation produces the same result as per-host recomputation

For any sequence of per-host merges performed by `scanall`, calling `session.recompute_paths()` exactly once after all merges complete yields an `attack_paths` value identical to what would result from calling it after each individual host's merge — because `recompute_paths` is a pure function of the accumulated `check_results` list and does not depend on the order or granularity in which that list was assembled.

**Validates: Requirements 4.3, 4.4**

### Property 4: Active target invariance

For any `scanall` invocation, regardless of success, partial failure, or the empty-targets case, `session.target` after the call is the same object identity as `session.target` before the call.

**Validates: Requirements 8.1, 8.2**

### Property 5: Per-host failure isolation

For any `scanall` invocation where one or more hosts' scans raise inside the worker pool, every other host's results are still merged into the session, evidence is still attempted for every host, and the aggregate summary still reflects all successfully-scanned hosts — a single host's failure never causes another host's results to be dropped or the method to return early.

**Validates: Requirements 3.1, 3.2, 3.3**

### Property 6: No target is silently omitted from output

For any non-empty `session.targets`, every host appears in the printed output exactly once — either as a per-host result-count line or as a "no checks applicable" line — so the number of per-host output lines always equals `len(session.targets)`.

**Validates: Requirements 6.3**

## Error Handling

| Operation | Failure condition | Recoverable? | What the caller/operator sees | Logged? |
|---|---|---|---|---|
| `scan_targets(...)` call itself raising | A bug outside the worker pool (e.g. bad `ScanOptions`, programming error in `_phases`) | Fatal to this invocation of `scanall`, not to the console | `print(f"Scan error: {exc}")`, method returns; `session.check_results`/`attack_paths` unchanged (no partial merge occurred since the loop that merges runs after this call returns successfully) | Printed only (console has no logging framework; matches `_run_scan`'s identical handling) |
| One host's scan raising inside the worker pool | Network failure, tool crash, unexpected exception in a check module for that host | Recoverable — isolated by `scan_targets`' own `except Exception` | That host's entry in `per_host` is `[CheckResult(name="scan", category="scan", error="scan failed: {exc}")]`; merged and counted normally, visible via `show findings`'s `error` column indirectly (findings list is empty, but the check is counted) and via any future `show results`-style inspection of `CheckResult.error` | Not separately logged; the error text lives in the merged `CheckResult.error` field for later inspection (`report`, `show findings`) |
| `session.evidence.write_results(...)` raising `OSError` for one host | Disk full, permissions, bad path | Recoverable — caught per host, loop continues | `print(f"  {host}: (could not write evidence: {exc})")`; evidence for other hosts still attempted | Printed only |
| Target out of scope | `scope.active` and `not scope.contains(host)` | Not an error — a warning; the actual refusal happens later inside `ToolRunner` per command | `print(f"WARNING: {host} is outside the configured scope; checks targeting it will be refused.")`; batch still proceeds (Requirement 5.2/5.3) | Printed only |
| Unknown category argument | `args[0].lower()` not in `_SCAN_CATEGORIES` | N/A — rejected before any scan starts | `print(f"Unknown category: {category}")` + categories list; method returns without scanning | Printed only |
| Empty `session.targets` | No targets loaded | N/A | `print("No targets to scan. Use 'targets' to check the loaded target list.")`; method returns | Printed only |

Validation of the `<category>` argument happens entirely in `cmd_scanall`
before `_run_scan_all` is ever called, reusing the existing `_SCAN_CATEGORIES`
tuple and the same two print lines `cmd_scan` already uses — there is exactly
one place that owns this validation (`cmd_scanall`), consistent with how
`cmd_scan` already owns it for the single-target command.

## Testing Strategy

Existing console tests live in `tests/test_console.py`; this feature's tests
belong there, following whatever fixture pattern that file already uses to
build a `Session`/`Console` with a fake/mocked `ToolRunner`.

**Unit-testable (mock `scan.scan_targets` directly, avoid real subprocesses):**
- `cmd_scanall([])` with no category calls `_run_scan_all(None)`; `cmd_scanall(["adcs"])` calls `_run_scan_all("adcs")`.
- `cmd_scanall(["bogus"])` prints the unknown-category message and does not call `_run_scan_all` at all (patch `_run_scan_all` and assert not called).
- `_run_scan_all` with `session.targets == []` prints the no-targets message and does not call `scan_targets` (patch/mock it and assert not called).
- `_run_scan_all` with a single target still prints both a per-host line and an aggregate summary (Requirement 9.2) — mock `scan_targets` to return a one-host dict and check both prints appear.
- Merge/replace semantics: seed `session.check_results` with a stale `CheckResult(name="x", category="unauthenticated")` tagged (via test bookkeeping) as belonging to host A; mock `scan_targets` to return a fresh `CheckResult` with the same `(name, category)` for host A; assert the stale one is gone and only the fresh one remains after `_run_scan_all` runs, and that an untouched result for a different host (not present in `per_host`) survives unchanged.
- `recompute_paths` call count: patch `session.recompute_paths` and assert it is called exactly once per `_run_scan_all` invocation regardless of how many hosts were in `per_host` (e.g. 3 hosts -> still 1 call).
- `session.target` identity: capture `id(session.target)` (or the object itself) before calling `_run_scan_all`, assert it is unchanged after, for both the success and the per-host-error paths.
- Evidence calls: mock `session.evidence` and assert `write_results(results, target=host)` is called once per host with that host's exact result list, and that a mocked `OSError` on one host's call doesn't prevent the call for the next host.
- Scope warning: configure a `Scope` with `active=True` and a host list that excludes one target's host; assert the warning line is printed for only that host, and that `scan_targets` is still called with the full target list (not a filtered one).
- Aggregate totals: mock `scan_targets` to return known finding/step counts across 3 hosts and assert the printed aggregate line's numbers equal the arithmetic sum.
- `cmd_help` includes a `scanall` line (simple substring check on captured stdout).
- Tab completion: completing a partial command string that matches `scanall`'s prefix returns it from `self.commands`-derived completions (can be tested by calling the completer function directly, as any existing command-completion test presumably already does for `scan`/`rescan`).

**Integration-testable (exercise the real `scan.scan_targets`, no mocking of it, but keep the underlying `ToolRunner.run` faked/stubbed as the rest of the test suite already does for `scan_target`/check-module tests):**
- End-to-end `scanall` against 2-3 fake targets with a stubbed `ToolRunner` that returns canned tool output, verifying real concurrency doesn't produce duplicate or missing results versus running `scan`/`target` sequentially for each host by hand (compare the final `session.check_results`/`capabilities`/`attack_paths` from a `scanall` run to the same session built by looping `target <id>` + `scan` manually).
- A host whose stubbed `ToolRunner` raises inside a check module to confirm the real (non-mocked) `scan_targets` wrapping produces the error `CheckResult`, and that the batch's other hosts still get full results and the aggregate summary still prints.

This maps directly onto a tasks list that: (1) adds `cmd_scanall`/registers it, (2) adds `_run_scan_all`'s header/scope-warning/empty-targets handling, (3) adds the `scan_targets` call and per-host merge loop, (4) adds evidence writing, (5) adds the aggregate summary and help text line, (6) adds the unit tests above, (7) adds the one or two integration tests above — each a independently committable, testable increment.
