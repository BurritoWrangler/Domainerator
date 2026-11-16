# Implementation Plan

## Overview

Implements the `scanall` console command: a new `cmd_scanall` method and
`_run_scan_all` helper in `src/domainerator/console/console.py` that scan
every loaded target via `domainerator.scan.scan_targets`, merging results
per host the same way the existing `scan`/`rescan` commands do for the
active target, writing evidence per host, and printing per-host plus
aggregate summaries. Tasks are ordered to build the method incrementally
(command registration, then scaffolding, then the scan/merge core, then
evidence/summary, then help text) before adding unit and integration tests.

## Task Dependency Graph

```
1. cmd_scanall + registration
       │
       ▼
2. _run_scan_all skeleton (empty-targets guard, header, scope warnings, ScanOptions)
       │
       ▼
3. scan_targets call + per-host merge loop + single recompute_paths()
       │
       ▼
4. Evidence writing + aggregate summary
       │
       ▼
5. Help text line
       │
       ▼
6. Unit tests (tasks 1-5 behavior)
       │
       ▼
7. Integration tests (real scan_targets, stubbed ToolRunner)
```

Tasks 1-5 are strictly sequential (each extends the method the previous task
started or depends on it being registered/callable). Tasks 6 and 7 both
depend on all of 1-5 being complete, but are independent of each other and
could be parallelized if dispatched separately; they are listed sequentially
here since both touch the same test file.

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2"] },
    { "id": 2, "tasks": ["3"] },
    { "id": 3, "tasks": ["4"] },
    { "id": 4, "tasks": ["5"] },
    { "id": 5, "tasks": ["6", "7"] }
  ]
}
```

## Tasks

- [ ] 1. Add `cmd_scanall` command method and register it in the command table
  - Add `cmd_scanall(self, args: list[str]) -> None` to `Console` in
    `src/domainerator/console/console.py`, placed directly after
    `cmd_rescan` (around line 1286). Parse an optional `<category>` argument,
    validate it against `self._SCAN_CATEGORIES`, print the existing
    "Unknown category" + categories-list message and return early on an
    invalid category (same two print lines `cmd_scan` uses), otherwise call
    `self._run_scan_all(category)`. Give it a docstring documenting both
    usage forms (`scanall` and `scanall <category>`) as specified in the
    design's Component 1.
  - Add `"scanall": self.cmd_scanall,` to the `self.commands` dict in
    `__init__`, immediately after the existing `"rescan": self.cmd_rescan,`
    entry.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  - Files: `src/domainerator/console/console.py`
  - Verify: `pytest -q tests/test_console.py` still passes (no new tests yet;
    this only confirms the file still imports and existing console tests are
    unaffected). `ruff check src/domainerator/console/console.py` passes.

- [ ] 2. Add `_run_scan_all` skeleton: empty-targets guard, header, and scope warnings
  - Add `_run_scan_all(self, category: str | None) -> None` to `Console` in
    `src/domainerator/console/console.py`, placed directly after `_run_scan`
    (after its evidence-write block, before `cmd_save`). Implement, in
    order: (a) snapshot `targets = self.session.targets`; (b) if `targets`
    is empty, print `"No targets to scan. Use 'targets' to check the loaded
    target list."` and return before doing anything else (Requirement 9.1);
    (c) print a blank line then the header line
    `f"Running {label} checks against {len(targets)} target(s): " + ", ".join(t.host for t in targets)`
    where `label = category or "all applicable"`; (d) if
    `self.session.runner.scope is not None and self.session.runner.scope.active`,
    loop over `targets` and print
    `f"WARNING: {t.host} is outside the configured scope; checks targeting it will be refused."`
    for each target that fails `scope.contains(t.host)`, without skipping
    any target from later processing.
  - Leave the rest of the method (the `scan_targets` call, merge loop,
    evidence, summary) for the next tasks — end this task's version of the
    method after the scope-warning block with a `pass` or a stub so the file
    stays syntactically valid and importable, OR implement the full
    `ScanOptions` construction here too since it has no dependency on later
    steps (recommended: include the `ScanOptions` construction at the end of
    this task, matching `_run_scan`'s identical construction, since it is
    pure setup with no merge/print side effects).
  - _Requirements: 2.1, 5.1, 5.2, 5.3, 6.1, 9.1_
  - Files: `src/domainerator/console/console.py`
  - Verify: `pytest -q tests/test_console.py` passes. Manually confirm via a
    quick interactive check or a temporary test that calling
    `console._run_scan_all(None)` with `session.targets == []` prints the
    no-targets message and does not raise. `ruff check src/domainerator/console/console.py` passes.

- [ ] 3. Wire the `scan_targets` call and per-host merge loop
  - In `_run_scan_all`, after the `ScanOptions` construction from task 2,
    import `scan_targets` from `..scan` (local import, matching `_run_scan`'s
    own `from ..scan import ScanOptions, scan_target` pattern) and call
    `per_host = scan_targets(self.session.runner, targets, opts, max_workers=5)`
    inside a `try/except Exception as exc` block; on exception, print
    `f"Scan error: {exc}"` and return (Requirement 2.4), leaving
    `session.check_results`/`attack_paths` untouched since no merge has
    happened yet.
  - After the call succeeds, loop over `targets` in `session.targets` order
    (not `per_host` dict order) and, for each host: look up
    `results = per_host.get(host, [])`; if empty, print
    `f"  {host}: no checks applicable"` and `continue` (Requirement 6.3,
    9.2 — no stale-result deletion on an empty result set, per the design's
    edge-case note); otherwise compute
    `fresh_keys = {(r.name, r.category) for r in results}`, filter
    `self.session.check_results` to drop entries whose `(name, category)` is
    in `fresh_keys`, call `self.session.add_results(results)`, and print the
    per-host summary line
    `f"  {host}: ran {len(results)} check(s), {findings} finding(s), {steps} path step(s)"`
    where `findings = sum(len(r.findings) for r in results)` and
    `steps = sum(len(r.path_steps or []) for r in results)`.
  - Accumulate `total_checks`, `total_findings`, `total_steps` across hosts
    for use in task 4's aggregate summary.
  - After the loop, call `self.session.recompute_paths()` exactly once
    (Requirement 4.3).
  - _Requirements: 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 6.2, 6.3, 8.1, 8.2_
  - Files: `src/domainerator/console/console.py`
  - Verify: `pytest -q tests/test_console.py` passes. `ruff check src/domainerator/console/console.py` passes.

- [ ] 4. Add per-host evidence writing and the aggregate summary
  - Inside the per-host merge loop from task 3, immediately after
    `self.session.add_results(results)` and the per-host print line, add:
    if `self.session.evidence is not None`, call
    `self.session.evidence.write_results(results, target=host)` inside a
    `try/except OSError as exc` block; on failure print
    `f"  {host}: (could not write evidence: {exc})"` and continue the loop
    (do not abort remaining hosts) (Requirement 7.1, 7.2).
  - After `recompute_paths()`, print the aggregate summary: a blank line,
    then
    `f"Scanned {len(targets)} target(s): {total_checks} check(s) total, {total_findings} finding(s), {total_steps} path step(s)."`,
    then
    `f"Capabilities: {len(self.session.capabilities)}  Attack paths: {len(self.session.attack_paths)}"`,
    then `"Use 'show paths' to view them."` if
    `self.session.attack_paths` else the no-path guidance line `_run_scan`
    already prints (match its exact wording) — printed exactly once total
    (Requirement 6.4, 6.5).
  - _Requirements: 6.4, 6.5, 7.1, 7.2_
  - Files: `src/domainerator/console/console.py`
  - Verify: `pytest -q tests/test_console.py` passes. `ruff check src/domainerator/console/console.py` passes.

- [ ] 5. Add the `scanall` help text line
  - In `cmd_help` (around line 237, the "Scanning:" block in
    `src/domainerator/console/console.py`), add
    `print("  scanall [check]      Run checks against every loaded target")`
    directly between the existing `scan [check]` line and the `rescan` line.
  - _Requirements: 1.5_
  - Files: `src/domainerator/console/console.py`
  - Verify: `pytest -q tests/test_console.py` passes; manually run
    `python -c "from domainerator.console.console import Console; ..."`-style
    check is unnecessary — the unit test added in task 6 covers this.

- [ ] 6. Add unit tests for `cmd_scanall` and `_run_scan_all`
  - Add tests to `tests/test_console.py`, following the existing
    `_ScanFakeRunner`/`Session`/`Console` fixture pattern used by
    `test_scan_command_runs_checks_and_recomputes`,
    `test_rescan_does_not_duplicate_results`, and
    `test_scan_rejects_unknown_category`. Cover:
    - `cmd_scanall([])` with no category invokes `_run_scan_all(None)`, and
      `cmd_scanall(["adcs"])` invokes `_run_scan_all("adcs")` (patch
      `console._run_scan_all` and assert call args).
    - `cmd_scanall(["bogus"])` prints "Unknown category" (via `capsys`) and
      does not call `_run_scan_all` (patch it and assert not called).
    - `_run_scan_all` with `session.targets == []` prints the no-targets
      message and does not call `scan.scan_targets` (monkeypatch it in the
      `domainerator.scan` module and assert not called).
    - `_run_scan_all` with a single target (reusing `_ScanFakeRunner`,
      one `Target`) prints both a per-host line and the aggregate summary.
    - Merge/replace semantics: seed `session.check_results` with a stale
      `CheckResult` sharing `(name, category)` with a fresh result the fake
      scan produces for one host; after `_run_scan_all` runs, assert the
      stale entry is gone and the fresh one is present, and that a result
      belonging to a host not present in the fresh batch is left untouched.
    - `session.recompute_paths` call count is exactly 1 regardless of host
      count (patch it on the session instance, use 3 targets via
      `_ScanFakeRunner`, assert `call_count == 1`).
    - `session.target` identity is unchanged before vs. after
      `_run_scan_all`, including when a host's scan raises inside
      `scan_targets` (simulate via a responder/monkeypatch that raises).
    - Evidence: provide a stub `session.evidence` object recording
      `write_results` calls; assert it is called once per host with that
      host's exact result list, and that one host raising `OSError` doesn't
      prevent the call for the next host.
    - Scope warning: configure `runner.scope` (`active=True`, excluding one
      target's host) and assert the warning line prints for only that host,
      while `scan_targets` is still invoked with the full target list.
    - Aggregate totals: use a fake scan producing known finding/step counts
      across multiple hosts and assert the printed aggregate numbers equal
      the arithmetic sum.
    - `cmd_help([])` output (via `capsys`) contains a `scanall` substring.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.4, 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 7.2, 8.1, 8.2, 9.1, 9.2_
  - Files: `tests/test_console.py`
  - Verify: `pytest -q tests/test_console.py` — all new and existing tests
    pass.

- [ ] 7. Add integration test(s) exercising the real `scan_targets`
  - Add one or two tests to `tests/test_console.py` (or a new
    `tests/test_console_scanall_integration.py` if that keeps the file more
    readable — follow whichever the project's existing file-granularity
    convention favors, consistent with the single `tests/test_console.py`
    already covering `scan`/`rescan`) that do **not** mock
    `domainerator.scan.scan_targets` itself, only the underlying
    `ToolRunner.run` (via `_ScanFakeRunner` or equivalent), covering:
    - End-to-end `scanall` against 2-3 fake targets with stubbed tool
      output, asserting the final `session.check_results`/`capabilities`/
      `attack_paths` match what manually looping `target <id>` + `scan` for
      each host produces.
    - A host whose stubbed runner raises inside a check module, confirming
      the real `scan_targets` error-wrapping produces an error
      `CheckResult` for that host while the other hosts still get full
      results and the aggregate summary still prints.
  - _Requirements: 2.2, 3.1, 3.2, 3.3, 4.4_
  - Files: `tests/test_console.py`
  - Verify: `pytest -q tests/test_console.py` — all tests pass. Then run the
    full suite with `pytest -q` and `ruff check .` to confirm the feature is
    complete and nothing else regressed.
## Notes

- No new modules or data models are introduced; everything lives in
  `src/domainerator/console/console.py` and `tests/test_console.py`, reusing
  `domainerator.scan.scan_targets`, `ScanOptions`, and existing `Session`
  methods unchanged (see design.md's Data Models section).
- Each task's "Verify" step should be run before moving to the next task;
  tasks 1-5 only need `ruff check` and a no-regression `pytest` pass since
  their dedicated tests arrive in tasks 6-7.
- After task 7, run the full suite (`pytest -q` and `ruff check .`) to
  confirm no regressions elsewhere in the console or scan modules.
