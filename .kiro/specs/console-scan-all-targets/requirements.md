# Requirements Document

## Introduction

This document specifies requirements for a new interactive-console command that scans every loaded target in one step, instead of requiring the operator to manually run `target <id>` followed by `scan` (or `rescan`) for each host. The console already tracks multiple targets (`session.targets`) and already has a concurrent multi-host scan primitive (`scan_targets` in `scan.py`) that the CLI uses for its initial batch pass; this feature exposes that same capability from inside the console, after the console has launched, merging results the same way the existing single-target `scan`/`rescan` commands do.

## Glossary

- **Console**: The Domainerator interactive REPL that provides command-line access to scanning, exploitation, and session management features
- **Session**: Runtime state (`domainerator.console.session.Session`) tracking the operator's targets, active target, accumulated check results, capabilities, and attack paths
- **Target**: A single host/credential combination (`domainerator.runner.Target`) the console can run checks against
- **Active_Target**: `session.target`, the one target that single-target commands (`scan`, `rescan`, `target <id>`) currently operate on
- **Check_Result**: `domainerator.runner.CheckResult`, the output of one check module run against one target, carrying findings, path steps, and optional error
- **Category**: One of the four check groups: `unauthenticated`, `authenticated`, `adcs`, `sccm`
- **Scan_Options**: `domainerator.scan.ScanOptions`, the per-run configuration (timeout and per-category skip flags) built from a requested category
- **Scope**: `domainerator.runner.Scope`, an optional allow-list of hosts/subnets; the `ToolRunner` refuses commands against out-of-scope hosts
- **Batch_Scan_Command**: The new console command introduced by this feature, which scans all targets in `session.targets`

## Requirements

### Requirement 1: Command to scan all loaded targets

**User Story:** As a pentester running the console against several hosts, I want one command that scans every loaded target, so that I don't have to manually `target <id>` + `scan` through each host.

#### Acceptance Criteria

1. THE Console SHALL register a new top-level command named `scanall` that is accepted alongside the existing `scan`, `rescan`, `target`, and `targets` commands.
2. WHEN the operator runs `scanall` with no arguments, THE Batch_Scan_Command SHALL run all applicable checks (gated by each target's `authenticated` state, exactly as `scan_target`/`_phases` already decide) against every target in `session.targets`.
3. WHEN the operator runs `scanall <category>` with `<category>` equal to one of `unauthenticated`, `authenticated`, `adcs`, `sccm`, THE Batch_Scan_Command SHALL run only that category's checks against every target.
4. IF the operator runs `scanall <category>` with a category not in the known list, THEN THE Console SHALL print an "Unknown category" message listing the valid categories (matching the existing `cmd_scan` behavior) and SHALL NOT run any scans.
5. THE Batch_Scan_Command's docstring/help text SHALL document both usage forms (`scanall` and `scanall <category>`), consistent with how `cmd_scan`'s docstring documents `scan` / `scan <category>`.

### Requirement 2: Reuse existing concurrent scan infrastructure

**User Story:** As a maintainer, I want the batch command to reuse the existing multi-host scan function, so that concurrency, worker limits, and per-host error isolation behave consistently with the CLI's own batch scan and don't duplicate that logic.

#### Acceptance Criteria

1. THE Batch_Scan_Command SHALL build a `ScanOptions` instance using `session.runner.timeout` and the requested category's skip flags, the same way `_run_scan` does today.
2. THE Batch_Scan_Command SHALL execute the scan via `domainerator.scan.scan_targets(session.runner, session.targets, opts, max_workers=5, tracker=...)` (or an equivalent call to the same function) rather than looping over targets and calling `scan_target` sequentially.
3. THE Batch_Scan_Command SHALL use a worker limit of 5, matching the CLI's default (`args.workers` defaults to 5) and `scan_targets`' own default, so console and CLI batch behavior stay consistent. A future enhancement may expose this as a configurable argument; this is out of scope here (see Out of Scope).
4. IF `scan_targets` raises an exception that escapes its own per-host isolation (e.g., a programming error outside the worker pool), THEN THE Batch_Scan_Command SHALL catch it, print a message in the form `f"Scan error: {exc}"` (consistent with `_run_scan`), and leave session state unchanged for hosts that had not yet been merged.

### Requirement 3: Per-host failure isolation

**User Story:** As a pentester scanning many hosts, I want one unreachable or erroring host to not abort the whole batch, so that I still get results for every host that succeeded.

#### Acceptance Criteria

1. WHEN one target's scan raises an exception inside the worker pool, THE Batch_Scan_Command SHALL still receive and process results for all other targets, relying on `scan_targets`' existing per-host exception wrapping (which records an error `CheckResult` for that host instead of raising).
2. WHEN a host's result list contains an error `CheckResult` (from a wrapped exception), THE Batch_Scan_Command SHALL still merge it into the session like any other result and SHALL surface the error in that host's per-host summary line rather than silently dropping it.
3. THE Batch_Scan_Command SHALL NOT let a single host's failure prevent `recompute_paths()` or the final aggregate summary from running.

### Requirement 4: Result merging and path recomputation

**User Story:** As a pentester, I want fresh scan results merged correctly per host, so that re-running `scanall` doesn't duplicate stale findings and attack paths reflect everything just discovered.

#### Acceptance Criteria

1. FOR EACH target scanned, THE Batch_Scan_Command SHALL drop prior `session.check_results` entries whose `(name, category)` matches one of that target's fresh result keys, before adding the fresh results — the same per-host replace-not-append semantics `_run_scan` applies to the active target today. Because `CheckResult` does not carry a host field, this requires scanning and replacing per host using the host-keyed `dict[str, list[CheckResult]]` returned by `scan_targets` (e.g., tracking which prior results belong to each host via the evidence/host association already used when results are produced, or by processing one host's fresh/stale replacement at a time before merging the next).
2. THE Batch_Scan_Command SHALL call `session.add_results(...)` to union in every host's fresh results and their capabilities.
3. THE Batch_Scan_Command SHALL call `session.recompute_paths()` exactly once, after all hosts' results have been merged — not once per host — to avoid redundant path-engine recomputation across a potentially large target list. This differs from doing it per-host, but is justified because attack paths are derived from the full accumulated `check_results` regardless of order, so a single recomputation at the end produces the same final path set as N recomputations with less wasted work.
4. AFTER the batch completes, THE Session's `capabilities` and `attack_paths` SHALL reflect the combined results of every target scanned in that batch, in the same way they would if the operator had manually run `target <id>` + `scan` for each host in sequence.

### Requirement 5: Scope handling

**User Story:** As a pentester operating under a defined engagement scope, I want out-of-scope targets handled safely during a batch scan, so that I don't violate scope and I understand why a host produced no results.

#### Acceptance Criteria

1. IF `session.runner.scope` is configured and active, THEN BEFORE scanning, THE Batch_Scan_Command SHALL check each target in `session.targets` against `scope.contains(target.host)`.
2. IF a target is out of scope, THEN THE Batch_Scan_Command SHALL print a warning identifying that host (consistent in wording with `_run_scan`'s existing single-target scope warning) and SHALL still include that host in the call to `scan_targets`, relying on the runner's existing per-command scope enforcement to refuse the actual tool invocations — this matches today's single-target `_run_scan` behavior (warn, don't pre-block) rather than introducing new scope-skipping logic that doesn't exist elsewhere in the console.
3. THE Batch_Scan_Command SHALL NOT crash or abort the batch because one or more targets are out of scope; refused checks surface as `CheckResult` errors/empty results exactly as they do for a single out-of-scope target today.

### Requirement 6: Output and summaries

**User Story:** As a pentester scanning many hosts, I want readable per-host and aggregate output, so that a large target list doesn't produce an unreadable wall of text.

#### Acceptance Criteria

1. WHEN the batch starts, THE Batch_Scan_Command SHALL print a header line stating how many targets will be scanned and which category (or "all applicable").
2. FOR EACH host, once its results are available, THE Batch_Scan_Command SHALL print one concise summary line containing the host, the number of checks run, the number of findings, and the number of path steps (a single line per host, not the full per-check detail `_run_scan` prints for a single target).
3. IF a host produced zero results (category not applicable to its auth state), THEN THE Batch_Scan_Command SHALL print a one-line note for that host (e.g., "no checks applicable") rather than omitting it silently, so the operator can account for every target in the output.
4. AFTER all hosts are processed, THE Batch_Scan_Command SHALL print one aggregate summary containing: total targets scanned, total findings across all hosts, total path steps across all hosts, total capability count, and total attack-path count (mirroring the two summary lines `_run_scan` prints today, but totaled across hosts instead of one host).
5. THE Batch_Scan_Command SHALL print the aggregate summary's attack-path hint ("Use 'show paths' to view them." or the no-path guidance) exactly once, after the aggregate totals, not once per host.

### Requirement 7: Evidence capture

**User Story:** As a pentester with an evidence folder configured, I want batch-scanned results captured the same way single-target scans are, so that my evidence trail stays complete regardless of which command produced the results.

#### Acceptance Criteria

1. IF `session.evidence` is configured, THEN FOR EACH host scanned, THE Batch_Scan_Command SHALL call `session.evidence.write_results(results, target=host)` with that host's fresh results, matching the per-host call `_run_scan` already makes for the active target.
2. IF `session.evidence.write_results` raises an `OSError` for one host, THEN THE Batch_Scan_Command SHALL print a message in the form `f"(could not write evidence: {exc})"` for that host and SHALL continue writing evidence for the remaining hosts rather than aborting.

### Requirement 8: Active target is left unchanged

**User Story:** As a pentester, I want my active target to stay the same after a batch scan, so that the batch command doesn't silently change what subsequent single-target commands (`scan`, `use`, etc.) operate on.

#### Acceptance Criteria

1. AFTER `scanall` completes (successfully or with partial per-host failures), `session.target` SHALL be identical (same object/identity) to whatever it was before the command ran.
2. THE Batch_Scan_Command SHALL NOT call `session.switch_target(...)` or otherwise reseed command variables as a side effect of scanning non-active targets.

### Requirement 9: Behavior with zero or one target

**User Story:** As a pentester who has only loaded one host, I want `scanall` to behave sensibly rather than erroring or printing confusing batch output.

#### Acceptance Criteria

1. IF `session.targets` is empty, THEN THE Batch_Scan_Command SHALL print a message stating there are no targets to scan and SHALL NOT invoke `scan_targets`.
2. IF `session.targets` contains exactly one target, THEN THE Batch_Scan_Command SHALL still run (delegating to `scan_targets`, which already handles the single-target case without spinning up a thread pool) and SHALL print the same per-host and aggregate summary format as the multi-target case, so behavior stays predictable regardless of target count.

## Out of Scope

- Making the worker/concurrency limit (`max_workers=5`) configurable via a command argument or session setting.
- Adding scope-based pre-filtering/skipping of targets before scanning (current behavior across the console is warn-then-let-the-runner-refuse, not pre-skip); introducing true skip semantics is a separate decision.
- Changing `scan_target`, `scan_targets`, or `CheckResult` to carry an explicit host field; the merge logic works around this using the existing host-keyed dict returned by `scan_targets`.
- A `rescanall` variant or any way to re-run only previously-failed hosts from a prior `scanall` batch.
- Progress UI beyond the per-host/aggregate print lines described above (e.g., a live progress bar); `ProgressTracker`/`KeypressStatus` wiring, if used, follows existing console conventions and is an implementation detail for the design phase, not a new requirement.
- Parallelizing evidence writes; they remain sequential per host as results arrive.
