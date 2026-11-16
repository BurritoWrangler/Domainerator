# Requirements Document

## Introduction

Users scanning hosts with null-session (unauthenticated, `-u "" -p ""`) NetExec
checks are seeing `inconclusive` results on every hardened host, even though
the scan ran correctly and got a definitive, informative answer: the target
refused the anonymous probe with `STATUS_ACCESS_DENIED`. This happens because
`looks_like_failure()` in `src/domainerator/checks/__init__.py` lumps two very
different situations into one flat `_FAILURE_SIGNALS` list:

1. Genuine connectivity/protocol failures (connection refused, timed out, no
   route to host) where the tool never got far enough to say anything about
   the target - correctly inconclusive.
2. A successful connection where the target *affirmatively rejected* the null
   session/anonymous probe (`access_denied`, `STATUS_ACCESS_DENIED`,
   `STATUS_LOGON_FAILURE`) - this is itself a result (anonymous access is
   blocked / hardened), not an unknown.

Any check in this codebase that sends a null-session probe (`-u "" -p ""`) and
finds no vulnerability currently gets marked `inconclusive` whenever either
signal appears in the output, producing a reported false positive / noisy
finding on essentially every hardened host for every affected check. This spec
defines how to split those two situations so that genuine failures still
report `inconclusive` while a definitive access-denied response to a null
probe is reported in a way that reflects what actually happened and stops
being noise.

## Glossary

- **Null session / anonymous probe**: An SMB/LDAP connection attempt using
  `-u "" -p ""` (no credentials), used by unauthenticated checks to test
  whether anonymous access is permitted.
- **Connectivity failure**: The tool could not reach, negotiate with, or
  complete a protocol handshake with the target (e.g. connection refused,
  timed out, no route to host). The check result carries no information about
  the target's actual security posture.
- **Access-denied-to-null-probe**: The target was reached and responded, but
  explicitly refused the anonymous/null credential attempt
  (`STATUS_ACCESS_DENIED`, `STATUS_LOGON_FAILURE`, `access_denied`,
  `logon_failure`). This is a successful, informative scan outcome: anonymous
  access is not permitted.
- **`looks_like_failure()`**: Helper in `src/domainerator/checks/__init__.py`
  that scans tool output for any of a list of failure-indicating substrings.
- **`CheckResult.mark_inconclusive()`**: Method on `CheckResult`
  (`src/domainerator/runner.py`) that flags a check as inconclusive (only
  takes effect if no finding was already recorded).
- **Affected check**: A check function in `src/domainerator/checks/` that (a)
  issues a null-session probe (`-u "" -p ""`, unconditionally or as the
  anonymous-target fallback) and (b) calls `looks_like_failure()` on its
  output to decide whether a "nothing found" result should be
  `mark_inconclusive()`'d.

## Requirements

### Requirement 1: Distinguish connectivity failure from access-denied-to-null-probe

**User Story:** As a pentester scanning many hosts, I want checks that
successfully reach a hardened host and get a clear access-denied response to
an anonymous probe to not be reported as "inconclusive", so that I'm not
flooded with noise that a real connectivity problem would otherwise warn me
about.

#### Acceptance Criteria

1. THE system SHALL provide a classification function that, given check
   output, distinguishes "connectivity/protocol failure" from
   "access-denied-to-null-probe" from "no failure signal present", rather
   than returning one flat boolean/string covering both.
2. WHEN output contains only connectivity-failure signals (`connection
   refused`, `connection timed out` / `timed out`, `no route to host`,
   `unable to connect`, `could not connect`), THE system SHALL continue to
   mark the result `inconclusive` with a reason naming the signal.
3. WHEN output contains only access-denied-to-null-probe signals
   (`access_denied`, `status_access_denied`, `logon_failure`,
   `status_logon_failure`) and no connectivity-failure signal, THE system
   SHALL NOT mark the result `inconclusive` for that reason alone; the
   per-check handling defined in Requirement 2 applies instead.
4. WHEN output contains both a connectivity-failure signal and an
   access-denied signal, THE system SHALL treat the result as a connectivity
   failure (mark inconclusive) because the connectivity signal means the scan
   outcome is unreliable regardless of the access-denied text also present.
5. THE generic `[-]` NetExec "negative line" signal and `error`/`traceback`
   SHALL remain classified as failure-like (inconclusive-worthy) signals
   distinct from the specific access-denied/logon-failure signals, since a
   bare `[-]` or `error`/`traceback` does not by itself indicate the target
   gave a definitive access-denied answer.

### Requirement 2: Per-check handling of access-denied-to-null-probe

**User Story:** As a pentester, I want each unauthenticated check to report a
clear, specific outcome when a target refuses the null-session probe, so that
I know the probe ran and the target is hardened against it, instead of seeing
an ambiguous "inconclusive".

#### Acceptance Criteria

1. WHEN a check whose entire purpose is to test anonymous/null-session access
   (e.g. null session share enumeration, RID cycling, LDAP anonymous bind)
   receives an access-denied-to-null-probe response and finds no
   vulnerability, THE check SHALL report a `clean` result whose
   finding/evidence notes that the anonymous probe was explicitly refused
   (informative hardening signal), not an `inconclusive` result.
2. WHEN a check whose vulnerability detection does not depend on
   authentication succeeding (e.g. SMBGhost, EternalBlue, Zerologon,
   PrintNightmare/spooler detection, SMB signing banner, NTLMv1,
   NTLM-reflection, WebDAV/WebClient, Timeroasting) receives an
   access-denied-to-null-probe response with no vulnerability pattern matched,
   THE check SHALL report `clean` (or continue to the existing "no
   recognizable output" inconclusive branch when the banner/module fields it
   depends on are themselves absent), rather than `inconclusive` solely
   because of the access-denied text.
3. IF a check's own detection logic requires the null-session authentication
   step to have succeeded in order to say anything meaningful (none identified
   among current checks, but any future one), THEN that check SHALL remain
   `inconclusive` on access-denied, with a reason stating that authentication
   was required and refused.
4. ALL affected checks SHALL continue to report `inconclusive` when a genuine
   connectivity-failure signal is present, per Requirement 1.
5. THE per-check `inconclusive_reason` / finding evidence text SHALL make the
   distinction legible to the user: connectivity failures say the scan could
   not reach/complete; access-denied-to-null-probe outcomes say the target
   refused the anonymous probe.

### Requirement 3: Preserve or improve detection of genuine failures

**User Story:** As a pentester, I want genuine connectivity/timeout failures
to always be reported as inconclusive and never silently reported as "clean",
so that I don't mistake "the scan never ran" for "the target is not
vulnerable".

#### Acceptance Criteria

1. THE system SHALL NOT weaken detection of connectivity-failure signals:
   every signal currently in `_FAILURE_SIGNALS` that indicates a genuine
   failure to connect/authenticate for a reason other than the target
   actively refusing the probe (`connection refused`, `timed out`, `no route
   to host`, `unable to connect`, `could not connect`, `error`, `traceback`,
   `[-]`) SHALL still result in `inconclusive` when no finding was made.
2. WHEN a check parses no finding and the output matches neither a
   connectivity-failure signal nor an access-denied signal nor the check's own
   "recognizable output" pattern, THE check SHALL continue to report
   `inconclusive` (existing "module produced no recognizable output"
   behavior is unchanged).

### Requirement 4: Apply consistently across all affected checks

**User Story:** As a maintainer, I want the fix applied uniformly to every
check that currently conflates these two situations, so that the false
positive is actually resolved rather than fixed for one check and left in the
others.

#### Acceptance Criteria

1. THE system SHALL apply Requirements 1 and 2 to every check function
   confirmed (by inspecting current code) to call `looks_like_failure()`
   after a null-session (`-u "" -p ""`) or conditionally-null-session probe
   with no finding. As of this analysis that list is:
   - `check_smb_signing` (`unauthenticated.py`) - uses a `[-]`/banner-absence
     inconclusive path, not `looks_like_failure()` directly; included for
     completeness in Requirement 2.2's "no vulnerability pattern matched"
     handling.
   - `check_null_session` (`unauthenticated.py`)
   - `check_rid_cycling` (`unauthenticated.py`)
   - `check_ldap_anonymous_bind` (`unauthenticated.py`)
   - `check_webdav` (`unauthenticated.py`, null session or supplied creds)
   - `check_ntlmv1` (`unauthenticated.py`, null session or supplied creds)
   - `check_ntlm_reflection` (`unauthenticated.py`, null session or supplied
     creds)
   - `check_timeroast` (`unauthenticated.py`, null session or supplied creds)
   - `check_eternalblue` (`unauthenticated.py`)
   - `check_zerologon` (`unauthenticated.py`)
   - `check_smbghost` (`unauthenticated.py`)
   - `check_printnightmare` (`unauthenticated.py`)
   - `check_sccm_discovery` and the PXE/NAA check in `sccm.py` (authenticated
     LDAP discovery and unauthenticated PXE retrieval respectively; both call
     `looks_like_failure()`)
   - The authenticated-phase post-processor `_mark_inconclusive_on_failure`
     in `authenticated.py`, which runs `looks_like_failure()` generically over
     every authenticated check's raw output.
2. `check_ldap_relay_exposure`, `check_dns_zone_transfer`,
   `check_kerberos_user_enum`, `check_asrep_roast`,
   `check_cisco_smart_install`, `check_anonymous_ftp_nfs`,
   `check_snmp_default_community`, `check_ipmi_hash_disclosure`, and
   `check_name_poisoning` SHALL be re-verified against current code during
   design; the requirements author's grep found no `-u "", "-p", ""` null
   probe combined with `looks_like_failure()` in these, but the design must
   confirm before excluding them.
3. THE system SHALL NOT change behavior for checks that require real
   credentials and do not run a null-session probe (e.g. `check_asrep_roast`
   uses `-no-pass` via impacket, not an nxc null session, and has no
   `looks_like_failure()` call on its "no hashes" branch today).

### Requirement 5: Banner metadata is not itself a failure signal

**User Story:** As a pentester, I want informational banner fields like `Null
Auth:True` to be treated as context, not as a pass/fail signal, so that a
host's SMB banner cannot flip a result's status on its own.

#### Acceptance Criteria

1. THE system SHALL NOT add `Null Auth:True`/`False` (or similar NetExec
   banner fields) to `_FAILURE_SIGNALS` or any new classification list used to
   decide `inconclusive` vs `clean` vs `findings`.
2. WHERE a check already parses the SMB banner (`check_smb_signing`), banner
   fields such as `Null Auth:True` MAY be surfaced as additional evidence text
   on an existing finding when useful context, but SHALL NOT by themselves
   create a new finding, change severity, or change status.

## Acceptance Criteria (consolidated, testable)

1. A fixture reproducing the reported bug (`smbghost` banner line plus
   `STATUS_ACCESS_DENIED`, no vulnerable match) run through `check_smbghost`
   SHALL NOT be `inconclusive`; it SHALL be `clean`.
2. A fixture with only `connection refused` (no access-denied text) run
   through any affected check SHALL remain `inconclusive`.
3. A fixture with both `connection refused` and `access_denied` text run
   through any affected check SHALL remain `inconclusive` (connectivity
   signal wins per Requirement 1.4).
4. A fixture with `STATUS_ACCESS_DENIED` and no vulnerability match, for each
   check listed in Requirement 4.1, SHALL NOT be `inconclusive` (either
   `clean` with an access-denied note, or per the per-check table in the
   design).
5. `pytest -q` passes with no failing tests after the change.
6. `ruff check .` passes clean after the change.
7. No existing test asserting genuine-connectivity-failure behavior is
   weakened or deleted to make the above pass.

## Out of Scope

- Changing the underlying `nxc`/NetExec command invocations, flags, or
  modules used by any check.
- Adding retry logic or re-running checks with alternate credentials when a
  null session is refused.
- Changing the `CheckResult.status` state machine (`skipped` / `error` /
  `findings` / `inconclusive` / `clean`) itself; this spec only changes which
  branch a given output lands in.
- Addressing other reported false positives outside the null-session
  access-denied pattern (e.g. parser drift for new NetExec output formats) -
  the "no recognizable output" inconclusive branches are left as-is except
  where Requirement 2 explicitly changes their precondition.
- UI/console/report formatting changes beyond the evidence/reason text
  described in Requirement 2.5.

## Assumptions

- "STATUS_LOGON_FAILURE"/"logon_failure" are treated the same as
  "access_denied"/"status_access_denied" (both mean "reached the target, null
  credential attempt was explicitly rejected") since no check in the current
  codebase was found to distinguish them; this will be confirmed or revised
  during design if any check's semantics differ.
- The generic `[-]` NetExec negative-line signal stays a connectivity/failure
  style signal (Requirement 1.5) because, unlike the specific status codes, it
  does not itself tell us the target actively refused auth versus some other
  non-match; reclassifying it is out of scope and would risk hiding real
  failures.
