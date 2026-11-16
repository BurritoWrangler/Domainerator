# Requirements Document

## Introduction

Users scanning hosts with null-session (unauthenticated, `-u "" -p ""`) NetExec
checks are seeing `inconclusive` results on hardened hosts even though the
scan ran correctly and got a definitive answer: the target refused the
anonymous probe with `STATUS_ACCESS_DENIED`. This happens because
`looks_like_failure()` in `src/domainerator/checks/__init__.py` lumps two very
different situations into one flat `_FAILURE_SIGNALS` list:

1. Genuine connectivity/protocol failures (connection refused, timed out, no
   route to host) where the tool never got far enough to say anything about
   the target - correctly inconclusive.
2. A successful connection where the target *affirmatively rejected* the null
   session/anonymous probe (`access_denied`, `STATUS_ACCESS_DENIED`,
   `STATUS_LOGON_FAILURE`) - this is itself a result (anonymous access is
   blocked / hardened), not an unknown.

The reported bug (`check_smbghost` against a hardened host, output containing
a banner line plus `[-] abcdomain.com\: STATUS_ACCESS_DENIED`) is produced by
two independent defects, both in scope for this spec:

- **Ordering defect**: today's flat signal list happens to match
  `access_denied` as the first substring found, which is why the user's
  report shows that reason text. But the list also contains `"[-]"`, and
  NetExec prints a `[-]` line for every negative/failed module result,
  including this one. Any reclassification must not let `"[-]"` (a generic
  "module did not succeed" marker) outrank or get conflated with the specific
  access-denied signal, and must not let it silently classify a genuine
  connectivity failure as something softer.
- **Module-dependency defect**: `check_smbghost`, like the other NetExec
  `-M <module>` checks, relies on the module's own result line (e.g.
  containing `smbghost` or `CVE-2020-0796`) being present in the output. In
  NetExec, `-M` modules run from on-login hooks, i.e. **after** a successful
  SMB login. When the null-session login itself is denied
  (`STATUS_ACCESS_DENIED`), the module never runs, so the module's own result
  line is never printed, and the existing "no recognizable output" guard
  (`elif not re.search(r"smbghost|cve-2020-0796|not vulnerable", ...)`) fires
  regardless of how the access-denied/connectivity split is implemented. For
  these module-dependent checks, "the null session was refused" and "we don't
  know if the module ran" are the same fact, not two different facts, so the
  check genuinely cannot say "clean" - it can only say *why* it couldn't test
  further, more precisely than today.

This spec defines how to split the two failure situations, and documents
exactly which outcome each affected check reports for each situation, so that
genuine failures still report `inconclusive`, a refused anonymous probe is
never silently read as "clean" when the check's own detection logic depended
on that probe succeeding, and the noise is reduced by making the refusal
visible and distinct rather than conflated with an unrelated connectivity
problem.

## Glossary

- **Null session / anonymous probe**: An SMB/LDAP connection attempt using
  `-u "" -p ""` (no credentials), used by unauthenticated checks to test
  whether anonymous access is permitted, or as the no-credentials fallback
  for checks that otherwise use supplied credentials.
- **Connectivity failure**: The tool could not reach, negotiate with, or
  complete a protocol handshake with the target, or a module/output format
  mismatch of unknown cause (e.g. `connection refused`, `timed out`, `no
  route to host`, a bare NetExec `[-]` negative-result line with no more
  specific signal, `error`, `traceback`). The result carries no information
  about the target's actual security posture.
- **Access-denied-to-null-probe**: The target was reached and responded, but
  explicitly refused the anonymous/null credential attempt
  (`STATUS_ACCESS_DENIED`, `STATUS_LOGON_FAILURE`, `access_denied`,
  `logon_failure`). This is a successful, informative scan outcome in itself:
  anonymous access is not permitted. Whether that fact alone lets a specific
  check report `clean` depends on whether the check's vulnerability
  detection is independent of the null login succeeding (see Requirement 2).
- **On-login module**: A NetExec `-M <module>` invocation. The module's
  detection logic executes from an on-login hook and therefore only runs if
  the SMB/LDAP authentication (including a null session) succeeds. All of
  `smbghost`, `ms17-010` (EternalBlue), `zerologon`, `spooler`
  (PrintNightmare), `ntlmv1`, `ntlm_reflection`, `webdav`, `timeroast`, `sccm`,
  and `ldap-checks` are on-login modules in this codebase.
- **`looks_like_failure()`**: Helper in `src/domainerator/checks/__init__.py`
  that scans tool output for any of a list of failure-indicating substrings
  and returns the first match, or `None`.
- **`CheckResult.mark_inconclusive()`**: Method on `CheckResult`
  (`src/domainerator/runner.py`) that sets `inconclusive = True` and records
  `inconclusive_reason`; a no-op if a finding was already recorded.
- **`CheckResult.status`**: Computed property; returns, in order,
  `"skipped"` (if `skipped`), `"error"` (if `error` is set), `"findings"` (if
  `findings` is non-empty), `"inconclusive"` (if `inconclusive`), else
  `"clean"`.
- **Affected check**: A check function in `src/domainerator/checks/` that (a)
  issues a null-session probe (`-u "" -p ""`, unconditionally or as the
  no-credentials fallback) and (b) calls `looks_like_failure()` on its output,
  or inspects its output for the same signals via an equivalent guard, to
  decide whether a "nothing found" result should be `mark_inconclusive()`'d.

## Requirements

### Requirement 1: Distinguish connectivity failure from access-denied-to-null-probe

**User Story:** As a pentester scanning many hosts, I want checks that
successfully reach a hardened host and get a clear access-denied response to
an anonymous probe to carry a distinct, accurate reason instead of being
conflated with a real connectivity problem, so that a timeout and a hardening
signal never look the same in my results.

#### Acceptance Criteria

1. THE system SHALL provide a classification function, `classify_failure`,
   that given check output returns one of: a connectivity-failure match, an
   access-denied match, or no match - never a single flat boolean/string
   covering both situations.
2. WHEN output contains a connectivity-failure signal (`connection refused`,
   `connection timed out` / `timed out`, `no route to host`, `unable to
   connect`, `could not connect`, `authentication failed`, `error`,
   `traceback`), THE system SHALL classify the result as a connectivity
   failure regardless of whether an access-denied-style substring is also
   present elsewhere in the output.
3. WHEN output contains an access-denied signal (`access_denied`,
   `status_access_denied`, `logon_failure`, `status_logon_failure`) and no
   connectivity-failure signal as defined in Criterion 2, THE system SHALL
   classify the result as access-denied, distinct from a connectivity
   failure.
4. A bare NetExec `[-]` negative-result marker, by itself with no more
   specific signal also present, SHALL classify as a connectivity failure
   (not as access-denied and not as "no signal"), because `[-]` alone does
   not tell us *why* the module failed to produce a positive result - it is
   exactly as uninformative as a format-drift or unreachable-host case, and
   downgrading it to a weaker category risks hiding a real failure. This
   bare-`[-]` case is a connectivity-style classification, not evidence of a
   refused probe: a line that contains `[-]` together with `access_denied` or
   `status_access_denied` text (as in the reported bug, where the `[-]` line
   itself states `STATUS_ACCESS_DENIED`) SHALL still classify as access-denied
   per Criterion 3, since the specific status code is strictly more
   informative than the generic marker that precedes it in NetExec's output
   format.
5. WHEN output contains neither a connectivity-failure signal nor an
   access-denied signal, THE system SHALL return "no match", leaving the
   caller's existing "no recognizable output" handling (Requirement 3.2)
   unchanged.

### Requirement 2: Per-check handling of access-denied-to-null-probe

**User Story:** As a pentester, I want each unauthenticated check's
inconclusive reason to say specifically whether the probe was refused or the
scan simply failed to connect, and I want a check to report a vulnerability
finding or `clean` only when its own detection logic actually ran, so I can
trust a non-inconclusive result and still get a more useful reason on the
cases that must legitimately stay inconclusive.

#### Acceptance Criteria

1. WHEN a check whose entire purpose is to test anonymous/null-session access
   itself (`check_null_session`, `check_rid_cycling`,
   `check_ldap_anonymous_bind`) receives an access-denied-to-null-probe
   response and finds no vulnerability, THE check SHALL report `clean` with
   an added INFO-severity finding noting that the anonymous probe was
   explicitly refused (an informative, hardened-posture result), rather than
   `inconclusive`. This is correct because these three checks' own detection
   logic *is* "did the null probe succeed", so a definitive refusal is a
   complete, conclusive answer, not a partial one. (Design note: adding an
   INFO finding sets `CheckResult.status` to `"findings"`, not `"clean"`,
   given the current status-precedence order in `runner.py`; see the design
   document for how this requirement is satisfied within that constraint.)
2. WHEN an on-login-module check (`check_smbghost`, `check_eternalblue`,
   `check_zerologon`, `check_printnightmare`, `check_ntlmv1`,
   `check_ntlm_reflection`, `check_webdav`, `check_timeroast`,
   `check_sccm_discovery`, `check_sccm_pxe_naa`) receives an
   access-denied-to-null-probe response, THE check SHALL remain
   `inconclusive`, because the module itself never ran and the check
   therefore has no information about the target's vulnerability status -
   but the `inconclusive_reason` SHALL be rewritten to say specifically that
   the null-session login was refused and the module did not run, instead of
   the current generic "output shows '<signal>'" wording that is
   indistinguishable from a connectivity failure. This reduces noise by
   making the operator's triage faster (a glance at the reason distinguishes
   "target hardened against null sessions, try with real creds" from "target
   unreachable, check connectivity") without reporting a vulnerability status
   the scan did not actually establish.
3. WHEN a check's banner-derived detection does not depend on a module login
   at all (`check_smb_signing`, which reads the `signing:`/`SMBv1:` fields
   from the connection banner itself, printed regardless of login outcome),
   access-denied status SHALL NOT affect its existing behavior: this check
   already only goes inconclusive when the banner's `signing:` field is
   itself absent, independent of login success, and that behavior is
   correct and unchanged by this spec.
4. IF a check's own detection logic requires the null-session authentication
   step to have succeeded in order to say anything meaningful - which,
   per re-verification in design, is true for every on-login-module check
   listed in Criterion 2 - THEN that check SHALL remain `inconclusive` on
   access-denied, with a reason stating that the null-session login was
   required and refused, per Criterion 2.
5. THE per-check `inconclusive_reason` / finding evidence text SHALL make the
   distinction legible to the user in all cases: connectivity failures say
   the scan could not reach/complete; access-denied-to-null-probe outcomes
   on module-dependent checks say the login was refused and the module did
   not run; access-denied-to-null-probe outcomes on Category A checks
   (Criterion 1) are reported as an explicit finding, not a reason string.

### Requirement 3: Preserve or improve detection of genuine failures

**User Story:** As a pentester, I want genuine connectivity/timeout failures
to always be reported as inconclusive and never silently reported as "clean"
or reclassified as a milder access-denied note, so that I don't mistake "the
scan never ran" for "the target is not vulnerable" or "the target is
hardened".

#### Acceptance Criteria

1. THE system SHALL NOT weaken detection of connectivity-failure signals:
   every signal currently in `_FAILURE_SIGNALS` that indicates a failure to
   connect/authenticate for a reason other than the target actively refusing
   the probe with a specific access-denied status code (`connection
   refused`, `timed out`, `no route to host`, `unable to connect`, `could not
   connect`, `authentication failed`, `error`, `traceback`, bare `[-]`) SHALL
   still result in `inconclusive` when no finding was made, with no behavior
   change from today for these signals in isolation.
2. WHEN a check parses no finding and the output matches neither a
   connectivity-failure signal nor an access-denied signal nor the check's own
   "recognizable output" pattern, THE check SHALL continue to report
   `inconclusive` (existing "module produced no recognizable output"
   behavior is unchanged).
3. A fixture containing both a connectivity-failure signal and an
   access-denied signal SHALL classify as a connectivity failure and SHALL
   remain `inconclusive`, per Requirement 1.2 and 1.4.

### Requirement 4: Apply consistently across all affected checks

**User Story:** As a maintainer, I want the fix applied uniformly, with an
accurate record of exactly which checks call `looks_like_failure()` after a
null-session probe today, so that the false positive is resolved for every
check that actually has it rather than fixed for one and assumed-fixed for
others that were never calling the function in the first place.

#### Acceptance Criteria

1. THE system SHALL apply Requirements 1 and 2 to every check function
   confirmed by direct inspection of current code to call `looks_like_failure`
   (or an equivalent output-signal check) after a null-session (`-u "" -p
   ""`) or no-credentials-fallback probe with no finding. Re-verified by
   `grep -n "looks_like_failure" src/domainerator/checks/*.py` during design,
   the authoritative list (file:line, credential mode, call present) is:

   | Check | File | Credential mode | Calls `looks_like_failure` | Category |
   |---|---|---|---|---|
   | `check_null_session` | `unauthenticated.py:171` | null only | yes | A |
   | `check_rid_cycling` | `unauthenticated.py:258` | null only | yes | A |
   | `check_ldap_anonymous_bind` | `unauthenticated.py:306` | null only | yes | A |
   | `check_smbghost` | `unauthenticated.py:1523` | null only | yes | B (on-login module) |
   | `check_eternalblue` | `unauthenticated.py:1171` | null only | yes | B (on-login module) |
   | `check_zerologon` | `unauthenticated.py:1257` | null only | yes | B (on-login module) |
   | `check_printnightmare` | `unauthenticated.py:1606` | null only | yes | B (on-login module) |
   | `check_timeroast` | `unauthenticated.py:1009` | auth-or-null fork | yes | B (on-login module) |
   | `check_kerberos_user_enum` | `unauthenticated.py:687` | `kerbrute`, not nxc null session | yes | Unaffected (Requirement 4.3) |
   | `check_sccm_discovery` | `sccm.py` (~line 95) | authenticated only (`target.nxc_auth_args()`); never null | yes | Unaffected - no null probe (Requirement 4.3), but see note below |
   | `check_sccm_pxe_naa` | `sccm.py` (~line 185) | auth-or-null fork | yes | B (on-login module), null branch only |
   | `check_gpp_cpassword` | `authenticated.py` | authenticated only | yes | Unaffected (Requirement 4.3) |

   THE following checks do **not** call `looks_like_failure` today and SHALL
   NOT have a call added by this spec, since their existing guard is a
   module-output-presence regex that already achieves the Requirement 2.2
   fallthrough behavior without needing the connectivity/access-denied split:
   `check_webdav` (`unauthenticated.py:777`, auth-or-null fork),
   `check_ntlmv1` (`unauthenticated.py:849`, auth-or-null fork),
   `check_ntlm_reflection` (`unauthenticated.py:920`, auth-or-null fork). These
   three are still Category B (on-login module, Requirement 2.2) in spirit -
   their `else` branch already reports `inconclusive` only when the module's
   own output marker (`webdav`/`webclient`, `ntlmv1`/`lmcompatibility`,
   `reflection`) is absent, with no reference to access-denied text, so an
   access-denied-only output already falls through to that same guard and
   stays `inconclusive` for the same "module didn't run" reason Requirement
   2.2 requires - just without ever having had the bug this spec fixes. No
   code change is required for these three; they are included here, and in
   the design's per-check table, so a future reader does not have to
   re-derive this.

   `check_sccm_discovery` uses only `target.nxc_auth_args()` (supplied
   credentials), never a null session, so an access-denied there means the
   *supplied* credentials were rejected, which is Requirement 4.3's
   "credentialed, out of scope" case, not Requirement 2's null-probe case. It
   is listed for completeness because it does call `looks_like_failure` and a
   naive grep for that call name alone would otherwise wrongly flag it as
   affected.

2. THE following checks SHALL be, and are hereby, re-verified against
   current code as having no null-session probe combined with
   `looks_like_failure` and therefore out of scope: `check_ldap_relay_exposure`
   (auth-or-null fork, but does not call `looks_like_failure` - uses a
   module-output-presence guard instead, per the same reasoning as
   `check_webdav` above), `check_dns_zone_transfer` (no credentials concept,
   DNS-only), `check_asrep_roast` (impacket `-no-pass`, no
   `looks_like_failure` call on its no-hashes branch), `check_cisco_smart_install`,
   `check_anonymous_ftp_nfs`, `check_snmp_default_community`,
   `check_ipmi_hash_disclosure`, `check_name_poisoning` (all nmap/raw-socket
   based, `looks_like_failure` called only on nmap-style "Note: Host seems
   down." text, which contains no SMB/LDAP access-denied status strings).
3. THE system SHALL NOT change behavior for checks that require real
   credentials and do not run a null-session probe (`check_asrep_roast`,
   `check_kerberos_user_enum`, `check_sccm_discovery`, `check_gpp_cpassword`
   and the other authenticated-phase checks using `target.nxc_auth_args()`).
   For these, an access-denied/logon-failure signal means the *supplied*
   credentials were rejected - a different, still-ambiguous situation that
   SHALL continue to report `inconclusive` via the existing authenticated-phase
   post-processor (`_mark_inconclusive_on_failure` in `authenticated.py`),
   unchanged in outcome, though its reason text SHALL be clarified per
   Requirement 2.5's spirit (distinguishing "connection failed" from
   "credentials rejected") as part of this spec's classification work.

### Requirement 5: Banner metadata is not itself a failure signal

**User Story:** As a pentester, I want informational banner fields like `Null
Auth:True` to be treated as context, not as a pass/fail signal, so that a
host's SMB banner cannot flip a result's status on its own.

#### Acceptance Criteria

1. THE system SHALL NOT add `Null Auth:True`/`False` (or similar NetExec
   banner fields) to any signal list used by `classify_failure` to decide
   connectivity-failure vs access-denied vs no-match.
2. `check_smb_signing`, which already parses the SMB banner, MAY surface
   `Null Auth:True`/`False` as additional evidence text on its existing
   signing/SMBv1 finding when present, as optional, purely informational
   context, but SHALL NOT use it to create a new finding, change severity,
   or change `status`.

## Acceptance Criteria (consolidated, testable)

1. A fixture reproducing the reported bug verbatim (the banner line plus
   `[-] abcdomain.com\: STATUS_ACCESS_DENIED`, run through `check_smbghost`)
   SHALL have `classify_failure` return an access-denied classification (not
   connectivity), per Requirement 1. The check's own result SHALL remain
   `inconclusive`, per Requirement 2.2/2.4 (the module never ran), but with an
   `inconclusive_reason` that names the refused null-session login
   specifically, distinct from a connectivity-failure reason, which is the
   measurable reduction in noise this spec delivers for this check and the
   rest of Category B.
2. A fixture with only `connection refused` (no access-denied text) run
   through any affected check SHALL remain `inconclusive` with an
   unchanged-in-spirit "connectivity failure" reason.
3. A fixture with both `connection refused` and `access_denied`/
   `STATUS_ACCESS_DENIED` text run through any affected check SHALL classify
   as connectivity and remain `inconclusive` (Requirement 1.2/3.3).
4. For each Category A check (`check_null_session`, `check_rid_cycling`,
   `check_ldap_anonymous_bind`), a fixture with `STATUS_ACCESS_DENIED` and no
   vulnerability match SHALL report `status == "findings"` with an
   INFO-severity finding present and `inconclusive is False` (Requirement
   2.1).
5. For each Category B / on-login-module check listed in Requirement 4.1, a
   fixture with `STATUS_ACCESS_DENIED` and no module-output marker SHALL
   remain `inconclusive`, with `inconclusive_reason` containing wording that
   identifies a refused null-session login distinct from a connectivity
   failure (Requirement 2.2/2.5).
6. `pytest -q` passes with no failing tests after the change.
7. `ruff check .` passes clean after the change.
8. No existing test asserting genuine-connectivity-failure behavior is
   weakened or deleted to make the above pass.

## Out of Scope

- Changing the underlying `nxc`/NetExec command invocations, flags, or
  modules used by any check.
- Adding retry logic or re-running checks with alternate credentials when a
  null session is refused.
- Changing the `CheckResult.status` state machine (`skipped` / `error` /
  `findings` / `inconclusive` / `clean`) itself, or adding a new status value;
  this spec only changes which branch a given output lands in and what reason
  text / findings are attached.
- Addressing other reported false positives outside the null-session
  access-denied pattern (e.g. parser drift for new NetExec output formats) -
  the "no recognizable output" inconclusive branches are left as-is except
  where Requirement 2 explicitly changes the reason text attached to them.
- UI/console/report formatting changes beyond the evidence/reason text
  described in Requirement 2.5, and beyond whatever rendering already exists
  for INFO-severity findings (not modified by this spec).
- Re-running the exploitation/verification or attack-path layers against the
  changed checks; this spec touches only `CheckResult` population inside
  `checks/`.

## Assumptions

- "STATUS_LOGON_FAILURE"/"logon_failure" are treated the same as
  "access_denied"/"status_access_denied" (both mean "reached the target, null
  credential attempt was explicitly rejected") since no check in the current
  codebase distinguishes them; this is confirmed unchanged during design.
- NetExec's `-M <module>` detection logic runs from an on-login hook and
  therefore does not execute when the login (including a null-session login)
  is denied. This is the basis for Requirement 2.2/2.4 keeping all on-login
  module checks `inconclusive` on access-denied. This is a real, documented
  property of NetExec's module execution model (modules register
  `on_login`/`on_admin_login` callbacks), not a guess specific to this
  codebase, and is treated as a hard constraint on the design, not a
  preference.
- "Whatever would be most helpful in reducing false positives" (the user's
  stated goal) is interpreted as: eliminate every case where this codebase
  reports a *wrong or unjustified* classification (Category A: reporting
  `inconclusive` when the check's own purpose was fully answered;
  Requirement 1's signal-ordering/conflation bug), and make every remaining,
  legitimately-still-inconclusive case say *why* in specific, accurate terms
  instead of a generic signal-substring dump - rather than reclassifying
  genuinely-unknown outcomes as `clean` to further shrink the inconclusive
  count, which would trade false positives for false negatives and violate
  the user's explicit "must never silently report as clean" guardrail
  (carried over verbatim from the task brief).
