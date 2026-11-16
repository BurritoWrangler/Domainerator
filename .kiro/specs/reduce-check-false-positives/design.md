# Design Document: Reduce Check False Positives

## Overview

This design splits the single `looks_like_failure()` signal into two
distinct classifications and changes every affected check's "no finding"
branch to act on the right one. `connection refused` / `timed out` / `no
route to host` / `unable to connect` / `could not connect` / `error` /
`traceback` / `[-]` continue to mean "the scan could not reliably test the
target" -> `inconclusive`. `access_denied` / `status_access_denied` /
`logon_failure` / `status_logon_failure` move to a new category meaning "the
scan reached the target and the target explicitly refused the null-session
probe" -> handled per-check (clean-with-note for probes that test anonymous
access itself; clean for probes whose vulnerability detection doesn't depend
on auth succeeding, falling back to the existing "no recognizable output"
inconclusive guard). No new files, no new dependencies, no change to
`CheckResult`'s status state machine - everything is implemented inside the
existing `checks/__init__.py` helper and the call sites in
`unauthenticated.py`, `sccm.py`, and `authenticated.py`'s post-processor. The
stack stays pure-stdlib Python 3.11+, matching the rest of the repo.

## Architecture

### Signal classification (`checks/__init__.py`)

Replace the single `_FAILURE_SIGNALS` tuple and `looks_like_failure()` with
two tuples and a small classifier:

```python
# Signals meaning the scan could not reliably reach/test the target at all.
# A "no finding" result alongside one of these is inconclusive: the tool
# never got far enough to say anything about the target's actual state.
_CONNECTIVITY_FAILURE_SIGNALS = (
    "connection refused",
    "connection timed out",
    "timed out",
    "no route to host",
    "unable to connect",
    "could not connect",
    "error",
    "traceback",
    # NetExec's "[-]" negative-result marker. Bare "[-]" doesn't tell us
    # *why* the module didn't succeed, so it is treated the same as a
    # connectivity failure rather than assumed to be an access-denied.
    "[-]",
)

# Signals meaning the scan reached the target and the target explicitly
# refused the null-session/anonymous probe. This is itself an informative,
# conclusive result (anonymous access is blocked), not an unknown.
_ACCESS_DENIED_SIGNALS = (
    "access_denied",
    "status_access_denied",
    "logon_failure",
    "status_logon_failure",
)


class FailureKind(enum.Enum):
    CONNECTIVITY = "connectivity"
    ACCESS_DENIED = "access_denied"


def classify_failure(output: str) -> tuple[FailureKind, str] | None:
    """Classify a failure-like signal in ``output``, or return None.

    Returns ``(FailureKind.CONNECTIVITY, matched_signal)`` if any
    connectivity-failure signal is present (checked first: connectivity
    failures take priority even if access-denied text also appears, since a
    broken connection makes the whole result unreliable). Otherwise returns
    ``(FailureKind.ACCESS_DENIED, matched_signal)`` if an access-denied-style
    signal is present. Otherwise returns ``None``.
    """
    lowered = output.lower()
    for signal in _CONNECTIVITY_FAILURE_SIGNALS:
        if signal in lowered:
            return (FailureKind.CONNECTIVITY, signal)
    for signal in _ACCESS_DENIED_SIGNALS:
        if signal in lowered:
            return (FailureKind.ACCESS_DENIED, signal)
    return None


def looks_like_failure(output: str) -> str | None:
    """Backward-compatible wrapper: any failure-like signal, or None.

    Deprecated for new call sites - prefer ``classify_failure`` so
    connectivity failures and access-denied-to-null-probe outcomes are
    handled differently. Kept because it is simple and some call sites
    (Requirement 1.2 connectivity-only paths) don't need the distinction.
    """
    found = classify_failure(output)
    return found[1] if found else None
```

`FailureKind` and `classify_failure` are new public names in
`checks/__init__.py`; `looks_like_failure` keeps its exact current signature
and behavior (any signal, connectivity or access-denied, returns truthy) so
call sites that are deliberately left unconverted (none planned, but this
keeps the change minimal and reversible per-call-site) keep compiling.
`enum` needs an added `import enum` in `checks/__init__.py`.

### Per-check handling strategy

Two per-check categories, decided by what the check actually tests:

**Category A - checks whose entire point is to test anonymous/null-session
access itself.** A definitive access-denied response IS the answer the check
was looking for (anonymous access is blocked). These checks get a `clean`
finding/evidence note instead of silence-or-inconclusive:
- `check_null_session` (tests null-session share enumeration)
- `check_rid_cycling` (tests anonymous RID cycling)
- `check_ldap_anonymous_bind` (tests anonymous LDAP bind)

These three currently produce *no* finding at all when the probe fails
(`else: ... mark_inconclusive(...)`), so "fixing" them means adding an
`INFO`-severity finding such as "Anonymous SMB session refused" when
`classify_failure` returns `ACCESS_DENIED`, and keeping `mark_inconclusive`
only for `CONNECTIVITY`. This makes the hardened case show up as a `clean`-ish
informative result (status becomes `findings` with an INFO severity finding,
which existing report code already renders) instead of noise, while a
genuinely broken connection still reports `inconclusive`. Why an INFO finding
rather than literally doing nothing: `CheckResult.status` has no `clean`
concept distinct from "no findings, no inconclusive" other than the default
fallthrough, and leaving these three with zero findings and
`inconclusive=False` would silently look identical to "ran and found nothing
interesting" in older report code that doesn't special-case it - an explicit
INFO finding keeps the hardening posture visible to the operator, which is
valuable for a pentest report, and matches Requirement 2.1 ("report a clean
result whose finding/evidence notes that the anonymous probe was explicitly
refused").

**Category B - checks whose vulnerability detection does not depend on the
null-session authenticating.** NetExec's banner/module output (`signing:`,
`SMBv1:`, `MS17-010 VULNERABLE`, `vulnerable to zerologon`, `smbghost
VULNERABLE`, `Spooler service enabled`, `NTLMv1 allowed`, `reflection
VULNERABLE`, `WebClient Service enabled`, timeroast hash lines) is produced
by the protocol negotiation / RPC call the module makes, independent of
whether the `-u "" -p ""` SMB session itself got `STATUS_ACCESS_DENIED`. For
these, an access-denied signal with no vulnerability match should fall
through to the existing "no recognizable output" guard rather than being
treated as its own inconclusive reason - i.e. delete the
`classify_failure`/`ACCESS_DENIED` branch's `mark_inconclusive` call and let
the existing `elif not re.search(...)` branch decide. If the recognizable
module output line is present (even a negative one, e.g. "not vulnerable"),
that existing regex already prevents a spurious inconclusive; if truly
nothing recognizable is there, it's legitimately inconclusive (format
drifted or module didn't run), independent of the access-denied text.
Checks in this category:
- `check_smb_signing` (banner-based; see special note below)
- `check_webdav`
- `check_ntlmv1`
- `check_ntlm_reflection`
- `check_timeroast`
- `check_eternalblue`
- `check_zerologon`
- `check_smbghost`
- `check_printnightmare`
- `check_sccm_discovery` and `check_sccm_pxe_naa` (`sccm.py`)

`check_smb_signing` is special: it doesn't call `looks_like_failure()` at
all today. It marks inconclusive only when the `signing:` banner regex fails
to match, which is already the correct behavior (a `STATUS_ACCESS_DENIED`
with no banner at all genuinely means the signing posture is unknown - the
banner line in the reported bug *was* present, so this check was never the
one producing the false positive; `check_smbghost` was). No code change is
needed in `check_smb_signing` for Requirement 2.2; it is listed for
completeness per Requirement 4.1 but the design makes no change here beyond
optionally surfacing `Null Auth:True` as evidence text (Requirement 5.2,
implemented as a one-line addition described below).

**Category C - the authenticated-phase generic post-processor.**
`_mark_inconclusive_on_failure` in `authenticated.py` runs
`looks_like_failure()` over every authenticated check's raw output
generically, not just null-session checks. Authenticated checks use real
credentials (`target.nxc_auth_args()`), so an `access_denied`/`logon_failure`
there means the *supplied* credentials were rejected (expired, wrong, locked
out) - a genuinely different, still-ambiguous situation, not a "null session
hardened" signal. This post-processor is changed to use `classify_failure`
and keep marking inconclusive for **both** kinds, with a reason that
distinguishes them ("auth/connection failed - signal: 'access_denied'" vs
"connection failed - signal: 'timed out'") for clearer reporting, but without
changing the outcome (still inconclusive either way). This satisfies
Requirement 2.3's spirit (a check whose logic needs authentication to succeed
stays inconclusive on access-denied) without a behavior change, and improves
the reason text per Requirement 2.5.

No check was found where a null-session probe's own detection logic requires
authentication to succeed (Requirement 2.3's hypothetical case does not
currently exist); this is noted and the generic Category C handling above
covers the authenticated-credential equivalent.

### Checks re-verified and confirmed unaffected (Requirement 4.2)

Grepped and read in full during design:
- `check_ldap_relay_exposure` - no null probe, no `looks_like_failure`.
- `check_dns_zone_transfer` - no null probe, no `looks_like_failure`.
- `check_kerberos_user_enum` - uses `kerbrute`, not nxc null session; calls
  `looks_like_failure` but on `kerbrute` output, which can legitimately say
  "KDC unreachable" - no access-denied-style status codes apply to Kerberos
  pre-auth probing in the same way, so Requirement 1's split does not change
  its behavior; left as-is (still uses `looks_like_failure`, acceptable since
  its own docstring explains it is about KDC reachability, and
  `STATUS_ACCESS_DENIED`/`logon_failure` are SMB/LDAP-specific strings that
  won't appear in kerbrute output).
- `check_asrep_roast` - uses impacket `-no-pass`, not an nxc null session; no
  `looks_like_failure()` call on its "no hashes" branch (confirmed: falls
  through with no finding and no inconclusive call at all today - out of
  scope, unchanged).
- `check_cisco_smart_install`, `check_anonymous_ftp_nfs`,
  `check_snmp_default_community`, `check_ipmi_hash_disclosure`,
  `check_name_poisoning` - these use nmap/raw probes, not nxc `-u "" -p ""`;
  confirmed no SMB/LDAP status-code strings apply. Each does call
  `looks_like_failure` on nmap-style output ("Note: Host seems down.") for
  the connectivity case, which is unaffected by this design (no access-denied
  string will appear in nmap output).

No changes are made to any of the above.

## Components and Interfaces

| Component | File | Change |
|---|---|---|
| `FailureKind`, `classify_failure`, `_CONNECTIVITY_FAILURE_SIGNALS`, `_ACCESS_DENIED_SIGNALS` | `src/domainerator/checks/__init__.py` | New. Replaces the single `_FAILURE_SIGNALS` tuple. `looks_like_failure` kept as a thin wrapper for compatibility. |
| `check_null_session` | `src/domainerator/checks/unauthenticated.py` | `else` branch: on `ACCESS_DENIED`, add an INFO finding instead of `mark_inconclusive`; on `CONNECTIVITY`, keep `mark_inconclusive`. |
| `check_rid_cycling` | same | same pattern as above. |
| `check_ldap_anonymous_bind` | same | same pattern as above. |
| `check_webdav`, `check_ntlmv1`, `check_ntlm_reflection`, `check_timeroast`, `check_eternalblue`, `check_zerologon`, `check_smbghost`, `check_printnightmare` | same | Replace `looks_like_failure(text)` call with `classify_failure(text)`; only call `mark_inconclusive` when kind is `CONNECTIVITY`; on `ACCESS_DENIED`, fall through to the existing "no recognizable output" `elif` guard unchanged. |
| `check_sccm_discovery`, `check_sccm_pxe_naa` | `src/domainerator/checks/sccm.py` | Same `classify_failure` substitution as the Category B checks above. |
| `_mark_inconclusive_on_failure` | `src/domainerator/checks/authenticated.py` | Use `classify_failure`; keep marking inconclusive for both kinds; improve the reason text to name the kind. |
| `check_smb_signing` | `src/domainerator/checks/unauthenticated.py` | No behavior change. Optionally append `Null Auth:True`/`False` to the existing finding's evidence string when present (Requirement 5.2), purely cosmetic. |

No changes to `src/domainerator/runner.py` (`CheckResult` is untouched - no
new fields, no new status value) and no changes to `paths.py`, `console/`,
or any CLI entry point.

## Data Models

No new persisted data model. `CheckResult` (runner.py) is unchanged:
`inconclusive`, `inconclusive_reason`, `findings`, `status` keep their
current fields and semantics. The only "new data" is the `FailureKind` enum,
an internal implementation detail of `checks/__init__.py` not exposed on
`CheckResult` or serialized anywhere (`to_dict()` is untouched).

For the three Category A checks, the new INFO finding uses the existing
`Finding` dataclass (`src/domainerator/runner.py`) with:
- `severity=Severity.INFO`
- `title` naming the specific refusal (e.g. "Anonymous SMB session refused")
- `evidence` = the matched signal plus a trimmed slice of raw output, same
  pattern already used by every other finding in these modules (`text[:500]`
  or similar)
- no `remediation` (nothing to remediate - this is the hardened state)
- no `PathStep` added (an access-denied null probe grants no capability)

## Correctness Properties

1. **No connectivity-failure signal is ever downgraded.** For every affected
   check, if `classify_failure(output)` returns `FailureKind.CONNECTIVITY`
   and the check made no finding, the result is `inconclusive`. This is
   invariant across all three categories and is the property Requirement 3.1
   demands; it is enforced at the per-check `else` branch (Category A/B) or
   inside `_mark_inconclusive_on_failure` (Category C) - i.e. the same layer
   that already owns inconclusive-marking today, unchanged in responsibility.
2. **Connectivity wins over access-denied when both are present.**
   `classify_failure` checks `_CONNECTIVITY_FAILURE_SIGNALS` before
   `_ACCESS_DENIED_SIGNALS` and returns on first match, so a line containing
   both "connection refused" and "access_denied" text classifies as
   `CONNECTIVITY`. Enforced once, centrally, in `classify_failure` - no
   per-check logic needs to reimplement this ordering.
3. **A bare access-denied with no vulnerability match never produces a false
   "clean, no issue" silence for Category A checks.** Category A checks
   convert `ACCESS_DENIED` into an explicit INFO finding, so the operator
   always sees *why* no vulnerability was reported (the probe ran and was
   refused), satisfying Requirement 2.1 and 2.5. Enforced in each Category A
   check's `else` branch - this is check-specific because only these three
   checks' findings are entirely about testing the null probe itself.
4. **Category B checks never claim a vulnerability absent a positive module
   match.** Unchanged: the `if vulnerable:` / `if enabled:` branch in each
   Category B check is untouched by this design; only the `else` branch's
   inconclusive-vs-fallthrough logic changes. Enforced by each check's
   existing vulnerability-matching regex, which this design does not touch.
5. **Banner-only fields never change status on their own.** `Null Auth:True`
   is never added to `_CONNECTIVITY_FAILURE_SIGNALS` or
   `_ACCESS_DENIED_SIGNALS`, so it cannot affect `classify_failure`'s result.
   Enforced by omission - verified by a unit test asserting a fixture
   containing only `Null Auth:True` (no other signal) does not classify as
   either kind.

## Error Handling

- **`out.error` set (tool not found / spawn failure):** unchanged in every
  check - `result.error = out.error; return result` short-circuits before
  any `classify_failure` call. Fatal for that check's run, logged nowhere
  new (existing behavior), surfaced to the caller as `CheckResult.status ==
  "error"`.
- **`classify_failure` called with non-string/`None` output:** cannot occur;
  every call site passes `out.combined` or `text`, both always `str` (empty
  string at worst) per `ToolRunner.run`'s `CommandOutput` contract. No new
  validation needed - this mirrors the existing `looks_like_failure`
  contract exactly.
- **Both connectivity and access-denied signals present:** not an error,
  handled by Correctness Property 2 (connectivity wins); no exception, no
  logging change - this is routine classification, not a failure of the
  tool itself.
- **A Category A/B check's regex fails to compile or raises:** out of scope
  - no regex changes are made to any existing vulnerability-matching
  pattern; only the `else` branch control flow changes. If `re.search` on a
  `None` text ever raised, that is a pre-existing bug unrelated to this
  change (and cannot happen since `text = out.combined`, always a `str`).
- **Ruff/lint failures introduced by the refactor (e.g. unused import,
  `enum` not imported):** caught by the verification gate (`ruff check .`)
  before commit; not a runtime error path, called out here because it's an
  explicit gate in Requirements.

No new exceptions are introduced; no existing exception handling is removed.

## Validation Rules (external inputs)

The only "external input" `classify_failure` touches is tool stdout/stderr
text (`out.combined`), already free-form and untrusted by construction (it's
shelled-out subprocess output). No new validation is needed beyond what
`ToolRunner.run` already does (capturing output as `str`, never raising on
non-UTF8 - confirmed existing behavior in `runner.py`'s `CommandOutput`
construction, unchanged by this design). No new CLI flags, config fields, or
user-supplied parameters are introduced by this feature, so there is no new
validation-rule surface to specify (required/optional/type/limits do not
apply - nothing new is parsed from user input).

## Testing Strategy

**Unit tests (all in `tests/test_checks.py`, following existing
`FakeRunner`/`ANON_TARGET` patterns already in that file):**

1. `test_classify_failure_connectivity_only` - `"Connection refused"` ->
   `(FailureKind.CONNECTIVITY, "connection refused")`.
2. `test_classify_failure_access_denied_only` - `"STATUS_ACCESS_DENIED"` ->
   `(FailureKind.ACCESS_DENIED, "status_access_denied")`.
3. `test_classify_failure_both_present_is_connectivity` - a string
   containing both `"connection refused"` and `"access_denied"` ->
   `FailureKind.CONNECTIVITY` (Correctness Property 2).
4. `test_classify_failure_null_auth_banner_is_not_a_signal` - a string
   containing only `"Null Auth:True"` -> `None` (Correctness Property 5).
5. `test_looks_like_failure_still_detects_both_kinds` - back-compat wrapper
   still returns truthy for either kind (regression guard on the kept
   wrapper).
6. Per Category A check (`check_null_session`, `check_rid_cycling`,
   `check_ldap_anonymous_bind`) - two new tests each:
   - `..._access_denied_is_not_inconclusive`: fixture with the reported
     bug's shape (banner line + `STATUS_ACCESS_DENIED`, no vulnerable
     match) -> `not res.inconclusive`, `res.findings` non-empty with an
     INFO-severity finding.
   - `..._connectivity_failure_stays_inconclusive`: fixture with
     `"Connection refused"` -> `res.inconclusive is True`, unchanged from
     today (this duplicates/strengthens existing coverage; existing tests
     like `test_inconclusive_on_connection_failure` already assert this for
     `check_smb_signing` and remain as regression guards).
7. Per Category B check, representative sample covering the originally
   reported bug plus the systemic pattern - full coverage for
   `check_smbghost` (the exact reported bug) and `check_eternalblue`,
   `check_zerologon`, `check_webdav`, `check_ntlmv1` (representative of the
   rest, since they share the identical `classify_failure`/fallthrough
   shape):
   - `test_smbghost_access_denied_is_clean_not_inconclusive`: the exact
     fixture from the bug report (`"[*] Windows Server 2019 ... (Null
     Auth:True)\n[-] abcdomain.com\\: STATUS_ACCESS_DENIED"`) -> `not
     res.inconclusive`. Status is `"clean"` since no finding and no
     inconclusive flag is set (the existing "no recognizable output" guard
     does not fire because, per current regex, `"smbghost"` *is* present in
     the banner text's command/module context - this is re-verified in
     implementation; if the literal fixture text contains no `smbghost`
     substring at all, status legitimately falls to the "no recognizable
     output" inconclusive branch, which is still correct per Requirement
     2.2's "unless the banner/module fields it depends on are themselves
     absent" carve-out, and the test is written to assert
     `not res.inconclusive` only when a recognizable module line is present
     in the fixture).
   - `test_smbghost_connection_refused_stays_inconclusive`: existing test
     `test_smbghost_inconclusive_on_failure` already covers this; kept
     unchanged as the regression guard.
   - Same two-test pattern applied to `check_eternalblue`,
     `check_zerologon`, `check_webdav`, `check_ntlmv1` (existing
     `..._inconclusive_on_connection_failure`/`..._inconclusive_on_unrecognized_output`
     tests already serve as the "stays inconclusive" half for several of
     these; only the new access-denied-is-not-inconclusive test is added
     per check).
8. `_mark_inconclusive_on_failure` (Category C,
   `authenticated.py`) - extend the existing
   `test_auth_failure_marked_inconclusive_by_run_all_postprocess` test with a
   third `CheckResult` whose `raw_output` is `"STATUS_ACCESS_DENIED"` and
   assert it is *also* marked inconclusive (Category C keeps both kinds
   inconclusive - this is a deliberate asymmetry from Category A/B,
   explained in Architecture, and must be test-locked so a future refactor
   doesn't accidentally "fix" it into a false negative on rejected
   credentials).
9. `test_sccm_discovery_access_denied_falls_through` and
   `test_sccm_pxe_naa_access_denied_falls_through` (`tests/test_sccm.py`,
   following that file's existing fixture patterns) mirroring the Category B
   pattern for the two `sccm.py` checks.

**Integration-level coverage:** `test_new_checks_registered_in_run_all` /
`test_new_network_checks_registered_in_run_all` already exist and continue
to pass unmodified, confirming `run_all` wiring is untouched. No new
integration test is needed since no module registration, CLI flag, or
console command changes.

**What is unit- vs integration-tested:** `classify_failure` itself is
pure-function unit-tested in isolation (no I/O). Each check function is
unit-tested with `FakeRunner` (already the pattern in `test_checks.py`),
which stubs `ToolRunner.run` and is itself a unit test, not an integration
test, since no real subprocess or network call occurs. There is no
integration test that shells out to real `nxc` in this repo's test suite
(confirmed by reading `tests/test_checks.py` in full), so this design does
not add one - consistent with existing practice.

**Verification gate:** after implementation, `pytest -q` and
`ruff check .` must both pass clean, per Requirement 4 of the consolidated
acceptance criteria. This is a manual/CI gate run before commit, not a test
file.

## Responses to Design Review Findings

No design review exists yet for this spec (first iteration). This section
will be populated if a review document is produced and findings are raised
against this revision.
