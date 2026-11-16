# Implementation Plan: Reduce Check False Positives

## Overview

This plan implements the `classify_failure`/`FailureKind` split in
`checks/__init__.py`, applies it to the three Category A checks (new INFO
finding on access-denied) and the Category B/C checks that call
`looks_like_failure` today (clarified, kind-specific inconclusive reason,
same `inconclusive` outcome), and adds required (non-optional) unit tests for
every affected check covering both the access-denied and
connectivity-failure cases. It finishes with the `pytest -q` / `ruff check .`
verification gate, run both before and after the change, and a standalone
commit of the spec itself.

## Tasks

- [ ] 1. Add `FailureKind` and `classify_failure` to `checks/__init__.py`
  - [ ] 1.1 Replace `_FAILURE_SIGNALS` with `_CONNECTIVITY_FAILURE_SIGNALS` and `_ACCESS_DENIED_SIGNALS`
    - Add `import enum` to `src/domainerator/checks/__init__.py`
    - `_CONNECTIVITY_FAILURE_SIGNALS`: `connection refused`, `connection
      timed out`, `timed out`, `no route to host`, `unable to connect`,
      `could not connect`, `authentication failed`, `error`, `traceback`
      (bare `[-]` is NOT in this tuple - it is a separate fallback step, see
      1.2)
    - `_ACCESS_DENIED_SIGNALS`: `access_denied`, `status_access_denied`,
      `logon_failure`, `status_logon_failure`
    - _Requirements: 1.1, 1.2, 1.3, 3.1_
  - [ ] 1.2 Implement `FailureKind` enum and `classify_failure()`
    - `FailureKind` with `CONNECTIVITY` and `ACCESS_DENIED` members
    - `classify_failure(output) -> tuple[FailureKind, str] | None`: check
      `_CONNECTIVITY_FAILURE_SIGNALS` first, then `_ACCESS_DENIED_SIGNALS`,
      then a bare `"[-]"` fallback classified as `CONNECTIVITY`, then `None`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  - [ ] 1.3 Reimplement `looks_like_failure()` as a thin wrapper over `classify_failure()`
    - Keep its exact current signature (`str -> str | None`); used
      unconverted by `check_kerberos_user_enum`, `check_gpp_cpassword`, and
      the nmap/raw-socket checks (`check_cisco_smart_install`,
      `check_anonymous_ftp_nfs`, `check_snmp_default_community`,
      `check_ipmi_hash_disclosure`, `check_name_poisoning`)
    - _Requirements: 3.1_
  - [ ] 1.4 Unit tests for `classify_failure` and `looks_like_failure`
    - `test_classify_failure_connectivity_only`
    - `test_classify_failure_access_denied_only`
    - `test_classify_failure_both_present_is_connectivity`
    - `test_classify_failure_bug_fixture_is_access_denied` (uses the shared
      `SMBGHOST_BUG_FIXTURE` constant added in this task)
    - `test_classify_failure_bare_dash_with_no_other_signal_is_connectivity`
    - `test_classify_failure_null_auth_banner_is_not_a_signal`
    - `test_classify_failure_no_signal_returns_none`
    - `test_looks_like_failure_still_detects_both_kinds`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1_

- [ ] 2. Update Category A checks (anonymous-access-is-the-test) in `unauthenticated.py`
  - [ ] 2.1 `check_null_session`: replace `looks_like_failure(text)` with
    `classify_failure(text)`; on `ACCESS_DENIED`, add an INFO `Finding`
    titled "Anonymous SMB session refused" instead of calling
    `mark_inconclusive`; on `CONNECTIVITY`, keep `mark_inconclusive` with
    reason text naming the connectivity signal
    - _Requirements: 2.1, 3.1_
  - [ ] 2.2 `check_rid_cycling`: same pattern, finding titled "Anonymous RID
    cycling refused"
    - _Requirements: 2.1, 3.1_
  - [ ] 2.3 `check_ldap_anonymous_bind`: same pattern, finding titled
    "Anonymous LDAP bind refused"
    - _Requirements: 2.1, 3.1_
  - [ ] 2.4 Unit tests for Category A checks (required, not optional)
    - Per check: `..._access_denied_is_finding_not_inconclusive` (using the
      reported-bug-shaped fixture; asserts `res.status == "findings"`,
      `res.inconclusive is False`, an INFO-severity finding with the exact
      title present) and `..._connection_refused_stays_inconclusive` (asserts
      `res.inconclusive is True`, `res.findings == []`)
    - _Requirements: 2.1, 3.1, 3.3, 4.1_

- [ ] 3. Update Category B on-login-module checks in `unauthenticated.py`
  - [ ] 3.1 `check_smbghost`, `check_eternalblue`, `check_zerologon`,
    `check_printnightmare`: replace `looks_like_failure(text)` with
    `classify_failure(text)`; both `CONNECTIVITY` and `ACCESS_DENIED` keep
    `mark_inconclusive`; the `ACCESS_DENIED` reason text states the
    null-session login was refused and the module did not run; the
    `CONNECTIVITY` reason text is the existing wording with the signal name
    substituted from `classify_failure`'s result
    - _Requirements: 2.2, 2.4, 2.5, 3.1, 4.1_
  - [ ] 3.2 `check_timeroast`: same substitution; reason text uses generic
    "the login was refused" wording (not "null-session" specifically) since
    this check has an authenticated-or-null fork and an access-denied
    classification can occur on either branch
    - _Requirements: 2.2, 2.4, 2.5, 3.1, 4.1_
  - [ ] 3.3 Unit tests for Category B checks in `unauthenticated.py`
    (required for every check in this task, not a sample)
    - Add module-level `SMBGHOST_BUG_FIXTURE` constant (exact text from the
      reported bug) near the top of `tests/test_checks.py`
    - `check_smbghost`:
      `test_smbghost_bug_fixture_stays_inconclusive_with_access_denied_reason`
      using `SMBGHOST_BUG_FIXTURE` verbatim, asserting `res.inconclusive is
      True` and kind-specific wording in `res.inconclusive_reason`; keep
      existing `test_smbghost_inconclusive_on_failure` unmodified and assert
      its reason text does NOT contain the access-denied-specific wording
    - `check_eternalblue`: new `..._access_denied_stays_inconclusive_with_specific_reason`;
      keep existing `test_eternalblue_inconclusive_on_connection_failure`
      unmodified
    - `check_zerologon`: new `..._access_denied_stays_inconclusive_with_specific_reason`
      AND new `test_zerologon_connection_refused_stays_inconclusive` (no
      prior connectivity test existed for this check)
    - `check_printnightmare`: new
      `..._access_denied_stays_inconclusive_with_specific_reason`; keep the
      existing connection-failure test for this check unmodified
    - `check_timeroast`: new
      `..._access_denied_stays_inconclusive_with_specific_reason`; keep the
      existing connection-failure test for this check unmodified
    - _Requirements: 2.2, 2.4, 2.5, 3.1, 3.3, 4.1_

- [ ] 4. Update `sccm.py`
  - [ ] 4.1 `check_sccm_pxe_naa`: replace `looks_like_failure(text)` with
    `classify_failure(text)` on the null-session branch; same reason-text
    pattern as task 3.2 (`check_sccm_discovery` is NOT touched - it has no
    null-probe branch)
    - _Requirements: 2.2, 2.4, 2.5, 3.1, 4.1_
  - [ ] 4.2 Unit tests in `tests/test_sccm.py` (required)
    - `test_sccm_pxe_naa_access_denied_stays_inconclusive_with_specific_reason`
      (null branch); keep the existing connection-failure equivalent for this
      check unmodified
    - _Requirements: 2.2, 2.4, 2.5, 3.1, 4.1_

- [ ] 5. Update the authenticated-phase post-processor
  - [ ] 5.1 `_mark_inconclusive_on_failure` in `authenticated.py`: use
    `classify_failure` instead of `looks_like_failure`; keep marking
    inconclusive for *both* kinds (rejected supplied credentials are still
    ambiguous, not a hardening signal); reason text names which kind matched
    - _Requirements: 2.5, 3.1, 4.1, 4.3_
  - [ ] 5.2 Extend the existing
    `test_auth_failure_marked_inconclusive_by_run_all_postprocess` test with
    a third `CheckResult` whose `raw_output` is access-denied-shaped text,
    asserting it is also marked inconclusive
    - _Requirements: 2.5, 3.1, 4.1, 4.3_

- [ ] 6. Surface `Null Auth:True` as evidence context on `check_smb_signing` (optional polish, non-blocking)
  - [ ] 6.1 When the SMB banner includes `Null Auth:True` or `Null
    Auth:False`, append it to the existing signing/SMBv1 finding's evidence
    string; do not create a new finding, change severity, or affect status
    - _Requirements: 5.1, 5.2_
  - [ ] 6.2 Unit test asserting a fixture containing only `Null Auth:True`
    (no other signal) never flips `classify_failure`'s result or this
    check's status
    - _Requirements: 5.1, 5.2_

- [ ] 7. Verification gate
  - [ ] 7.1 Run `pytest -q` from the worktree root BEFORE making any code
    change and record that the baseline is green
    - _Requirements: consolidated Acceptance Criteria 6_
  - [ ] 7.2 After implementing tasks 1-6, run `pytest -q` from the worktree
    root again; it must pass with zero failures
    - _Requirements: consolidated Acceptance Criteria 1-6_
  - [ ] 7.3 Run `ruff check .` from the worktree root; it must pass with zero
    findings
    - _Requirements: consolidated Acceptance Criteria 7_
  - [ ] 7.4 Diff `tests/test_checks.py` and `tests/test_sccm.py` against
    their pre-change versions and confirm every pre-existing
    connectivity-failure assertion is present and unmodified
    - _Requirements: consolidated Acceptance Criteria 8_

- [ ] 8. Commit the spec
  - [ ] 8.1 Commit `requirements.md`, `design.md`, `tasks.md` under
    `.kiro/specs/reduce-check-false-positives/` as a standalone commit in the
    worktree
    - _Requirements: (process, not a product requirement)_

## Notes

- No task in this plan is optional/skippable test authoring; every test
  subtask is required for the gate in task 7 to be considered passed, per
  the brief's "unit tests for both cases ... for all or a representative
  sample" being satisfied here by covering *all* affected checks, not a
  sample.
- `check_webdav`, `check_ntlmv1`, `check_ntlm_reflection`,
  `check_ldap_relay_exposure`, `check_smb_signing` (core signing/SMBv1
  behavior), `check_sccm_discovery`, `check_kerberos_user_enum`,
  `check_gpp_cpassword`, `check_dns_zone_transfer`, `check_asrep_roast`,
  `check_cisco_smart_install`, `check_anonymous_ftp_nfs`,
  `check_snmp_default_community`, `check_ipmi_hash_disclosure`,
  `check_name_poisoning` require no code change per the design's per-check
  table (Requirement 4.1/4.2) and have no task here beyond the regression
  confirmation in task 7.2/7.4.
- Task 6 (`Null Auth:True` evidence) is explicitly optional polish per
  Requirement 5.2's "MAY"; it does not gate task 7 and may be dropped without
  affecting any Acceptance Criterion, but is included with a required test
  (6.2) if implemented, since an implemented-but-untested change is not
  acceptable even for optional scope.
- The implementation uses Python 3.11+, pure stdlib, matching the existing
  codebase; no new dependencies are introduced.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["7.1"] },
    { "id": 1, "tasks": ["1.1"] },
    { "id": 2, "tasks": ["1.2"] },
    { "id": 3, "tasks": ["1.3", "2.1", "2.2", "2.3", "3.1", "3.2", "4.1", "5.1", "6.1"] },
    { "id": 4, "tasks": ["1.4", "2.4", "3.3", "4.2", "5.2", "6.2"] },
    { "id": 5, "tasks": ["7.2", "7.3", "7.4"] },
    { "id": 6, "tasks": ["8.1"] }
  ]
}
```
