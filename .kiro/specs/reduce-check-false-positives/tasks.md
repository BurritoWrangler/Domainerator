# Implementation Plan: Reduce Check False Positives

## Overview

This plan implements the `classify_failure`/`FailureKind` split in
`checks/__init__.py`, applies it to every affected check in
`unauthenticated.py` and `sccm.py`, updates the authenticated-phase
post-processor to use the new classifier while keeping its current
inconclusive-on-either-kind behavior, and adds unit tests for both the
genuine-connectivity-failure and access-denied-to-null-probe cases. It
finishes with the `pytest -q` / `ruff check .` verification gate.

## Tasks

- [ ] 1. Add `FailureKind` and `classify_failure` to `checks/__init__.py`
  - [ ] 1.1 Replace `_FAILURE_SIGNALS` with `_CONNECTIVITY_FAILURE_SIGNALS` and `_ACCESS_DENIED_SIGNALS`
    - Add `import enum` to `src/domainerator/checks/__init__.py`
    - Define `_CONNECTIVITY_FAILURE_SIGNALS` (connection refused, timed out, no route to host, unable to connect, could not connect, error, traceback, `[-]`)
    - Define `_ACCESS_DENIED_SIGNALS` (access_denied, status_access_denied, logon_failure, status_logon_failure)
    - _Requirements: 1.1, 1.2, 1.3, 1.5, 3.1_
  - [ ] 1.2 Implement `FailureKind` enum and `classify_failure()`
    - `FailureKind` with `CONNECTIVITY` and `ACCESS_DENIED` members
    - `classify_failure(output) -> tuple[FailureKind, str] | None`, checking connectivity signals before access-denied signals so a line with both classifies as `CONNECTIVITY`
    - _Requirements: 1.1, 1.4_
  - [ ] 1.3 Reimplement `looks_like_failure()` as a thin wrapper over `classify_failure()`
    - Keep its exact current signature (`str -> str | None`) for any unconverted call sites
    - _Requirements: 3.1_
  - [ ]* 1.4 Unit tests for `classify_failure` and `looks_like_failure`
    - `test_classify_failure_connectivity_only`
    - `test_classify_failure_access_denied_only`
    - `test_classify_failure_both_present_is_connectivity`
    - `test_classify_failure_null_auth_banner_is_not_a_signal`
    - `test_looks_like_failure_still_detects_both_kinds`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 5.1_

- [ ] 2. Update Category A checks (anonymous-access-is-the-test) in `unauthenticated.py`
  - [ ] 2.1 `check_null_session`: on `ACCESS_DENIED`, add an INFO finding ("Anonymous SMB session refused") instead of `mark_inconclusive`; on `CONNECTIVITY`, keep `mark_inconclusive`
    - _Requirements: 2.1, 2.5, 3.1_
  - [ ] 2.2 `check_rid_cycling`: same pattern ("Anonymous RID cycling refused")
    - _Requirements: 2.1, 2.5, 3.1_
  - [ ] 2.3 `check_ldap_anonymous_bind`: same pattern ("Anonymous LDAP bind refused")
    - _Requirements: 2.1, 2.5, 3.1_
  - [ ]* 2.4 Unit tests for Category A checks
    - Per check: `..._access_denied_is_not_inconclusive` (reported-bug-shaped fixture; asserts `not res.inconclusive` and an INFO finding present) and `..._connectivity_failure_stays_inconclusive` (asserts `res.inconclusive is True`)
    - _Requirements: 2.1, 2.4, 2.5, 3.1, 4.1_

- [ ] 3. Update Category B checks (auth-independent detection) in `unauthenticated.py`
  - [ ] 3.1 `check_webdav`, `check_ntlmv1`, `check_ntlm_reflection`, `check_timeroast`: replace `looks_like_failure(text)` with `classify_failure(text)`; only `mark_inconclusive` on `CONNECTIVITY`; let `ACCESS_DENIED` fall through to the existing "no recognizable output" `elif` guard unchanged
    - _Requirements: 2.2, 2.4, 3.1, 3.2, 4.1_
  - [ ] 3.2 `check_eternalblue`, `check_zerologon`, `check_smbghost`, `check_printnightmare`: same substitution
    - _Requirements: 2.2, 2.4, 3.1, 3.2, 4.1_
  - [ ]* 3.3 Unit tests for Category B checks
    - `check_smbghost`: `test_smbghost_access_denied_is_clean_not_inconclusive` using the exact reported-bug fixture (banner line + `STATUS_ACCESS_DENIED`); keep existing `test_smbghost_inconclusive_on_failure` as the connectivity regression guard
    - `check_eternalblue`, `check_zerologon`, `check_webdav`, `check_ntlmv1`: one new `..._access_denied_is_not_inconclusive` test each; keep existing `..._inconclusive_on_connection_failure`/`..._inconclusive_on_unrecognized_output` tests as regression guards
    - _Requirements: 2.2, 2.4, 2.5, 3.1, 3.2, 4.1_

- [ ] 4. Update `sccm.py` checks
  - [ ] 4.1 `check_sccm_discovery` and `check_sccm_pxe_naa`: replace `looks_like_failure(text)` with `classify_failure(text)`, same Category B fallthrough pattern
    - _Requirements: 2.2, 2.4, 3.1, 3.2, 4.1_
  - [ ]* 4.2 Unit tests in `tests/test_sccm.py`
    - `test_sccm_discovery_access_denied_falls_through`
    - `test_sccm_pxe_naa_access_denied_falls_through`
    - _Requirements: 2.2, 2.4, 3.1, 4.1_

- [ ] 5. Update the authenticated-phase post-processor
  - [ ] 5.1 `_mark_inconclusive_on_failure` in `authenticated.py`: use `classify_failure` instead of `looks_like_failure`; keep marking inconclusive for *both* `CONNECTIVITY` and `ACCESS_DENIED` kinds (rejected supplied credentials are still ambiguous, not a hardening signal); improve `inconclusive_reason` text to name which kind matched
    - _Requirements: 2.3, 2.5, 3.1, 4.1_
  - [ ]* 5.2 Extend `test_auth_failure_marked_inconclusive_by_run_all_postprocess` with a third `CheckResult` whose `raw_output` is `"STATUS_ACCESS_DENIED"`, asserting it is also marked inconclusive
    - _Requirements: 2.3, 3.1, 4.1_

- [ ] 6. Surface `Null Auth:True` as evidence context on `check_smb_signing` (optional polish)
  - [ ] 6.1 When the SMB banner includes `Null Auth:True` or `Null Auth:False`, append it to the existing signing/SMBv1 finding's evidence text; do not create a new finding, change severity, or affect status
    - _Requirements: 5.1, 5.2_
  - [ ]* 6.2 Unit test asserting `Null Auth:True` alone (no other signal) never flips status via `classify_failure`
    - _Requirements: 5.1, 5.2_

- [ ] 7. Verification gate
  - [ ] 7.1 Run `pytest -q` from the worktree root and fix any failures
    - _Requirements: Acceptance Criteria 5_
  - [ ] 7.2 Run `ruff check .` from the worktree root and fix any findings
    - _Requirements: Acceptance Criteria 6_
  - [ ] 7.3 Confirm no existing connectivity-failure test was weakened or deleted (diff review of `tests/test_checks.py`, `tests/test_sccm.py`)
    - _Requirements: Acceptance Criteria 7_

- [ ] 8. Commit the spec
  - [ ] 8.1 Commit `requirements.md`, `design.md`, `tasks.md` under `.kiro/specs/reduce-check-false-positives/` as a standalone commit in the worktree
    - _Requirements: (process, not a product requirement)_

## Notes

- Tasks marked with `*` are optional test-authoring subtasks; skipping them
  entirely is not acceptable per the brief ("unit tests for both cases ...
  for all or a representative sample of affected checks" is a hard
  requirement), but individual `*` tasks may be consolidated if a single
  test function covers multiple checks' identical shape.
- `check_smb_signing` requires no behavior change for the core bug fix; task
  6 is the only work item touching it, and it is explicitly optional polish
  per design (Requirement 5.2 says evidence text "MAY" be added).
- `check_kerberos_user_enum`, `check_asrep_roast`, `check_cisco_smart_install`,
  `check_anonymous_ftp_nfs`, `check_snmp_default_community`,
  `check_ipmi_hash_disclosure`, `check_name_poisoning`,
  `check_ldap_relay_exposure`, `check_dns_zone_transfer` are confirmed
  unaffected during design (Requirement 4.2) and have no task here.
- The implementation uses Python 3.11+, pure stdlib, matching the existing
  codebase; no new dependencies are introduced.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["1.3", "2.1", "2.2", "2.3", "3.1", "3.2", "4.1", "5.1", "6.1"] },
    { "id": 3, "tasks": ["1.4", "2.4", "3.3", "4.2", "5.2", "6.2"] },
    { "id": 4, "tasks": ["7.1", "7.2", "7.3"] },
    { "id": 5, "tasks": ["8.1"] }
  ]
}
```
