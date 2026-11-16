# Design Document: Reduce Check False Positives

## Overview

This design splits the single `looks_like_failure()` signal into two
distinct classifications - `CONNECTIVITY` and `ACCESS_DENIED` - implemented
as a `classify_failure()` function in `src/domainerator/checks/__init__.py`,
and changes each affected check's reason text (and, for three checks, its
finding/status) based on which one matched. The classifier orders
connectivity signals first so a broken connection is never read as a mere
hardening signal, then checks a specific access-denied status code, then
falls back to the existing generic "`[-]`-with-nothing-more-specific" case as
a connectivity-style result. Three checks whose own purpose *is* testing
anonymous access (`check_null_session`, `check_rid_cycling`,
`check_ldap_anonymous_bind` - "Category A") convert a definitive
access-denied into an explicit INFO finding instead of silence, which
changes their `status` from `inconclusive` to `findings` (there is no
`clean`-with-note mechanism on `CheckResult` today, and adding one is more
invasive than the bug justifies - see "Status model" below). Every other
null-probing check in scope depends on a NetExec on-login module
(`-M <module>`), which by NetExec's own execution model never runs when the
login is denied; for these ("Category B"), the result legitimately stays
`inconclusive`, but the reason text is rewritten to say specifically "null
session login refused, module did not run" instead of a generic "output
shows '<signal>'" string that reads identically to a connectivity failure.
The authenticated-phase generic post-processor (`authenticated.py`,
"Category C") keeps marking both kinds `inconclusive`, since there access-
denied means the *supplied* credentials were rejected, not that null-session
hardening was detected - but its reason text is likewise clarified. No change
to `CheckResult`'s fields, `to_dict()`, or the status-precedence order in
`runner.py`. No new dependencies; stack stays pure-stdlib Python 3.11+.

## Architecture

### Signal classification (`checks/__init__.py`)

```python
import enum

class FailureKind(enum.Enum):
    CONNECTIVITY = "connectivity"
    ACCESS_DENIED = "access_denied"


# Signals meaning the scan could not reliably reach/test the target, or the
# module/output format is in a state we can't specifically identify. A "no
# finding" result alongside one of these is inconclusive for a reason
# unrelated to the target's hardening posture.
_CONNECTIVITY_FAILURE_SIGNALS = (
    "connection refused",
    "connection timed out",
    "timed out",
    "no route to host",
    "unable to connect",
    "could not connect",
    "authentication failed",
    "error",
    "traceback",
)

# A specific status code meaning the target was reached and explicitly
# refused the null-session/anonymous credential. Checked only after
# confirming no connectivity signal is present, and only after confirming no
# bare, unqualified "[-]" is the sole signal (see classify_failure).
_ACCESS_DENIED_SIGNALS = (
    "access_denied",
    "status_access_denied",
    "logon_failure",
    "status_logon_failure",
)


def classify_failure(output: str) -> tuple[FailureKind, str] | None:
    """Classify a failure-like signal in ``output``, or return None.

    Order of evaluation, and why:

    1. ``_CONNECTIVITY_FAILURE_SIGNALS`` first. A genuine connectivity
       failure makes the whole result unreliable even if access-denied text
       also appears elsewhere in the same output (Requirement 1.2).
    2. ``_ACCESS_DENIED_SIGNALS`` next. If none of the above matched, a
       specific access-denied status code means the target was reached and
       explicitly refused the probe - more informative than a bare ``[-]``,
       so it is returned even though the same line may also contain ``[-]``
       (NetExec's negative-result marker always precedes its status detail,
       e.g. ``"[-] abcdomain.com\\: STATUS_ACCESS_DENIED"``), satisfying
       Requirement 1.4's "specific code outranks the generic marker" rule.
    3. A bare ``"[-]"`` with neither of the above present. This is NetExec's
       generic negative-result marker with no specific reason attached - we
       cannot tell *why* the module failed, so treat it the same as a
       connectivity failure rather than silently returning ``None``
       (Requirement 1.4, Requirement 3.1).
    4. Otherwise, ``None``.
    """
    lowered = output.lower()
    for signal in _CONNECTIVITY_FAILURE_SIGNALS:
        if signal in lowered:
            return (FailureKind.CONNECTIVITY, signal)
    for signal in _ACCESS_DENIED_SIGNALS:
        if signal in lowered:
            return (FailureKind.ACCESS_DENIED, signal)
    if "[-]" in lowered:
        return (FailureKind.CONNECTIVITY, "[-]")
    return None


def looks_like_failure(output: str) -> str | None:
    """Backward-compatible wrapper: any failure-like signal, or None.

    Returns the matched signal string regardless of kind, exactly like the
    function it replaces. Kept because a handful of call sites
    (``check_kerberos_user_enum``, ``check_gpp_cpassword``,
    ``_mark_inconclusive_on_failure``'s pre-existing shape, and the nmap-based
    checks) only need "is something wrong", not the kind - see the per-check
    table below for exactly which call sites keep using this wrapper
    unconverted, and why each one is safe to leave unconverted.
    """
    found = classify_failure(output)
    return found[1] if found else None
```

This resolves the review's ordering finding directly against the reported
fixture: `classify_failure("...[*] Windows Server 2019 ... (Null
Auth:True)\n[-] abcdomain.com\\: STATUS_ACCESS_DENIED")` checks the
connectivity tuple first (no match - `"[-]"` is not in that tuple anymore),
then the access-denied tuple, where `"status_access_denied"` matches,
returning `(FailureKind.ACCESS_DENIED, "status_access_denied")`. A fixture
containing `"[-] abcdomain.com\\: STATUS_ACCESS_DENIED"` *and*
`"Connection refused"` still matches the connectivity tuple first and returns
`CONNECTIVITY`, per Requirement 1.2/3.3. A fixture with only a bare `"[-]
something unrelated"` (no access-denied text, no connectivity text) falls to
step 3 and returns `CONNECTIVITY` with signal `"[-]"`, preserving today's
"bare `[-]` means inconclusive" behavior exactly (Requirement 1.4, Requirement
3.1) - this is a deliberate behavior-preservation, not a new feature.
`"authentication failed"` is kept in the connectivity tuple (dropped from
neither tuple, contrary to an earlier draft of this design), since no
call site in this codebase distinguishes it from a connectivity-style
failure and removing it would be an unjustified weakening of Requirement 3.1.

### Status model: why Category A uses an INFO finding, not a new `clean`-with-note field

`CheckResult.status` (runner.py, unchanged by this design) evaluates, in
order: `skipped` -> `error` -> `findings` (if `self.findings` truthy) ->
`inconclusive` -> `clean`. There is no field today that means "ran, found
nothing notable, but here's a note" distinct from "ran and truly found
nothing" (`clean` with an empty findings list and `inconclusive=False`) - a
hand-written note on a clean result would be invisible to `to_dict()`,
report code, and summary/exit-code logic alike, since none of those read
anything off a `clean` result besides its name and category. Two options were
considered: (a) add a new `CheckResult.note: str = ""` field, threaded through
`to_dict()` and report rendering, to carry a "probe refused" message on an
otherwise-`clean` result; (b) add an `INFO`-severity `Finding`, which is
already a first-class, fully-rendered concept everywhere `findings` is
consumed. Option (a) touches `runner.py` (new field, `to_dict()` entry) and
every report-rendering call site that iterates a clean result without
expecting a note, none of which were read in option (a)'s favor before this
decision; option (b) touches zero files outside `checks/unauthenticated.py`
and reuses a dataclass, enum, and `add_finding()` call that already exist and
are already rendered by every consumer of `CheckResult` (report text, JSON
export, console display) without any additional code, because `Severity.INFO`
is the lowest tier of the same enum every other finding uses. Option (b) is
chosen. The accepted cost, stated plainly per Requirement 2.1's parenthetical:
`status` becomes `"findings"`, not `"clean"`, for a Category A check that hit
this branch; `max_severity` for that result is `Severity.INFO` (the enum's
lowest value), so any severity-ordered report, summary, or `--fail-on`-style
gate that filters or sorts by severity places this result at the bottom of
its findings, indistinguishable in ranking from "no issue, zero severity"
results would have been - this repo's `--fail-on`/exit-code logic (grepped:
none found; no CLI flag of that name exists in this codebase today, per
`grep -rn "fail.on\|exit_code\|sys.exit" src/domainerator/` returning no
matches tying exit codes to finding counts) does not currently key off
finding *count* at all, only off `status`/severity values read per-check, so
an added INFO finding does not change any pass/fail decision already made by
existing code; it only adds a line to that check's rendered output and
.contributes an `INFO` to that check's `max_severity`. This is the intended,
accepted trade-off: Requirement 2.1 explicitly asks for the refusal to be
visible, and INFO is the correct severity tier for "nothing to remediate, but
noteworthy."

### Why `check_smbghost` (and seven other checks) cannot report `clean` on access-denied

NetExec's `-M <module>` mechanism executes module logic from connection
on-login hooks: the module's checks run only after `smb_login` (or
`ldap_login`) succeeds, including for a null/anonymous session. When the
null-session login itself returns `STATUS_ACCESS_DENIED`, the on-login hook
never fires, so the module prints nothing - no `smbghost`/`CVE-2020-0796`
line, no `VULNERABLE`/`not vulnerable` line, nothing the existing "no
recognizable output" `elif` guards look for. This is confirmed directly
against the reported bug's own fixture: the raw output
(`result.raw_output = out.combined`, i.e. stdout+stderr only - the command
string the user saw printed separately in their bug report is never part of
`out.combined`) contains no substring matching `smbghost|cve-2020-0796|not
vulnerable`, so `check_smbghost`'s existing `elif not re.search(...)` branch
fires and the result is `inconclusive` "no recognizable output" *regardless*
of how Requirement 1's connectivity/access-denied split is implemented. The
same is true for every other on-login-module check. Reporting `clean` here
would be a false negative: the scan did not establish that the host is *not*
vulnerable to SMBGhost, it established that the null session couldn't even
start the test. The fix implemented here is Requirement 2.2's choice (a):
these checks stay `inconclusive`, with the reason text changed from the
current generic `f"SMBGhost check inconclusive; output shows '{signal}'"`
(identical in shape whether `signal` is `"timed out"` or
`"status_access_denied"`, which is the actual root cause of the reported
noise - two very different situations rendered as the same sentence shape) to
a reason that names the specific kind:

```python
kind, signal = classify_failure(text)
if kind is FailureKind.ACCESS_DENIED:
    result.mark_inconclusive(
        "SMBGhost check inconclusive: null-session login was refused "
        f"('{signal}'); the smbghost module runs on a successful login and "
        "did not execute, so this host's SMBGhost status is unknown, not "
        "confirmed clean"
    )
elif kind is FailureKind.CONNECTIVITY:
    result.mark_inconclusive(
        f"SMBGhost check inconclusive: connectivity failure ('{signal}')"
    )
elif not re.search(r"smbghost|cve-2020-0796|not vulnerable", text, re.IGNORECASE):
    result.mark_inconclusive(
        "smbghost module produced no recognizable output (module "
        "unavailable or output changed)"
    )
```

This does not change `status` (still `"inconclusive"`) for this check or any
of the other seven on-login-module checks in Category B, and that is by
design: it is the accurate outcome, not a workaround. What it changes is
whether the *operator* can tell, from the reason text alone and without
reading raw output, that "null session refused" (try with real credentials,
or accept this host is hardened against anonymous probing in general) is a
fundamentally different triage action from "connection failed" (check network
reachability, firewall, host up). That distinction, consistently applied
across all affected checks, is the noise reduction this design delivers for
Category B; it does not, and per the module-execution-model constraint
cannot, reduce the raw *count* of `inconclusive` results for these checks.

### Per-check table (grepped, not recalled from memory)

Produced by `grep -n "looks_like_failure" src/domainerator/checks/*.py
src/domainerator/checks/authenticated.py` plus reading each call site's
surrounding function in full.

| Check | File:line | Credential mode | Calls `looks_like_failure`? | Category | Change |
|---|---|---|---|---|---|
| `check_null_session` | `unauthenticated.py:171` | null only (`-u "" -p ""`) | yes | A | Replace with `classify_failure`; `ACCESS_DENIED` -> add INFO finding, no `mark_inconclusive`; `CONNECTIVITY` -> `mark_inconclusive` (reason unchanged in meaning, kind-specific wording) |
| `check_rid_cycling` | `unauthenticated.py:258` | null only | yes | A | same pattern |
| `check_ldap_anonymous_bind` | `unauthenticated.py:306` | null only | yes | A | same pattern |
| `check_smbghost` | `unauthenticated.py:1523` | null only | yes | B (on-login module) | Replace with `classify_failure`; both kinds stay `mark_inconclusive`, reason text names the kind |
| `check_eternalblue` | `unauthenticated.py:1171` | null only | yes | B (on-login module) | same pattern |
| `check_zerologon` | `unauthenticated.py:1257` | null only | yes | B (on-login module) | same pattern |
| `check_printnightmare` | `unauthenticated.py:1606` | null only | yes | B (on-login module) | same pattern |
| `check_timeroast` | `unauthenticated.py:1009` | auth-or-null fork | yes | B (on-login module); null branch only | same pattern (an access-denied classification can only occur on the null branch - authenticated creds that fail SMB login would also show `access_denied`-style text, so the reason wording is written generically as "login was refused", not "null-session login was refused", for this one check - see Edge Cases) |
| `check_sccm_pxe_naa` | `sccm.py` (`check_sccm_pxe_naa`) | auth-or-null fork | yes | B (on-login module); null branch only | same pattern, same generic-wording note as `check_timeroast` |
| `check_webdav` | `unauthenticated.py:777` | auth-or-null fork | **no** - uses `if not re.search(r"webdav\|webclient", ...)` | B in spirit, already correct | No code change. Access-denied text alone does not satisfy this regex, so the existing branch already reports `inconclusive` for "module didn't run" reasons without ever referencing access-denied text. Confirmed by reading the full function: no `looks_like_failure` call exists here today. |
| `check_ntlmv1` | `unauthenticated.py:849` | auth-or-null fork | **no** - `if not re.search(r"ntlmv1\|lmcompatibility", ...)` | B in spirit, already correct | No code change, same reasoning as `check_webdav` |
| `check_ntlm_reflection` | `unauthenticated.py:920` | auth-or-null fork | **no** - `if not re.search(r"reflection", ...)` | B in spirit, already correct | No code change, same reasoning |
| `check_smb_signing` | `unauthenticated.py:58` | null only | **no** - inconclusive only when `signing:` banner absent | Banner-based, unaffected | No behavior change. Optional: append `Null Auth:True`/`False` to the existing finding's evidence text (Requirement 5.2) |
| `check_sccm_discovery` | `sccm.py` | authenticated only (`target.nxc_auth_args()`), never null | yes | Out of scope (Requirement 4.3) | No change - access-denied here means supplied creds were rejected, a Category C situation, not Category A/B |
| `check_ldap_relay_exposure` | `unauthenticated.py:391` | auth-or-null fork | **no** - `if not re.search(r"signing\|channel binding", ...)` | Already correct, no null-probe-specific bug | No change |
| `check_kerberos_user_enum` | `unauthenticated.py:687` | `kerbrute`, not nxc | yes | Out of scope | No change - kerbrute output has no SMB/LDAP status codes; `looks_like_failure` wrapper is safe to leave as-is since neither new tuple introduces a false match on kerbrute's own vocabulary ("KDC unreachable" still matches `_CONNECTIVITY_FAILURE_SIGNALS` via no substring change needed) |
| `check_gpp_cpassword` | `authenticated.py` | authenticated only | yes | Out of scope | No change - supplied-credential rejection, Category C semantics, same reasoning as `check_sccm_discovery` |
| `_mark_inconclusive_on_failure` | `authenticated.py` | authenticated only, generic post-processor over every authenticated CheckResult | yes | C | Use `classify_failure`; keep marking inconclusive for **both** kinds (rejected supplied creds are still ambiguous); reason text names the kind |

Checks re-verified as having **no** null probe and **no** `looks_like_failure`
call combined (confirmed via the same grep, listed for completeness per
Requirement 4.2, no change): `check_dns_zone_transfer`, `check_asrep_roast`,
`check_cisco_smart_install`, `check_anonymous_ftp_nfs`,
`check_snmp_default_community`, `check_ipmi_hash_disclosure`,
`check_name_poisoning`.

### Edge cases

- **Mixed signal, both present in one line** (the reported bug's actual
  shape: `"[-] abcdomain.com\: STATUS_ACCESS_DENIED"` contains both `[-]` and
  the access-denied status): handled by evaluation order in
  `classify_failure` - step 2 (access-denied) is checked, and matches, before
  step 3 (bare `[-]` fallback) is ever reached, so this is not actually a
  "mixed" case in the classifier's own terms; it is a clean ACCESS_DENIED
  match. A genuinely mixed case - connectivity text and access-denied text in
  the same output, e.g. a timeout on one line and a `STATUS_ACCESS_DENIED` on
  another (possible if NetExec retries and the second attempt is denied after
  the first timed out) - is covered by step 1 taking priority unconditionally,
  tested explicitly (see Testing Strategy, test 3).
- **`check_timeroast` / `check_sccm_pxe_naa` authenticated-branch
  access-denied**: when `target.authenticated` is true, these two checks use
  `target.nxc_auth_args()`, not a null probe, so an access-denied there means
  the *supplied* credentials were rejected, not that null-session hardening
  was detected. Both checks' new `ACCESS_DENIED`-branch reason text is worded
  generically ("the login was refused") rather than "the null-session login
  was refused", so it reads correctly in either branch without needing to
  thread `target.authenticated` into the message. The underlying `status`
  outcome (`inconclusive`) is identical in both branches, so this wording
  choice has no behavioral effect, only a cosmetic one, and is called out
  here so a future reader does not mistake the generic wording for an
  oversight.
- **A check's own vulnerability regex and the access-denied signal both
  match** (a module ran, found nothing vulnerable, and also printed
  `STATUS_ACCESS_DENIED` for an unrelated secondary probe within the same
  nxc invocation - not observed in any current check's output shape, but
  structurally possible for multi-step modules): `classify_failure` is only
  consulted inside the `else` branch that already gates on "no finding was
  made" (`result.findings` is empty at that point for every check in this
  table), so if the vulnerability regex matched, a `Finding` is added and the
  `else`/`elif` chain containing `classify_failure` is never reached at all -
  `mark_inconclusive` is a no-op once a finding exists regardless. No new
  code is needed for this case; it falls out of the existing `if
  vulnerable: ... else: ...` control flow untouched by this design.
- **Finding/evidence truncation**: Category A's new INFO finding uses the
  same `text[:500]` truncation pattern already used by every other finding in
  `unauthenticated.py` (e.g. `check_ldap_anonymous_bind`'s existing
  `evidence=out.combined[:500]`), so no new truncation logic is introduced.

## Components and Interfaces

| Component | File | Change |
|---|---|---|
| `FailureKind`, `classify_failure`, `_CONNECTIVITY_FAILURE_SIGNALS`, `_ACCESS_DENIED_SIGNALS` | `src/domainerator/checks/__init__.py` | New. Replaces the single `_FAILURE_SIGNALS` tuple. `looks_like_failure` kept as a thin wrapper, used unconverted by `check_kerberos_user_enum`, `check_gpp_cpassword`, and the nmap/raw-socket checks listed in Requirement 4.2 (none of which need the kind distinction). |
| `check_null_session`, `check_rid_cycling`, `check_ldap_anonymous_bind` | `src/domainerator/checks/unauthenticated.py` | Replace `looks_like_failure(text)` with `classify_failure(text)`; on `ACCESS_DENIED`, add an INFO `Finding` instead of `mark_inconclusive`; on `CONNECTIVITY`, keep `mark_inconclusive` with kind-specific wording. |
| `check_smbghost`, `check_eternalblue`, `check_zerologon`, `check_printnightmare`, `check_timeroast` | `src/domainerator/checks/unauthenticated.py` | Replace `looks_like_failure(text)` with `classify_failure(text)`; both kinds keep `mark_inconclusive`, reason text names the kind (null-session-refused vs connectivity) per the per-check table. |
| `check_sccm_pxe_naa` | `src/domainerator/checks/sccm.py` | Same substitution as the Category B unauthenticated.py checks, null branch only. |
| `_mark_inconclusive_on_failure` | `src/domainerator/checks/authenticated.py` | Use `classify_failure`; keep marking inconclusive for both kinds; reason text names the kind. |
| `check_smb_signing` | `src/domainerator/checks/unauthenticated.py` | No behavior change. Optionally append `Null Auth:True`/`False` to the existing finding's evidence string when present (Requirement 5.2). |
| `check_webdav`, `check_ntlmv1`, `check_ntlm_reflection`, `check_ldap_relay_exposure`, `check_sccm_discovery`, `check_kerberos_user_enum`, `check_gpp_cpassword` | n/a | **No change.** Listed here explicitly so the per-check table's "no change" entries are traceable to a Components-table decision, not an omission. |

No changes to `src/domainerator/runner.py`, `paths.py`, `console/`, or any
CLI entry point.

## Data Models

No new persisted data model. `CheckResult` (runner.py) is unchanged:
`inconclusive`, `inconclusive_reason`, `findings`, `status`, `to_dict()` keep
their current fields, types, and semantics. `FailureKind` is a new internal
enum in `checks/__init__.py`, never serialized, never exposed on
`CheckResult`.

For the three Category A checks, the new finding uses the existing `Finding`
dataclass (`src/domainerator/runner.py`) with:
- `severity=Severity.INFO`
- `title`: `"Anonymous SMB session refused"` (`check_null_session`),
  `"Anonymous RID cycling refused"` (`check_rid_cycling`), `"Anonymous LDAP
  bind refused"` (`check_ldap_anonymous_bind`)
- `target=target.host`
- `description`: a one-sentence statement that the null/anonymous probe was
  reached and explicitly denied, e.g. for `check_null_session`: `"The target
  explicitly refused the anonymous/NULL SMB session
  (STATUS_ACCESS_DENIED-style response) rather than the connection failing to
  complete. Anonymous share enumeration is blocked."`
- `evidence`: the matched signal plus `text[:500]`, matching the existing
  truncation pattern used elsewhere in these files
- no `remediation` (nothing to remediate - already hardened)
- no `PathStep` added (a refused null probe grants no attacker capability)

## Correctness Properties

1. **No connectivity-failure signal is ever downgraded to access-denied or
   to no-match.** For every affected check, if `classify_failure(output)`
   returns `FailureKind.CONNECTIVITY`, the result is `inconclusive` (or, for
   Category A, still `inconclusive` - Category A's `clean`-equivalent
   `findings` path is reached only on `ACCESS_DENIED`). Enforced centrally
   inside `classify_failure`'s fixed evaluation order (connectivity before
   access-denied before bare-`[-]`), not reimplemented per call site.
2. **Connectivity wins over access-denied when both are present anywhere in
   the output**, even on separate lines. Enforced once, centrally, in
   `classify_failure`'s step-1-before-step-2 order.
3. **A specific access-denied status code outranks the generic `[-]` marker
   on the same line.** `classify_failure` checks `_ACCESS_DENIED_SIGNALS`
   (step 2) before falling back to bare `"[-]"` (step 3), so
   `"[-] ...STATUS_ACCESS_DENIED"` classifies as `ACCESS_DENIED`, not
   `CONNECTIVITY`. This is the specific defect the design review identified
   and is now a named, tested property rather than an implicit side effect
   of tuple ordering.
4. **No on-login-module check ever reports `clean` or a vulnerability
   finding when its module's own result line is absent**, regardless of
   `classify_failure`'s outcome. Enforced by the unchanged `elif not
   re.search(<module-marker-pattern>, ...)` guard in each Category B check,
   which this design does not touch - `classify_failure`'s result only
   changes *which reason string* is attached when that guard's companion
   `if`/`elif` chain reaches the inconclusive branch, never whether it does.
5. **Category A's refusal finding is never emitted when a connectivity
   failure, not an access-denied code, is what the output actually shows.**
   Enforced by the explicit `if kind is FailureKind.ACCESS_DENIED: ... elif
   kind is FailureKind.CONNECTIVITY: ...` branch structure in each Category A
   check - there is no shared "anything non-None" branch that could blur the
   two.
6. **Banner-only fields never change classification.** `Null Auth:True` is
   never added to either signal tuple, so it cannot affect
   `classify_failure`'s result. Enforced by omission, verified by a unit test
   asserting a fixture containing only `Null Auth:True` (no other signal)
   returns `None`.

## Error Handling

- **`out.error` set (tool not found / spawn failure)**: unchanged in every
  check - `result.error = out.error; return result` short-circuits before
  any `classify_failure` call is reached. Fatal for that check's run;
  surfaced to the caller as `CheckResult.status == "error"`; no new logging
  (this path is pre-existing and untouched).
- **`classify_failure` receives output with no signal at all**: not an
  error; returns `None`. Each call site's existing `elif not
  re.search(...)` (Category B) or implicit fallthrough (Category A - no
  action taken, check already reported a finding or there genuinely is
  nothing to say) governs what happens next, unchanged by this design.
- **Both connectivity and access-denied signals present**: not an error;
  resolved deterministically by Correctness Property 2. No exception raised,
  no logging change.
- **Ruff/lint issues introduced by the refactor** (unused import, `enum` not
  imported, line length): caught by the verification gate (`ruff check .`)
  before commit, addressed as part of implementation, not a runtime error
  path.

`classify_failure` takes a `str` and only does substring membership tests
(`in`) after `.lower()`; `str.lower()` and `in` do not raise on any `str`
input, including the empty string, so there is no input to this function
that can raise. No new exception handling is introduced; no existing
exception handling is removed or altered.

## Validation Rules (external inputs)

The only "external input" `classify_failure` touches is tool stdout/stderr
text (`out.combined`), already a plain `str` by the time it reaches any call
site (confirmed: `ToolRunner.run` always returns a `CommandOutput` whose
`combined` attribute is populated via `str`-typed subprocess capture in
`runner.py`; this design introduces no new call path to that capture code).
No new CLI flags, config fields, or user-supplied parameters are introduced,
so there is no new validation-rule surface (required/optional/type/limits do
not apply here).

## Testing Strategy

All new tests live in `tests/test_checks.py` (and `tests/test_sccm.py` for
the two SCCM checks), following the existing `FakeRunner`/`ANON_TARGET`
pattern already used throughout those files. A shared module-level constant
holds the exact reported-bug fixture so every test referencing it uses the
identical string, not a paraphrase:

```python
SMBGHOST_BUG_FIXTURE = (
    "SMB    10.40.0.13   445   PRIFS02   [*] Windows Server 2019 Datacenter "
    "17763 x64 (name:PRIFS02) (domain:abcdomain.com) (signing:True) "
    "(SMBv1:True) (Null Auth:True)\n"
    "SMB    10.40.0.13   445   PRIFS02   [-] abcdomain.com\\: STATUS_ACCESS_DENIED"
)
```

**Unit tests for `classify_failure`/`looks_like_failure` (new, in
`tests/test_checks.py`):**

1. `test_classify_failure_connectivity_only`: `"Connection refused"` ->
   `(FailureKind.CONNECTIVITY, "connection refused")`.
2. `test_classify_failure_access_denied_only`: `"STATUS_ACCESS_DENIED"` ->
   `(FailureKind.ACCESS_DENIED, "status_access_denied")`.
3. `test_classify_failure_both_present_is_connectivity`: a string containing
   both `"Connection refused"` and `"STATUS_ACCESS_DENIED"` (on separate
   lines) -> `FailureKind.CONNECTIVITY` (Correctness Property 2).
4. `test_classify_failure_bug_fixture_is_access_denied`: `classify_failure(
   SMBGHOST_BUG_FIXTURE)` -> `(FailureKind.ACCESS_DENIED,
   "status_access_denied")` - the exact verbatim bug report fixture,
   asserting the specific status code outranks the bare `[-]` marker on the
   same line (Correctness Property 3). This is the test the prior design
   revision's hedged assertion is replaced with.
5. `test_classify_failure_bare_dash_with_no_other_signal_is_connectivity`:
   `"[-] no sccm found"` (no access-denied text, no connectivity text) ->
   `(FailureKind.CONNECTIVITY, "[-]")` - regression guard for Requirement
   1.4/3.1's "generic `[-]` stays inconclusive-worthy" behavior.
6. `test_classify_failure_null_auth_banner_is_not_a_signal`: a string
   containing only `"Null Auth:True"` -> `None` (Correctness Property 6).
7. `test_classify_failure_no_signal_returns_none`: plain unrelated output ->
   `None`.
8. `test_looks_like_failure_still_detects_both_kinds`: back-compat wrapper
   returns a truthy string for both a connectivity fixture and an
   access-denied fixture (regression guard on the kept wrapper, used by
   `check_kerberos_user_enum` and `check_gpp_cpassword`).

**Category A checks - two tests each (new):**

9. `test_null_session_access_denied_is_finding_not_inconclusive`: fixture
   with banner line + `STATUS_ACCESS_DENIED`, no READ/WRITE tokens -> assert
   `res.status == "findings"`, `res.inconclusive is False`,
   `res.findings[0].severity == Severity.INFO`,
   `res.findings[0].title == "Anonymous SMB session refused"`.
10. `test_null_session_connection_refused_stays_inconclusive`: fixture with
    `"Connection refused"`, no READ/WRITE tokens -> assert `res.inconclusive
    is True`, `res.status == "inconclusive"`, `res.findings == []`. (Existing
    `test_inconclusive_on_connection_failure` already covers
    `check_smb_signing`'s equivalent case and is kept unmodified as a second,
    independent regression guard.)
11. `test_rid_cycling_access_denied_is_finding_not_inconclusive` /
    `test_rid_cycling_connection_refused_stays_inconclusive`: same two-test
    pattern for `check_rid_cycling`.
12. `test_ldap_anonymous_bind_access_denied_is_finding_not_inconclusive` /
    `test_ldap_anonymous_bind_connection_refused_stays_inconclusive`: same
    pattern for `check_ldap_anonymous_bind`.

**Category B / on-login-module checks - two tests each, full coverage (new,
not a hedged/optional sample - every check in Requirement 4.1's Category B
list gets both tests):**

13. `test_smbghost_bug_fixture_stays_inconclusive_with_access_denied_reason`:
    `unauthenticated.check_smbghost(FakeRunner(SMBGHOST_BUG_FIXTURE),
    ANON_TARGET)` -> assert `res.inconclusive is True`,
    `res.status == "inconclusive"`, and `"refused" in
    res.inconclusive_reason` and `"STATUS_ACCESS_DENIED".lower() not in
    res.inconclusive_reason.lower()` is *not* asserted (the signal substring
    legitimately appears in the reason) - instead assert the reason text
    contains `"null-session login"` or equivalent kind-identifying wording,
    distinguishing it from the connectivity reason text asserted in test 14.
    This is the literal reported-bug fixture, run through the literal
    reported-bug check, with no conditional logic in the assertion - directly
    answering the design review's finding that the prior revision's test was
    hedged.
14. `test_smbghost_connection_refused_stays_inconclusive`: existing
    `test_smbghost_inconclusive_on_failure` (fixture: `"SMB 10.0.0.10 [-]
    connection refused"`) is kept unmodified and continues to pass -
    confirmed by running it, not assumed - plus a new assertion that its
    `inconclusive_reason` does *not* contain the access-denied-specific
    wording, so the two reasons are asserted to actually differ in text, not
    just in theory.
15. `test_eternalblue_access_denied_stays_inconclusive_with_specific_reason`
    / existing `test_eternalblue_inconclusive_on_connection_failure` (kept,
    re-run, confirmed passing) - same two-test shape for `check_eternalblue`.
16. `test_zerologon_access_denied_stays_inconclusive_with_specific_reason` /
    a new `test_zerologon_connection_refused_stays_inconclusive` (no prior
    equivalent test existed for this check; added here) - same shape for
    `check_zerologon`.
17. `test_printnightmare_access_denied_stays_inconclusive_with_specific_reason`
    / existing `test_printnightmare`-connection-failure test (kept, re-run,
    confirmed passing, fixture `"SMB 10.0.0.10 [-] timed out"`) - same shape
    for `check_printnightmare`.
18. `test_timeroast_access_denied_stays_inconclusive_with_specific_reason` /
    existing timeroast connection-failure test (kept, re-run, confirmed
    passing, fixture `"SMB 10.0.0.10 [-] nope"` - note: this existing fixture
    has no connectivity-specific substring and no access-denied substring,
    so it falls to the bare-`[-]` branch (step 3) and remains `CONNECTIVITY`
    classified, unchanged from today; re-confirmed as part of this task, not
    assumed) - same shape for `check_timeroast`.

**Category B - checks with no code change, regression-only (existing tests,
re-run and confirmed passing, no new tests required since no behavior
changed):** `check_webdav` (`test_webdav_...` existing tests), `check_ntlmv1`
(`test_ntlmv1_...`), `check_ntlm_reflection` (`test_ntlm_reflection_...`).

**`sccm.py` (new):**

19. `test_sccm_pxe_naa_access_denied_stays_inconclusive_with_specific_reason`
    (null-session branch, `target.authenticated=False`) / existing
    connection-failure equivalent for this check (kept, re-run, confirmed
    passing) - same shape as the `unauthenticated.py` Category B checks.
    `check_sccm_discovery` gets no new test - it has no null-probe branch
    (Requirement 4.1's table), so its existing `looks_like_failure`-driven
    behavior for rejected supplied credentials is unchanged and already
    covered by its existing tests.

**Category C (`authenticated.py`, new):**

20. Extend the existing
    `test_auth_failure_marked_inconclusive_by_run_all_postprocess` test with a
    third `CheckResult` whose `raw_output` is `SMBGHOST_BUG_FIXTURE`-shaped
    access-denied text, asserting it is *also* marked `inconclusive`
    (Category C keeps both kinds inconclusive - a deliberate asymmetry from
    Category A, test-locked so a future refactor doesn't accidentally turn a
    rejected *supplied* credential into a false "clean").

**Integration-level / wiring regression:** `test_new_checks_registered_in_run_all`
and the SCCM equivalent already exist and are re-run unmodified to confirm
`run_all` wiring (module registration) is untouched by this change - no new
integration test is added since no module registration, CLI flag, or console
command changes.

**What is unit- vs integration-tested:** `classify_failure` is a pure
function, unit-tested in isolation with no I/O (tests 1-8). Each check
function is unit-tested with `FakeRunner`, which stubs `ToolRunner.run` and
is itself a unit test (no real subprocess or network call), consistent with
every existing test in `tests/test_checks.py` and `tests/test_sccm.py` - this
repo's test suite contains no test that shells out to a real `nxc` binary
(confirmed by reading both files in full), and this design does not introduce
one.

**Verification gate (required, not optional):**
- Run `pytest -q` from the worktree root (`/Users/bkeil/Domainerator/.worktrees/fix-check-false-positives`)
  *before* making any code change, to record the pre-existing baseline
  (expected: all green, since this is a pure addition/clarification to
  existing passing behavior) and confirm no test is already broken for an
  unrelated reason.
- Make the implementation changes described above.
- Run `pytest -q` again; it must pass with zero failures, including every
  existing test listed as "kept, re-run, confirmed passing" above - any
  existing test whose assertion text would need to change to pass is a sign
  this design's reason-text wording conflicts with that test, and must be
  resolved by adjusting the new wording (not by weakening the existing
  assertion) before the gate is considered passed.
- Run `ruff check .` from the worktree root; it must pass with zero findings.
- Diff `tests/test_checks.py` and `tests/test_sccm.py` against their
  pre-change versions and confirm every pre-existing connectivity-failure
  assertion is present and unmodified (Requirement, consolidated Acceptance
  Criterion 8) - this is a manual review step, not an automated check, done
  immediately before commit.

## Responses to Design Review Findings

This is a revision following `design-review.md`
(`Verdict: CHANGES_REQUESTED (4 HIGH, 4 MEDIUM, 2 NIT)`). Each finding below
is addressed, with the location of the fix in this revision noted.

1. **HIGH - `[-]` outranks access-denied for the exact fixture.** Fixed.
   `classify_failure` now checks `_ACCESS_DENIED_SIGNALS` before falling back
   to a bare `"[-]"` check (step 2 before step 3), and `"[-]"`/`"error"` are
   removed from `_CONNECTIVITY_FAILURE_SIGNALS` (error/traceback are kept in
   the connectivity tuple per the review's own suggested ordering, but `[-]`
   moved to its own fallback step as the review's code sketch proposed). See
   "Signal classification" and Correctness Property 3. New test 4
   (`test_classify_failure_bug_fixture_is_access_denied`) and test 3
   (mixed connectivity+access-denied) directly test the two scenarios the
   finding called out.
2. **HIGH - Even after fix 1, the SMBGhost fixture is still inconclusive;
   "clean" would be a false negative.** Fixed by changing the design's
   premise, not by forcing a wrong "clean" result. Requirement 2.2 is
   rewritten (choice (a) from the finding's own suggested fix) to keep
   on-login-module checks `inconclusive` on access-denied, with a
   kind-specific reason. The "module output is independent of login" claim
   is removed and replaced with the opposite, correctly-cited claim (NetExec
   modules run from on-login hooks) in "Why `check_smbghost` ... cannot
   report `clean`". Test 13 asserts the verbatim fixture with no conditional.
3. **HIGH - The authoritative list of affected checks was wrong.** Fixed.
   The per-check table is regenerated from a fresh grep (shown as the command
   used) and corrected: `check_webdav`/`check_ntlmv1`/`check_ntlm_reflection`
   are marked "no call, no change"; `check_sccm_discovery` is marked
   "authenticated only, out of scope"; `check_timeroast` and
   `check_sccm_pxe_naa`'s auth-or-null fork is called out explicitly with its
   own Edge Cases entry; `check_smb_signing`'s "no call" status is retained
   and clarified; `check_ldap_relay_exposure` and `check_kerberos_user_enum`
   are both listed with their actual (no-call / out-of-scope) status.
   Authenticated.py's other inline `looks_like_failure` callers
   (`check_gpp_cpassword`) are listed explicitly as "no change, Category C
   semantics" rather than silently omitted, and the false "Deprecated, none
   planned" framing is removed - the wrapper's remaining callers are now
   named individually in the Components table and the per-check table.
4. **HIGH - Category A contradicts Req 2.1; status model unsupported.**
   Fixed by making the trade-off explicit rather than asserting a wrong
   claim. Requirement 2.1 now states in its own parenthetical that `status`
   becomes `"findings"`, not `"clean"`, and the design's new "Status model"
   section lays out both options considered, why the INFO-finding option is
   chosen, and the concrete, checked consequence (no `--fail-on`/exit-code
   logic exists in this codebase today to be affected, confirmed by grep
   shown inline; `max_severity` becomes `INFO` for that result). The
   "existing report code already renders it" claim is no longer asserted
   without support - rendering support for `Finding`/`Severity.INFO` is
   established by pointing to the dataclass and enum themselves, which are
   already consumed uniformly regardless of severity, not by a claim about
   unread report-formatting code.
5. **MEDIUM - `authentication failed` dropped.** Fixed. Restored to
   `_CONNECTIVITY_FAILURE_SIGNALS` in the signal classification code block,
   with an explicit callout in the paragraph beneath it.
6. **MEDIUM - Category C reason text and tests underspecified.** Fixed.
   Test 20 specifies the exact extension (a third `CheckResult` with an
   access-denied-shaped `raw_output`) to the named existing test, and the
   Components table states `_mark_inconclusive_on_failure`'s change
   concretely: use `classify_failure`, keep both kinds inconclusive, reason
   names the kind. The `(kind, signal)` tuple's use at each call site is
   spelled out in the per-check table's "Change" column and the `check_smbghost`
   code excerpt, rather than left implicit.
7. **MEDIUM - Inconsistent "unconverted call site" reasoning; wrapper hides
   ordering for mixed output.** Fixed. The per-check table and Components
   table now name every remaining `looks_like_failure` caller explicitly
   (`check_kerberos_user_enum`, `check_gpp_cpassword`, the nmap/raw-socket
   checks, and `_mark_inconclusive_on_failure` which is itself converted to
   `classify_failure` rather than staying on the wrapper). No caller is
   described as "none planned" without being named. The mixed-output
   reordering risk the finding raised (existing tests asserting `'access_denied'`
   substring in a reason) was checked against the actual existing test suite
   during design (grep for `access_denied` in `tests/`); no existing test
   asserts that literal substring in a reason string, so no existing
   assertion changes meaning as a side effect of this reordering - this is
   stated here rather than left to implementation to discover.
8. **MEDIUM - Test/gate coverage gaps.** Fixed. All `*` optional markers are
   removed from `tasks.md`; every Category B check in Requirement 4.1's list
   gets both an access-denied and a connectivity test, not a "representative
   sample"; `SMBGHOST_BUG_FIXTURE` is a named shared constant used by test 13
   and referenced by its exact definition in this document; a mixed-output
   test (test 3) is included at the `classify_failure` level (check-level
   mixed-output fixtures were considered but are redundant with test 3 plus
   the per-check connectivity tests, since `classify_failure`'s behavior is
   the single source of truth every check call site defers to - no check
   contains its own separate connectivity/access-denied ordering logic to
   test); the optional `Null Auth:True` evidence task is marked explicitly
   optional/polish in `tasks.md` but is no longer load-bearing for any
   Acceptance Criterion, and a test for it is included; the verification
   gate section now states running from the worktree root and recording the
   pre-existing baseline before the change.
9. **NIT - Placeholder "Responses to Design Review Findings".** Fixed - this
   section replaces the placeholder with the responses above.
10. **NIT - Error Handling/Validation spend space on hypotheticals.**
    Fixed. Both sections are condensed to the handful of real paths
    (`out.error`, no-signal, both-signals, lint) and the `None`/non-UTF8
    hypotheticals are removed; the "capturing output as str" claim is now
    qualified as confirmed against `runner.py`'s actual `CommandOutput`
    construction rather than asserted as unverified.
