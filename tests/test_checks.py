"""Tests for check parsing logic (RBCD enumeration, WebDAV discovery).

These drive the checks through a fake ToolRunner that returns canned tool
output, so we exercise the parsing/finding/path-step logic without needing the
real external tools installed.
"""

from __future__ import annotations

from domainerator.checks import authenticated, unauthenticated
from domainerator.paths import Capability
from domainerator.runner import CommandOutput, Target


class FakeRunner:
    """A ToolRunner stand-in that returns a scripted CommandOutput."""

    def __init__(self, combined: str = "", error: str | None = None):
        self._combined = combined
        self._error = error

    def is_available(self, name: str) -> bool:  # all tools "present"
        return True

    def run(self, argv, timeout=None) -> CommandOutput:
        stdout = "" if self._error else self._combined
        return CommandOutput(
            command=" ".join(argv),
            return_code=0 if not self._error else None,
            stdout=stdout,
            stderr="",
            duration_seconds=0.0,
            error=self._error,
        )


AUTH_TARGET = Target(
    host="10.0.0.10", domain="corp.local", username="alice", password="pw", dc_ip="10.0.0.10"
)
ANON_TARGET = Target(host="10.0.0.10", domain="corp.local")


def test_rbcd_enum_detects_existing_and_emits_step():
    output = (
        "LDAP  10.0.0.10  msDS-AllowedToActOnBehalfOfOtherIdentity\n"
        "SRV01$   <binary-sd>\n"
        "SRV02$   <binary-sd>\n"
    )
    res = authenticated.check_rbcd(FakeRunner(output), AUTH_TARGET)
    # A finding for existing RBCD relationships.
    assert any("RBCD" in f.title for f in res.findings)
    # And a DACL_CONTROL + MACHINE_ACCOUNT -> RBCD path step.
    grants = {s.grants for s in res.path_steps}
    assert Capability.RBCD in grants


def test_rbcd_enum_skips_without_creds():
    res = authenticated.check_rbcd(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_webdav_detects_service_and_emits_step():
    output = "SMB  10.0.0.20  WEBDAV  WebClient Service enabled on: WS01"
    res = unauthenticated.check_webdav(FakeRunner(output), ANON_TARGET)
    assert any("WebClient" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.WEBDAV_HOST in grants


def test_webdav_quiet_when_not_present():
    res = unauthenticated.check_webdav(FakeRunner("SMB 10.0.0.20  nothing here"), ANON_TARGET)
    assert not res.findings
    assert not res.path_steps


def test_coercion_detects_and_emits_step():
    output = (
        "SMB  10.0.0.10  COERCE_PLUS  MS-EFSR (EfsRpcOpenFileRaw) VULNERABLE\n"
        "SMB  10.0.0.10  COERCE_PLUS  MS-RPRN spooler coerce possible\n"
    )
    res = authenticated.check_coercion(FakeRunner(output), AUTH_TARGET)
    assert any("coercible" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.COERCIBLE_AUTH in grants


def test_coercion_quiet_when_not_vulnerable():
    res = authenticated.check_coercion(FakeRunner("SMB 10.0.0.10  nothing"), AUTH_TARGET)
    assert not res.findings


def test_nopac_detects_and_emits_dcsync_step():
    output = "SMB  10.0.0.10  NOPAC  VULNERABLE - got TGT for domain controller"
    res = authenticated.check_nopac(FakeRunner(output), AUTH_TARGET)
    assert any("noPac" in f.title for f in res.findings)
    assert any(f.severity.label == "Critical" for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.DCSYNC in grants


def test_ldap_relay_exposure_detects_and_emits_step():
    output = (
        "LDAP  10.0.0.10  LDAP Signing NOT Enforced\n"
        "LDAP  10.0.0.10  LDAPS Channel Binding is NOT set to Required\n"
    )
    res = unauthenticated.check_ldap_relay_exposure(FakeRunner(output), ANON_TARGET)
    assert any("relay protections" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.LDAP_RELAY_TARGET in grants


def test_inconclusive_on_connection_failure():
    # SMB signing check with no 'signing:' banner -> inconclusive, not clean.
    res = unauthenticated.check_smb_signing(
        FakeRunner("SMB 10.0.0.10  [-] Connection refused"), ANON_TARGET
    )
    assert res.inconclusive
    assert not res.findings
    assert res.status == "inconclusive"


def test_auth_failure_marked_inconclusive_by_run_all_postprocess():
    # A ran-but-empty authenticated check whose output shows auth failure is
    # marked inconclusive by the run_all post-processor.
    from domainerator.runner import CheckResult

    clean = CheckResult(name="a", category="authenticated", raw_output="all good, nothing")
    failed = CheckResult(
        name="b", category="authenticated", raw_output="STATUS_LOGON_FAILURE"
    )
    authenticated._mark_inconclusive_on_failure([clean, failed])
    assert not clean.inconclusive
    assert failed.inconclusive
