"""Tests for the SCCM / PXE NAA checks.

These drive the SCCM checks with canned NetExec-style output through a fake
runner, so parsing/finding/path-step logic is exercised without the real tool.
"""

from __future__ import annotations

from domainerator.checks import sccm
from domainerator.paths import Capability
from domainerator.runner import CommandOutput, Target


class FakeRunner:
    def __init__(self, combined: str = "", error: str | None = None):
        self._combined = combined
        self._error = error

    def is_available(self, name: str) -> bool:
        return True

    def run(self, argv, timeout=None) -> CommandOutput:
        return CommandOutput(
            command=" ".join(argv),
            return_code=0 if not self._error else None,
            stdout="" if self._error else self._combined,
            stderr="",
            duration_seconds=0.0,
            error=self._error,
        )


AUTH_TARGET = Target(
    host="10.0.0.10", domain="corp.local", username="alice", password="pw", dc_ip="10.0.0.10"
)
ANON_TARGET = Target(host="10.0.0.10", domain="corp.local")


def test_sccm_discovery_requires_creds():
    res = sccm.check_sccm_discovery(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_sccm_discovery_detects_management_point():
    output = (
        "LDAP  10.0.0.10  SCCM  Found System Management container\n"
        "LDAP  10.0.0.10  SCCM  ManagementPoint: MP01.corp.local  SiteCode: P01\n"
    )
    res = sccm.check_sccm_discovery(FakeRunner(output), AUTH_TARGET)
    assert any("SCCM" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.SCCM_MANAGEMENT_POINT in grants


def test_sccm_discovery_inconclusive_on_unrecognized():
    res = sccm.check_sccm_discovery(FakeRunner("LDAP 10.0.0.10  [-] nothing"), AUTH_TARGET)
    assert not res.findings
    assert res.inconclusive


def test_sccm_pxe_naa_recovered():
    output = (
        "SMB  10.0.0.10  SCCM  PXE enabled, no password\n"
        "SMB  10.0.0.10  SCCM  Recovered Network Access Account: CORP\\svc_naa\n"
    )
    res = sccm.check_sccm_pxe_naa(FakeRunner(output), ANON_TARGET)
    assert any("Network Access Account" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.SCCM_NAA_CREDS in grants


def test_sccm_pxe_open_without_naa():
    output = "SMB  10.0.0.10  SCCM  PXE enabled, no password required"
    res = sccm.check_sccm_pxe_naa(FakeRunner(output), ANON_TARGET)
    assert any("PXE" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.SCCM_NAA_CREDS in grants


def test_sccm_pxe_inconclusive_on_unrecognized():
    res = sccm.check_sccm_pxe_naa(FakeRunner("SMB 10.0.0.10  [-] no sccm here x"), ANON_TARGET)
    assert not res.findings
    assert res.inconclusive
