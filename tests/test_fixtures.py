"""Fixture-based parser tests.

These drive the checks with captured (sanitized) tool output stored under
``tests/fixtures/``. Fixtures are the most reliable defence against parser
drift: if a NetExec/Certipy output format changes, we capture the new format as
a fixture and the test tells us whether the parser still works.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from domainerator.checks import unauthenticated
from domainerator.paths import Capability
from domainerator.runner import CommandOutput, Target

FIXTURES = Path(__file__).parent / "fixtures"


class FixtureRunner:
    """ToolRunner stand-in that replays a fixture file as command output."""

    def __init__(self, fixture: str):
        self._text = (FIXTURES / fixture).read_text(encoding="utf-8")

    def is_available(self, name: str) -> bool:
        return True

    def run(self, argv, timeout=None) -> CommandOutput:
        return CommandOutput(
            command=" ".join(argv),
            return_code=0,
            stdout=self._text,
            stderr="",
            duration_seconds=0.0,
        )


TARGET = Target(host="10.0.0.10", domain="corp.local")


def test_smb_signing_disabled_fixture():
    res = unauthenticated.check_smb_signing(FixtureRunner("nxc_smb_signing_disabled.txt"), TARGET)
    assert any("signing not required" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.RELAY_TARGET in grants
    assert not res.inconclusive


def test_smb_signing_enabled_fixture():
    res = unauthenticated.check_smb_signing(FixtureRunner("nxc_smb_signing_enabled.txt"), TARGET)
    # Enforced signing -> an INFO finding, no relay-target step, conclusive.
    assert any("signing required" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.RELAY_TARGET not in grants


def test_rid_brute_fixture_parses_real_format():
    # Real NetExec format is "1104: CORP\\user (SidTypeUser)".
    res = unauthenticated.check_rid_cycling(FixtureRunner("nxc_rid_brute.txt"), TARGET)
    assert any("RID cycling" in f.title for f in res.findings)
    # Evidence should contain the enumerated users.
    evidence = res.findings[0].evidence
    assert "Administrator" in evidence
    assert "jsmith" in evidence
    grants = {s.grants for s in res.path_steps}
    assert Capability.USER_LIST in grants


@pytest.mark.parametrize(
    "fixture,expect_signing_disabled",
    [
        ("nxc_smb_signing_disabled.txt", True),
        ("nxc_smb_signing_enabled.txt", False),
    ],
)
def test_signing_fixtures_parametrized(fixture, expect_signing_disabled):
    res = unauthenticated.check_smb_signing(FixtureRunner(fixture), TARGET)
    disabled = any("not required" in f.title.lower() for f in res.findings)
    assert disabled == expect_signing_disabled
