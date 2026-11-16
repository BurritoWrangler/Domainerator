"""Tests for verification layer and state machine."""

from __future__ import annotations

import datetime

from domainerator.console.outcomes import _TECHNIQUE_SIGNALS, interpret
from domainerator.console.state_machine import (
    ExploitationStateMachine,
    StepStatus,
)
from domainerator.console.variables import Variables
from domainerator.console.verification import (
    Pre2KAccountVerifier,
    VerificationCache,
    VerificationLayer,
    VerificationResult,
    VerificationStatus,
)
from domainerator.paths import Capability
from domainerator.runner import CommandOutput, Finding, Severity, Target

# === Outcome Detection Tests ===


def test_outcome_detection_kerberoast_success():
    """Test Kerberoast success detection."""
    output = "$krb5tgs$23$*user$DOMAIN$SPN$hash..."
    result = interpret("Kerberoast", Capability.SPN_TGS, output)
    assert result.success
    assert result.capability == Capability.SPN_TGS
    assert "Kerberoast" in result.detail


def test_outcome_detection_esc1_success():
    """Test ESC1 certificate success detection."""
    output = "Saved certificate to user.pfx"
    result = interpret("ESC1", Capability.CERT_AS_DA, output)
    assert result.success
    assert result.capability == Capability.CERT_AS_DA


def test_outcome_detection_pre2k_success():
    """Test Pre-2k authentication success detection."""
    output = "[+] DOMAIN\\COMPUTER$ Pwn3d!"
    result = interpret("Pre2k", Capability.VALID_CREDENTIALS, output)
    assert result.success


def test_outcome_detection_failure_signal():
    """Test failure signal detection."""
    output = "STATUS_LOGON_FAILURE"
    result = interpret("Kerberoast", Capability.SPN_TGS, output)
    assert not result.success
    assert "failure" in result.detail.lower()


def test_outcome_detection_unconfirmed():
    """Test unconfirmed output handling."""
    output = "some random output without signals"
    result = interpret("UnknownTechnique", Capability.VALID_CREDENTIALS, output)
    assert not result.success
    assert "unconfirmed" in result.detail.lower()


def test_outcome_detection_loot_extraction():
    """Test loot extraction from output."""
    output = "$krb5tgs$23$*user$DOMAIN$SPN$hash..."
    result = interpret("Kerberoast", Capability.SPN_TGS, output)
    assert len(result.loot) > 0
    assert "$krb5tgs$" in result.loot[0]


def test_technique_signals_count():
    """Verify we have the expected number of technique signals."""
    # Should have 50+ technique signals after the extension
    assert len(_TECHNIQUE_SIGNALS) >= 50


# === State Machine Tests ===


class FakeSession:
    """Minimal session mock for state machine tests."""

    def __init__(self):
        self.capabilities = set()


def test_state_machine_record_step():
    """Test step recording in state machine."""
    session = FakeSession()
    machine = ExploitationStateMachine(session)

    record = machine.record_step(
        path_id="test-path",
        step_index=0,
        technique="Kerberoast",
        status=StepStatus.SUCCEEDED,
        capability_granted=Capability.SPN_TGS,
    )

    assert record.technique == "Kerberoast"
    assert record.status == StepStatus.SUCCEEDED
    assert record.capability_granted == Capability.SPN_TGS
    assert record.step_id.startswith("step-")


def test_state_machine_capability_provenance():
    """Test capability provenance tracking."""
    session = FakeSession()
    machine = ExploitationStateMachine(session)

    machine.record_step(
        path_id="test-path",
        step_index=0,
        technique="DCSync",
        status=StepStatus.SUCCEEDED,
        capability_granted=Capability.DCSYNC,
    )

    prov = machine.get_capability_source(Capability.DCSYNC)
    assert prov is not None
    assert prov.capability == Capability.DCSYNC
    assert prov.source.startswith("step:")


def test_state_machine_manual_capability():
    """Test manual capability grant tracking."""
    session = FakeSession()
    machine = ExploitationStateMachine(session)

    machine.grant_manual_capability(Capability.VALID_CREDENTIALS, "manual entry")

    orphaned = machine.get_orphaned_capabilities()
    assert len(orphaned) == 1
    assert orphaned[0].capability == Capability.VALID_CREDENTIALS


def test_state_machine_status_summary():
    """Test status summary generation."""
    session = FakeSession()
    machine = ExploitationStateMachine(session)

    machine.record_step("path-1", 0, "Kerberoast", StepStatus.SUCCEEDED)
    machine.record_step("path-1", 1, "DCSync", StepStatus.FAILED)
    machine.record_step("path-1", 2, "ESC1", StepStatus.SUCCEEDED)

    summary = machine.get_status_summary()
    assert summary["total_steps"] == 3
    assert summary["status_counts"]["succeeded"] == 2
    assert summary["status_counts"]["failed"] == 1
    # Success rate: 2/3 = 66.7%
    assert 60 <= summary["success_rate"] <= 70


def test_state_machine_serialization():
    """Test state machine serialization."""
    session = FakeSession()
    machine = ExploitationStateMachine(session)

    machine.record_step(
        "path-1",
        0,
        "Kerberoast",
        StepStatus.SUCCEEDED,
        capability_granted=Capability.SPN_TGS,
    )

    data = machine.to_dict()
    assert "steps" in data
    assert "provenance" in data

    # Reconstruct
    new_machine = ExploitationStateMachine.from_dict(data, session)
    assert len(new_machine._steps) == 1


# === Verification Cache Tests ===


def test_verification_cache_set_get():
    """Test cache set and get operations."""
    cache = VerificationCache(ttl_minutes=30.0)

    result = VerificationResult(
        status=VerificationStatus.VERIFIED,
        finding_id="test-1",
        technique="Coercion",
        timestamp=datetime.datetime.now(),
        detail="Test verified",
    )

    cache.set("test-key", result)
    cached = cache.get("test-key")

    assert cached is not None
    assert cached.status == VerificationStatus.VERIFIED
    assert cached.finding_id == "test-1"


def test_verification_cache_invalidation():
    """Test cache invalidation."""
    cache = VerificationCache(ttl_minutes=30.0)

    result = VerificationResult(
        status=VerificationStatus.VERIFIED,
        finding_id="test-1",
        technique="Coercion",
        timestamp=datetime.datetime.now(),
        detail="Test verified",
    )

    cache.set("coercion:10.0.0.1:test-1", result)
    cache.set("coercion:10.0.0.2:test-2", result)
    cache.set("adcs:template:ca", result)

    # Invalidate by pattern
    count = cache.invalidate("coercion")
    assert count == 2

    assert cache.get("coercion:10.0.0.1:test-1") is None
    assert cache.get("adcs:template:ca") is not None


def test_verification_cache_invalidation_by_dependency():
    """Test dependency-based cache invalidation."""
    cache = VerificationCache(ttl_minutes=30.0)

    result = VerificationResult(
        status=VerificationStatus.VERIFIED,
        finding_id="test-1",
        technique="Coercion",
        timestamp=datetime.datetime.now(),
        detail="Test verified",
    )

    cache.set("coercion:10.0.0.1", result, dependencies={"smb_signing:10.0.0.1"})
    cache.set("other-key", result)

    count = cache.invalidate_by_dependency("smb_signing:10.0.0.1")
    assert count == 1
    assert cache.get("coercion:10.0.0.1") is None
    assert cache.get("other-key") is not None


def test_verification_cache_disambiguates_distinct_findings_same_technique_target():
    """Regression for H2: two findings sharing (technique, target) must not
    collapse to the same cache key just because Finding has no 'id' field.
    """
    finding_a = Finding(
        title="ESC1: certificate template allows SAN",
        severity=Severity.CRITICAL,
        description="x",
        target="10.0.0.10",
        evidence="Template Name: VulnTemplateA\nCA Name: corp-CA",
    )
    finding_b = Finding(
        title="ESC1: certificate template allows SAN",
        severity=Severity.CRITICAL,
        description="x",
        target="10.0.0.10",
        evidence="Template Name: VulnTemplateB\nCA Name: corp-CA",
    )

    key_a = VerificationLayer.cache_key_for(finding_a, "ESC1")
    key_b = VerificationLayer.cache_key_for(finding_b, "ESC1")

    assert key_a != key_b
    # Same finding, called twice, must be stable (reproducible, not random).
    assert key_a == VerificationLayer.cache_key_for(finding_a, "ESC1")


def test_verification_cache_serialization():
    """Test cache serialization."""
    cache = VerificationCache(ttl_minutes=30.0)

    result = VerificationResult(
        status=VerificationStatus.VERIFIED,
        finding_id="test-1",
        technique="Coercion",
        timestamp=datetime.datetime.now(),
        detail="Test verified",
        capability_granted=Capability.COERCIBLE_AUTH,
    )

    cache.set("test-key", result)

    data = cache.to_dict()
    new_cache = VerificationCache.from_dict(data)

    cached = new_cache.get("test-key")
    assert cached is not None
    assert cached.capability_granted == Capability.COERCIBLE_AUTH


# === Pre2k loot formatting (H1 regression) ===


class _FakeRunner:
    """Minimal ToolRunner stand-in returning a canned 'Pwn3d!' transcript."""

    def __init__(self, combined: str):
        self._combined = combined

    def run(self, argv, timeout=None):
        return CommandOutput(
            command=" ".join(argv), return_code=0,
            stdout=self._combined, stderr="", duration_seconds=0.1,
        )


class _FakeSession:
    """Minimal session stand-in for Pre2KAccountVerifier.verify()."""

    def __init__(self, target: Target):
        self.target = target
        self.state = type("S", (), {})()  # no password_policy attribute
        self.no_verify = False
        self.variables = Variables()


def test_pre2k_verified_loot_uses_single_backslash_separator():
    """Regression for H1: the loot string must use one backslash between
    domain and account name, matching DOMAIN\\user:pass conventions used
    everywhere else (loot.py's CLEARTEXT pattern, nxc output examples)."""
    target = Target(host="10.0.0.10", domain="CORP")
    runner = _FakeRunner("[+] CORP\\COMPUTER$:computer Pwn3d!")
    session = _FakeSession(target)
    verifier = Pre2KAccountVerifier(runner, session)

    finding = Finding(
        title="Pre-Windows 2000 computer account",
        severity=Severity.MEDIUM,
        description="x",
        target=target.host,
        evidence="COMPUTER$",
    )

    result = verifier.verify(finding)

    assert result.status == VerificationStatus.VERIFIED
    assert result.loot == ["CORP\\COMPUTER$:computer"]
    # Exactly one backslash, not two, between domain and account name.
    assert "\\\\" not in result.loot[0]
