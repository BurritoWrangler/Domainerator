"""Tests for the attack-path engine."""

from __future__ import annotations

from domainerator.paths import (
    AttackPath,
    Capability,
    Noise,
    PathEngine,
    PathStep,
    Reliability,
    baseline_steps,
    starting_capabilities,
)


def _step(name, technique, requires, grants, reliability=Reliability.HIGH):
    return PathStep(
        name=name,
        technique=technique,
        requires=frozenset(requires),
        grants=grants,
        command=f"# {technique}",
        description=technique,
        reliability=reliability,
        noise=Noise.QUIET,
    )


def test_reaches_domain_and_enterprise_admin():
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    # low-priv user -> DA via a single high-value control edge
    eng.add_step(_step("fcp", "ForceChangePassword",
                       {Capability.LOW_PRIV_USER}, Capability.DOMAIN_ADMIN))

    paths = eng.find_paths(starting_capabilities(authenticated=True), max_depth=8)
    assert paths
    goals = {p.goal for p in paths}
    assert Capability.DOMAIN_ADMIN in goals
    # baseline glue extends DA -> EA
    assert Capability.ENTERPRISE_ADMIN in goals


def test_no_path_when_disconnected():
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    # A step that requires a capability nobody grants -> unreachable.
    eng.add_step(_step("dead", "DeadEnd",
                       {Capability.CERT_AS_DA}, Capability.DOMAIN_ADMIN))
    paths = eng.find_paths({Capability.UNAUTHENTICATED}, max_depth=6)
    # Unauthenticated with no credential-gaining steps cannot reach a goal.
    assert all(p.goal not in {Capability.DOMAIN_ADMIN, Capability.ENTERPRISE_ADMIN}
               for p in paths) or not paths


def test_ranking_prefers_reliable_then_short():
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    # Reliable 1-hop to DCSync.
    eng.add_step(_step("rel", "ReliableDCSync",
                       {Capability.LOW_PRIV_USER}, Capability.DCSYNC,
                       reliability=Reliability.GUARANTEED))
    # Speculative alternative to the same goal.
    eng.add_step(_step("spec", "SpeculativeDCSync",
                       {Capability.LOW_PRIV_USER}, Capability.DCSYNC,
                       reliability=Reliability.SPECULATIVE))
    paths = eng.find_paths(starting_capabilities(authenticated=True), max_depth=8)
    dcsync = [p for p in paths if p.goal == Capability.DCSYNC]
    assert dcsync
    # The best kept path for the goal should use the guaranteed step.
    best = dcsync[0]
    assert best.min_reliability == Reliability.GUARANTEED


def test_webdav_relay_rbcd_chain_resolves():
    """WebDAV host + LDAP relay target + machine account -> local admin via RBCD.

    This exercises the baseline glue: WEBDAV_HOST + LOW_PRIV_USER -> coercion,
    coercion + LDAP_RELAY_TARGET -> RBCD, RBCD + MACHINE_ACCOUNT -> local admin.
    """
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    # Signals the new checks would emit:
    eng.add_step(_step("webdav", "WebDAV-host",
                       {Capability.UNAUTHENTICATED}, Capability.WEBDAV_HOST))
    eng.add_step(_step("ldaprelay", "LDAP-relay-target",
                       {Capability.UNAUTHENTICATED}, Capability.LDAP_RELAY_TARGET))
    eng.add_step(_step("maq", "MAQ-abuse",
                       {Capability.LOW_PRIV_USER}, Capability.MACHINE_ACCOUNT))

    # LOCAL_ADMIN isn't a goal capability, so search for it explicitly.
    got_local_admin = eng.find_paths(
        starting_capabilities(authenticated=True),
        goals=[Capability.LOCAL_ADMIN],
        max_depth=10,
    )
    assert got_local_admin, "WebDAV->relay->RBCD->local admin chain did not resolve"


def test_nopac_chain_reaches_domain_admin():
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    eng.add_step(_step("maq", "MAQ-abuse",
                       {Capability.LOW_PRIV_USER}, Capability.MACHINE_ACCOUNT))
    eng.add_step(_step("nopac", "noPac",
                       {Capability.LOW_PRIV_USER, Capability.MACHINE_ACCOUNT},
                       Capability.DCSYNC))
    paths = eng.find_paths(starting_capabilities(authenticated=True), max_depth=10)
    assert any(p.goal == Capability.DOMAIN_ADMIN for p in paths)


def test_gpo_control_chain_reaches_local_admin():
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    eng.add_step(_step("gpo", "WriteGPLink (GPO)",
                       {Capability.LOW_PRIV_USER}, Capability.GPO_CONTROL))
    got = eng.find_paths(
        starting_capabilities(authenticated=True),
        goals=[Capability.LOCAL_ADMIN],
        max_depth=10,
    )
    assert got, "GPO control -> local admin chain did not resolve"


def test_next_best_action_returns_first_actionable_step():
    from domainerator.paths import next_best_action

    eng = PathEngine()
    eng.add_steps(baseline_steps())
    eng.add_step(_step("kerb", "Kerberoast",
                       {Capability.VALID_CREDENTIALS}, Capability.SPN_TGS))
    eng.add_step(_step("crack", "Hash-crack",
                       {Capability.SPN_TGS}, Capability.DCSYNC,
                       reliability=Reliability.GUARANTEED))
    paths = eng.find_paths(starting_capabilities(authenticated=True), max_depth=8)
    held = starting_capabilities(authenticated=True)
    action = next_best_action(paths, held)
    assert action is not None
    # The first actionable step must have its requirements already satisfied.
    assert action.requires.issubset(held)
    assert action.grants not in held


def test_next_best_action_none_when_no_paths():
    from domainerator.paths import next_best_action

    assert next_best_action([], {Capability.UNAUTHENTICATED}) is None


def test_attackpath_score_and_summary():
    steps = [
        _step("a", "A", {Capability.LOW_PRIV_USER}, Capability.DCSYNC),
    ]
    path = AttackPath(steps=steps, goal=Capability.DCSYNC)
    assert "A" in path.summary()
    assert path.length == 1
    d = path.to_dict()
    assert d["goal"] == "dcsync"
    assert d["steps"][0]["technique"] == "A"


def test_ntlmv1_chain_yields_crackable_hash():
    # NTLMV1_HOST + coercion (baseline) -> crackable hash.
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    eng.add_step(_step("ntlmv1", "NTLMv1",
                       {Capability.UNAUTHENTICATED}, Capability.NTLMV1_HOST))
    got = eng.find_paths(
        starting_capabilities(authenticated=True),
        goals=[Capability.CRACKABLE_HASH],
        max_depth=10,
    )
    assert got, "NTLMv1 + coercion -> crackable hash chain did not resolve"


def test_ntlm_reflection_chain_reaches_local_admin():
    # SELF_RELAY_TARGET + coercion (baseline) -> local admin.
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    eng.add_step(_step("refl", "NTLM-Reflection-target",
                       {Capability.UNAUTHENTICATED}, Capability.SELF_RELAY_TARGET))
    got = eng.find_paths(
        starting_capabilities(authenticated=True),
        goals=[Capability.LOCAL_ADMIN],
        max_depth=10,
    )
    assert got, "NTLM reflection + coercion -> local admin chain did not resolve"


def test_sccm_naa_chain_grants_credentials():
    # SCCM NAA creds -> valid credentials (baseline glue), reachable unauth.
    eng = PathEngine()
    eng.add_steps(baseline_steps())
    eng.add_step(_step("naa", "SCCM-PXE-NAA",
                       {Capability.UNAUTHENTICATED}, Capability.SCCM_NAA_CREDS))
    got = eng.find_paths(
        {Capability.UNAUTHENTICATED},
        goals=[Capability.VALID_CREDENTIALS],
        max_depth=10,
    )
    assert got, "SCCM NAA -> valid credentials chain did not resolve"
