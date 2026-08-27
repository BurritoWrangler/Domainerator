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
