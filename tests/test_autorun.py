"""Tests for the step classifier (execplan) and the seamless 'autorun' loop."""

from __future__ import annotations

from domainerator.console import Console, Session
from domainerator.console.execplan import StepClass, classify_step
from domainerator.console.variables import Variables
from domainerator.paths import Capability, Noise, PathStep, Reliability
from domainerator.runner import CheckResult, CommandOutput, Target, ToolRunner


def _vars_from_creds():
    v = Variables()
    v.seed_from_target(Target(
        host="dc01.corp.local", domain="corp.local",
        username="alice", password="pw", dc_ip="10.0.0.10",
    ))
    return v


def _step(technique, command, grants=Capability.DCSYNC,
          requires=(Capability.LOW_PRIV_USER,), noise=Noise.QUIET):
    return PathStep(
        name=technique, technique=technique,
        requires=frozenset(requires), grants=grants, command=command,
        description="d", reliability=Reliability.HIGH, noise=noise,
    )


# --- classifier ------------------------------------------------------------

def test_classify_deterministic_single_binary_is_auto():
    v = _vars_from_creds()
    c = classify_step(_step("DCSync", "secretsdump.py -just-dc DOMAIN/USER@DC"), v)
    assert c.kind is StepClass.AUTO


def test_classify_hash_crack_needs_human():
    v = _vars_from_creds()
    c = classify_step(_step("Hash-crack", "hashcat -m 13100 out.tgs wordlist.txt"), v)
    assert c.kind is StepClass.NEEDS_HUMAN


def test_classify_guidance_comment_needs_human():
    v = _vars_from_creds()
    c = classify_step(_step("RelayToLDAP-RBCD", "# ntlmrelayx.py -t ldaps://DC ..."), v)
    assert c.kind is StepClass.NEEDS_HUMAN


def test_classify_shell_pipe_needs_human():
    v = _vars_from_creds()
    c = classify_step(_step("RID-cycling", "nxc smb DC --rid-brute | grep Sid"), v)
    assert c.kind is StepClass.NEEDS_HUMAN


def test_classify_unresolved_vars_needs_human_and_lists_them():
    v = _vars_from_creds()
    c = classify_step(_step(
        "ESC1",
        "certipy req -u USER@DOMAIN -p PASS -ca CA-NAME -template VULN-TEMPLATE "
        "-upn administrator@DOMAIN -dc-ip DC-IP",
    ), v)
    assert c.kind is StepClass.NEEDS_HUMAN
    assert c.missing_vars and "CA" in c.missing_vars and "TEMPLATE" in c.missing_vars


# --- autorun loop ----------------------------------------------------------

class _SignalRunner(ToolRunner):
    """Fake runner emitting a per-technique success signal."""

    def __init__(self):
        super().__init__(dry_run=False)

    def is_available(self, name):
        return True

    def find_tool(self, name):
        return "/usr/bin/" + name

    def run(self, argv, timeout=None):
        cmd = " ".join(argv)
        out = ""
        if "certipy" in cmd and "req" in cmd:
            out = "Saved certificate and private key to 'administrator.pfx'"
        elif "certipy" in cmd and "auth" in cmd:
            out = "Got hash for 'administrator@corp.local'"
        elif "secretsdump" in cmd:
            out = "Administrator:500:aad3b...:31d6c...:::"
        return CommandOutput(command=cmd, return_code=0, stdout=out, stderr="",
                             duration_seconds=0.1)


def _esc1_session(runner=None):
    t = Target(host="dc01.corp.local", domain="corp.local",
               username="alice", password="pw", dc_ip="10.0.0.10")
    s = Session(runner=runner or _SignalRunner(), target=t, targets=[t])
    r = CheckResult(name="adcs", category="adcs")
    r.add_step(_step(
        "ESC1",
        "certipy req -u USER@DOMAIN -p PASS -ca CA-NAME -template VULN-TEMPLATE "
        "-upn administrator@DOMAIN -dc-ip DC-IP",
        grants=Capability.CERT_AS_DA, noise=Noise.MODERATE,
    ))
    r.add_step(_step(
        "PKINIT-auth", "certipy auth -pfx administrator.pfx -dc-ip DC-IP",
        grants=Capability.DCSYNC, requires=(Capability.CERT_AS_DA,),
        noise=Noise.MODERATE,
    ))
    s.add_results([r])
    s.capabilities = {
        Capability.UNAUTHENTICATED, Capability.VALID_CREDENTIALS,
        Capability.LOW_PRIV_USER,
    }
    s.recompute_paths()
    return s


def _da_path_id(session):
    for i, p in enumerate(session.attack_paths, 1):
        if p.goal == Capability.DOMAIN_ADMIN:
            return i
    return None


def test_autorun_reaches_domain_admin(monkeypatch):
    s = _esc1_session()
    s.variables.set("CA", "corp-CA")
    s.variables.set("TEMPLATE", "VulnTemplate")
    console = Console(s)
    pid = _da_path_id(s)
    assert pid is not None
    console.cmd_use([str(pid)])
    # Only the single up-front confirm is needed (vars already set).
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    console.cmd_autorun([])
    assert Capability.DOMAIN_ADMIN in s.capabilities


def test_autorun_preflight_prompts_for_missing_vars(monkeypatch):
    s = _esc1_session()  # CA/TEMPLATE NOT set
    console = Console(s)
    pid = _da_path_id(s)
    console.cmd_use([str(pid)])
    # Preflight asks for CA then TEMPLATE, then the begin-confirm.
    answers = iter(["corp-CA", "VulnTemplate", "y"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    console.cmd_autorun([])
    assert Capability.DOMAIN_ADMIN in s.capabilities


def test_autorun_pauses_on_crack_step(monkeypatch, capsys):
    # A path whose second step is an offline crack: autorun runs the first
    # (auto) step and then pauses at the crack (needs human), without reaching
    # the goal. We build the path explicitly and select it so the test does not
    # depend on PathEngine ordering.
    from domainerator.paths import AttackPath

    t = Target(host="dc01.corp.local", domain="corp.local",
               username="alice", password="pw", dc_ip="10.0.0.10")

    class KerbRunner(_SignalRunner):
        def run(self, argv, timeout=None):
            cmd = " ".join(argv)
            out = "$krb5tgs$23$*svc*corp*$abcdef" if "kerberoasting" in cmd else ""
            return CommandOutput(command=cmd, return_code=0, stdout=out,
                                 stderr="", duration_seconds=0.1)

    s = Session(runner=KerbRunner(), target=t, targets=[t])
    s.capabilities = {Capability.UNAUTHENTICATED, Capability.VALID_CREDENTIALS,
                      Capability.LOW_PRIV_USER}

    kerb = _step("Kerberoast",
                 "nxc ldap DC -u USER -p PASS --kerberoasting out.tgs",
                 grants=Capability.SPN_TGS,
                 requires=(Capability.VALID_CREDENTIALS,))
    crack = _step("Hash-crack", "hashcat -m 13100 out.tgs wordlist.txt",
                  grants=Capability.DOMAIN_ADMIN,  # pretend crack reaches a goal
                  requires=(Capability.SPN_TGS,))
    path = AttackPath(steps=[kerb, crack], goal=Capability.DOMAIN_ADMIN)
    s.attack_paths = [path]

    console = Console(s)
    console.cmd_use(["1"])
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    console.cmd_autorun([])
    out = capsys.readouterr().out
    # Kerberoast ran (SPN_TGS granted) but autorun paused at the crack.
    assert Capability.SPN_TGS in s.capabilities
    assert Capability.DOMAIN_ADMIN not in s.capabilities
    assert "Pausing" in out


def test_autorun_requires_selected_path(capsys):
    t = Target(host="dc01.corp.local", domain="corp.local")
    s = Session(runner=ToolRunner(dry_run=True), target=t, targets=[t])
    console = Console(s)
    console.cmd_autorun([])
    assert "No path selected" in capsys.readouterr().out


def test_autorun_cancel_at_confirmation(monkeypatch, capsys):
    s = _esc1_session()
    s.variables.set("CA", "corp-CA")
    s.variables.set("TEMPLATE", "VulnTemplate")
    console = Console(s)
    console.cmd_use([str(_da_path_id(s))])
    monkeypatch.setattr("builtins.input", lambda *a: "n")  # decline begin
    console.cmd_autorun([])
    assert Capability.DOMAIN_ADMIN not in s.capabilities
    assert "cancelled" in capsys.readouterr().out.lower()
