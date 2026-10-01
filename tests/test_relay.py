"""Tests for relay orchestration: command building, plan validation, the
run lifecycle state machine, and ToolRunner background-process support."""

from __future__ import annotations

import pytest

from domainerator.console.relay import (
    CoercionMethod,
    RelayError,
    RelayMode,
    RelayOrchestrator,
)
from domainerator.paths import Capability
from domainerator.runner import Target, ToolRunner

# --- fakes -----------------------------------------------------------------

class FakeBackground:
    """A scripted background process: yields one buffered line per read_new."""

    def __init__(self, lines, *, started=True, error=None, dies_after=None):
        self._lines = list(lines)
        self._i = 0
        self.started = started
        self.error = error
        self.command = "fake-listener"
        self._dies_after = dies_after
        self.stopped = False

    @property
    def alive(self):
        if self._dies_after is not None and self._i >= self._dies_after:
            return False
        return True

    def read_new(self):
        if self._i < len(self._lines):
            line = self._lines[self._i]
            self._i += 1
            return line
        return ""

    def output(self):
        return "\n".join(self._lines[: self._i])

    def stop(self, timeout=5.0):
        self.stopped = True


class FakeCmdOut:
    def __init__(self, error=None, combined="coercion fired"):
        self.error = error
        self.combined = combined


class FakeRunner:
    def __init__(self, bg, cmd_out=None):
        self._bg = bg
        self._cmd_out = cmd_out or FakeCmdOut()
        self.background_calls = []
        self.run_calls = []

    def run_background(self, argv):
        self.background_calls.append(argv)
        return self._bg

    def run(self, argv, timeout=None):
        self.run_calls.append(argv)
        return self._cmd_out


def _orch(runner):
    # No real sleeping in tests.
    return RelayOrchestrator(runner=runner, _sleep=lambda _s: None)


# --- command building ------------------------------------------------------

def test_build_ldap_rbcd_plan():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.LDAP_RBCD, CoercionMethod.COERCER,
        listener_ip="10.0.0.5", relay_target="10.0.0.10", victim="10.0.0.20",
        domain="corp.local", username="alice", password="pw",
    )
    assert "ntlmrelayx.py" in plan.relay_argv
    assert "ldaps://10.0.0.10" in plan.relay_argv
    assert "--delegate-access" in plan.relay_argv
    assert plan.mode.grants is Capability.RBCD
    assert plan.coercion_argv[:2] == ["coercer", "coerce"]


def test_build_shadow_plan_uses_shadow_credentials():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.LDAP_SHADOW, CoercionMethod.DFSCOERCE,
        listener_ip="10.0.0.5", relay_target="10.0.0.10", victim="10.0.0.20",
        domain="corp.local", username="alice", password="pw",
    )
    assert "--shadow-credentials" in plan.relay_argv
    assert plan.mode.grants is Capability.RESET_PASSWORD


def test_reflection_defaults_relay_target_to_victim():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.REFLECTION, CoercionMethod.PRINTERBUG,
        listener_ip="10.0.0.5", relay_target=None, victim="10.0.0.20",
        domain="corp.local", username="alice", password="pw",
    )
    # Reflection relays back to the victim over SMB.
    assert "smb://10.0.0.20" in plan.relay_argv
    assert plan.relay_target == "10.0.0.20"
    assert plan.mode.grants is Capability.LOCAL_ADMIN


def test_missing_required_values_raise():
    orch = _orch(FakeRunner(FakeBackground([])))
    with pytest.raises(RelayError) as exc:
        orch.build_plan(
            RelayMode.LDAP_RBCD, CoercionMethod.COERCER,
            listener_ip=None, relay_target=None, victim=None,
            domain=None, username=None, password=None,
        )
    msg = str(exc.value)
    assert "LHOST" in msg
    assert "victim" in msg


def test_password_redacted_in_displays():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.LDAP_RBCD, CoercionMethod.COERCER,
        listener_ip="10.0.0.5", relay_target="10.0.0.10", victim="10.0.0.20",
        domain="corp.local", username="alice", password="SuperSecret1!",
    )
    assert "SuperSecret1!" not in plan.coercion_display
    assert "******" in plan.coercion_display


def test_printerbug_authstring_redacted():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.REFLECTION, CoercionMethod.PRINTERBUG,
        listener_ip="10.0.0.5", relay_target=None, victim="10.0.0.20",
        domain="corp.local", username="alice", password="SuperSecret1!",
    )
    # The embedded domain/user:pass@victim string masks the password.
    assert "SuperSecret1!" not in plan.coercion_display
    assert "corp.local/alice:******@10.0.0.20" in plan.coercion_display


# --- lifecycle state machine ----------------------------------------------

def _plan(orch):
    return orch.build_plan(
        RelayMode.LDAP_RBCD, CoercionMethod.COERCER,
        listener_ip="10.0.0.5", relay_target="10.0.0.10", victim="10.0.0.20",
        domain="corp.local", username="alice", password="pw",
    )


def test_run_success_grants_capability_and_tears_down():
    bg = FakeBackground([
        "Setting up SMB Server",
        "Servers started, waiting for connections",
        "Authenticating against ldaps://10.0.0.10 as CORP/VICTIM$",
        "msDS-AllowedToActOnBehalfOfOtherIdentity was set successfully",
    ])
    runner = FakeRunner(bg)
    orch = _orch(runner)
    result = orch.run(_plan(orch))

    assert result.success
    assert result.capability is Capability.RBCD
    assert runner.run_calls, "coercion command should have been fired"
    assert bg.stopped, "listener must be torn down"


def test_run_listener_fails_to_start():
    bg = FakeBackground([], started=False, error="tool 'ntlmrelayx.py' not found on PATH")
    runner = FakeRunner(bg)
    orch = _orch(runner)
    result = orch.run(_plan(orch))

    assert not result.success
    assert "failed to start" in result.detail
    # No coercion should fire if the listener never came up.
    assert not runner.run_calls


def test_run_timeout_without_success_signal():
    # Ready signal present, but no success signal ever appears.
    bg = FakeBackground([
        "Servers started, waiting for connections",
        "some unrelated chatter",
    ])
    runner = FakeRunner(bg)
    # watch_timeout small; _now advances via a counter so the loop terminates.
    ticks = iter(range(0, 1000))
    orch = RelayOrchestrator(
        runner=runner,
        _sleep=lambda _s: None,
        _now=lambda: next(ticks),
        ready_timeout=5,
        watch_timeout=3,
    )
    result = orch.run(_plan(orch))

    assert not result.success
    assert result.capability is None
    assert bg.stopped


def test_run_listener_dies_during_watch_without_signal():
    bg = FakeBackground(
        ["Servers started, waiting for connections", "line2"],
        dies_after=2,
    )
    runner = FakeRunner(bg)
    orch = _orch(runner)
    result = orch.run(_plan(orch))

    assert not result.success
    assert "exited" in result.detail
    assert bg.stopped


# --- ToolRunner background support -----------------------------------------

def test_background_dry_run_not_started():
    bp = ToolRunner(dry_run=True).run_background(["ntlmrelayx.py", "-t", "ldaps://dc"])
    assert bp.started
    assert not bp.alive
    assert "dry-run" in bp.output().lower()


def test_background_missing_tool():
    bp = ToolRunner().run_background(["definitely-not-a-tool-xyz-123"])
    assert not bp.started
    assert "not found" in bp.error


def test_background_captures_output_and_stops():
    bp = ToolRunner().run_background(["sh", "-c", "echo alpha; echo beta"])
    # Give the reader thread a moment.
    import time
    time.sleep(0.3)
    out = bp.output()
    assert "alpha" in out
    assert "beta" in out
    bp.stop()
    assert not bp.alive


def test_background_scope_refusal(tmp_path):
    from domainerator.runner import Scope

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.0.0.0/24\n", encoding="utf-8")
    scope = Scope.from_file(str(scope_file))
    bp = ToolRunner(scope=scope).run_background(["nxc", "smb", "192.168.1.1"])
    assert not bp.started
    assert "scope" in bp.error


# --- console target switching & relay victim selection ---------------------

def _console_session():
    from domainerator.console import Session
    from domainerator.console.console import Console

    runner = ToolRunner(dry_run=True)
    t1 = Target(host="10.0.0.10", domain="corp.local",
                username="alice", password="pw", dc_ip="10.0.0.10")
    t2 = Target(host="10.0.0.20", domain="corp.local")
    session = Session(runner=runner, target=t1, targets=[t1, t2])
    return Console(session), session


def test_cmd_target_switches_active(capsys):
    console, session = _console_session()
    console.cmd_target(["1"])
    assert session.target.host == "10.0.0.20"
    out = capsys.readouterr().out
    assert "10.0.0.20" in out


def test_cmd_target_rejects_bad_id(capsys):
    console, session = _console_session()
    console.cmd_target(["99"])
    assert session.target.host == "10.0.0.10"  # unchanged
    assert "Invalid target ID" in capsys.readouterr().out


def test_cmd_targets_lists_and_marks_active(capsys):
    console, _ = _console_session()
    console.cmd_targets([])
    out = capsys.readouterr().out
    assert "10.0.0.10" in out
    assert "10.0.0.20" in out
    assert "*" in out  # active marker


def test_relay_victim_prompt_selects_scanned_host_by_index(monkeypatch):
    console, _ = _console_session()
    # Operator types "1" -> should resolve to the second scanned host.
    monkeypatch.setattr("builtins.input", lambda _prompt="": "1")
    victim = console._prompt_relay_victim()
    assert victim == "10.0.0.20"


def test_relay_victim_prompt_accepts_literal_host(monkeypatch):
    console, _ = _console_session()
    # A non-index entry is taken literally (victim not among scanned hosts).
    monkeypatch.setattr("builtins.input", lambda _prompt="": "10.9.9.9")
    victim = console._prompt_relay_victim()
    assert victim == "10.9.9.9"


# --- ESC8 (relay to AD CS web enrollment) ----------------------------------

def test_build_esc8_plan_from_bare_ca_host():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.ADCS_ESC8, CoercionMethod.PETITPOTAM,
        listener_ip="10.0.0.5", relay_target="ca01.corp.local", victim="10.0.0.10",
        domain="corp.local", username="alice", password="pw",
    )
    # Bare host is turned into the certsrv web-enrollment URL.
    assert "http://ca01.corp.local/certsrv/certfnsh.asp" in plan.relay_argv
    assert "--adcs" in plan.relay_argv
    assert "--template" in plan.relay_argv
    assert "DomainController" in plan.relay_argv
    assert plan.mode.grants is Capability.CERT_AS_DA


def test_build_esc8_plan_passes_through_full_url():
    orch = _orch(FakeRunner(FakeBackground([])))
    plan = orch.build_plan(
        RelayMode.ADCS_ESC8, CoercionMethod.COERCER,
        listener_ip="10.0.0.5",
        relay_target="https://ca01/certsrv/certfnsh.asp",
        victim="10.0.0.10", domain="corp.local", username="alice", password="pw",
    )
    assert "https://ca01/certsrv/certfnsh.asp" in plan.relay_argv


def test_esc8_requires_relay_target():
    orch = _orch(FakeRunner(FakeBackground([])))
    with pytest.raises(RelayError) as exc:
        orch.build_plan(
            RelayMode.ADCS_ESC8, CoercionMethod.COERCER,
            listener_ip="10.0.0.5", relay_target=None, victim="10.0.0.10",
            domain="corp.local", username="alice", password="pw",
        )
    assert "CA" in str(exc.value)


def test_esc8_run_detects_certificate_and_grants_cert_as_da():
    bg = FakeBackground([
        "Setting up HTTP Server",
        "Servers started, waiting for connections",
        "Authenticating against http://ca01 as CORP/DC01$",
        "GOT CERTIFICATE! ID 42",
    ])
    runner = FakeRunner(bg)
    orch = _orch(runner)
    plan = orch.build_plan(
        RelayMode.ADCS_ESC8, CoercionMethod.PETITPOTAM,
        listener_ip="10.0.0.5", relay_target="ca01.corp.local", victim="10.0.0.10",
        domain="corp.local", username="alice", password="pw",
    )
    result = orch.run(plan)
    assert result.success
    assert result.capability is Capability.CERT_AS_DA
    assert bg.stopped
