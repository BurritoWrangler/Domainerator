"""Tests for evidence capture and the console 'report' command."""

from __future__ import annotations

from domainerator.console import Session
from domainerator.console.console import Console
from domainerator.evidence import EvidenceWriter
from domainerator.paths import Capability, Noise, PathStep, Reliability
from domainerator.runner import CheckResult, Finding, Severity, Target, ToolRunner


def _finding_result() -> CheckResult:
    r = CheckResult(
        name="GPP cpassword in SYSVOL",
        category="authenticated",
        command="nxc smb 10.0.0.10 -u alice -p ****** -M gpp_password",
        raw_output="[+] Found credentials Username: svc Password: p",
        return_code=0,
        duration_seconds=1.0,
    )
    r.add_finding(Finding(
        title="GPP cpassword recovered", severity=Severity.HIGH,
        target="corp.local", description="d", evidence="e", remediation="m",
    ))
    return r


# --- EvidenceWriter --------------------------------------------------------

def test_evidence_write_result_creates_file_with_header(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    path = w.write_result(_finding_result(), target="10.0.0.10")
    assert path is not None
    assert path.exists()
    text = path.read_text()
    assert "GPP cpassword in SYSVOL" in text
    assert "Command: nxc smb 10.0.0.10" in text
    assert "--- raw output ---" in text
    assert "Found credentials" in text


def test_evidence_skips_skipped_checks(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    skipped = CheckResult(name="s", category="authenticated", skipped=True, skip_reason="no creds")
    assert w.write_result(skipped) is None
    # No evidence dir should even be created for a lone skipped result.
    assert not w.evidence_dir.exists()


def test_evidence_numbers_files_sequentially(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    w.write_result(_finding_result(), target="h")
    w.write_result(_finding_result(), target="h")
    names = sorted(p.name for p in w.evidence_dir.glob("*.txt"))
    assert names[0].startswith("001_")
    assert names[1].startswith("002_")


def test_evidence_write_execution(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    path = w.write_execution(
        technique="Kerberoast", command="nxc ldap ...",
        output="$krb5tgs$...", target="10.0.0.10", success=True,
    )
    text = path.read_text()
    assert path.name == "exec_001_kerberoast.txt"
    assert "Result: success" in text
    assert "$krb5tgs$" in text


def test_evidence_write_text_lands_in_run_dir(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    path = w.write_text("report.md", "# Report\n")
    assert path == w.run_dir / "report.md"
    assert path.read_text() == "# Report\n"


# --- console report command ------------------------------------------------

def _session_with_evidence(tmp_path):
    ev = EvidenceWriter(tmp_path, run_stamp="run-x")
    runner = ToolRunner(dry_run=True)
    target = Target(host="10.0.0.10", domain="corp.local",
                    username="alice", password="pw", dc_ip="10.0.0.10")
    session = Session(runner=runner, target=target, targets=[target], evidence=ev)

    r = _finding_result()
    r.add_step(PathStep(
        name="gpp", technique="GPP-cpassword",
        requires=frozenset({Capability.LOW_PRIV_USER}),
        grants=Capability.VALID_CREDENTIALS,
        command="nxc smb ... -M gpp_password",
        description="d", reliability=Reliability.HIGH, noise=Noise.QUIET,
    ))
    session.add_results([r])
    session.capabilities = {Capability.UNAUTHENTICATED, Capability.LOW_PRIV_USER}
    session.recompute_paths()
    return Console(session), session, ev


def test_report_command_writes_into_evidence_folder(tmp_path, capsys):
    console, _, ev = _session_with_evidence(tmp_path)
    console.cmd_report([])
    md = ev.run_dir / "report.md"
    js = ev.run_dir / "report.json"
    assert md.exists() and js.exists()
    assert "GPP cpassword recovered" in md.read_text()


def test_report_command_respects_explicit_dir(tmp_path):
    console, _, _ = _session_with_evidence(tmp_path)
    dest = tmp_path / "custom"
    console.cmd_report([str(dest)])
    assert (dest / "report.md").exists()
    assert (dest / "report.json").exists()


def test_execute_step_evidence_capture(tmp_path, capsys):
    console, session, ev = _session_with_evidence(tmp_path)
    console._capture_execution("Kerberoast", "nxc ldap ...", "$krb5tgs$...", True)
    files = list(ev.evidence_dir.glob("exec_*.txt"))
    assert len(files) == 1
    assert "$krb5tgs$" in files[0].read_text()


def test_capture_execution_noop_without_evidence(tmp_path):
    runner = ToolRunner(dry_run=True)
    target = Target(host="10.0.0.10", domain="corp.local")
    session = Session(runner=runner, target=target)  # no evidence writer
    console = Console(session)
    # Should not raise when no evidence writer is configured.
    console._capture_execution("Kerberoast", "cmd", "out", True)
