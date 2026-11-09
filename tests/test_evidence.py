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


def test_evidence_write_results_by_host_creates_per_host_subfolders(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    per_host = {
        "10.0.0.10": [_finding_result(), _finding_result()],
        "10.0.0.20": [_finding_result()],
    }
    written = w.write_results_by_host(per_host)

    assert set(written.keys()) == {"10.0.0.10", "10.0.0.20"}
    assert len(written["10.0.0.10"]) == 2
    assert len(written["10.0.0.20"]) == 1

    host_dirs = {p.name for p in w.evidence_dir.iterdir()}
    assert host_dirs == {"10-0-0-10", "10-0-0-20"}

    # Numbering restarts per host (independent counters), both starting at 001.
    names_a = sorted(p.name for p in (w.evidence_dir / "10-0-0-10").glob("*.txt"))
    names_b = sorted(p.name for p in (w.evidence_dir / "10-0-0-20").glob("*.txt"))
    assert names_a[0].startswith("001_")
    assert names_a[1].startswith("002_")
    assert names_b[0].startswith("001_")

    # Each file's header reflects its own host, not another host's.
    text_a = (w.evidence_dir / "10-0-0-10" / names_a[0]).read_text()
    assert "Target: 10.0.0.10" in text_a
    text_b = (w.evidence_dir / "10-0-0-20" / names_b[0]).read_text()
    assert "Target: 10.0.0.20" in text_b


def test_evidence_write_results_by_host_skips_skipped_checks(tmp_path):
    w = EvidenceWriter(tmp_path, run_stamp="run-x")
    skipped = CheckResult(name="s", category="authenticated", skipped=True, skip_reason="no creds")
    written = w.write_results_by_host({"10.0.0.10": [skipped]})
    assert written["10.0.0.10"] == []


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


# --- session loot capture -> loot/ folder ----------------------------------

def test_session_capture_loot_writes_to_loot_dir(tmp_path):
    ev = EvidenceWriter(tmp_path, run_stamp="run-x")
    target = Target(host="dc01", domain="corp.local")
    session = Session(runner=ToolRunner(dry_run=True), target=target,
                      targets=[target], evidence=ev)
    out = (
        "SMB 10.0.0.10 [+] CORP\\alice:Summer2024!\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    newly = session.capture_loot(out)
    assert len(newly) == 2
    # Persisted to per-kind files under loot/.
    assert (ev.loot_dir / "cleartext.txt").exists()
    assert (ev.loot_dir / "ntlm_hash.txt").exists()
    # Also tracked in memory for 'show loot'.
    assert session.loot


def test_session_capture_loot_dedupes_on_disk(tmp_path):
    ev = EvidenceWriter(tmp_path, run_stamp="run-x")
    target = Target(host="dc01", domain="corp.local")
    session = Session(runner=ToolRunner(dry_run=True), target=target,
                      targets=[target], evidence=ev)
    out = "$krb5tgs$23$*svc*CORP*$abcdef"
    assert len(session.capture_loot(out)) == 1
    assert len(session.capture_loot(out)) == 0


def test_session_capture_loot_without_evidence_is_in_memory_only(tmp_path):
    target = Target(host="h", domain="corp.local")
    session = Session(runner=ToolRunner(dry_run=True), target=target, targets=[target])
    items = session.capture_loot(
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    )
    assert items          # returned the extracted items
    assert session.loot   # kept in memory


# --- console 'loot' command -------------------------------------------------

def _looted_session(evidence=None):
    target = Target(host="dc01", domain="corp.local")
    session = Session(runner=ToolRunner(dry_run=True), target=target,
                      targets=[target], evidence=evidence)
    session.capture_loot(
        "SMB [+] CORP\\alice:Summer2024!\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "$krb5tgs$23$*svc*CORP*$abcdef"
    )
    return session


def test_loot_command_lists_when_no_args(capsys):
    console = Console(_looted_session())
    console.cmd_loot([])
    out = capsys.readouterr().out
    assert "Collected loot" in out
    assert "CORP\\alice:Summer2024!" in out


def test_loot_export_to_explicit_dir(tmp_path):
    console = Console(_looted_session())
    dest = tmp_path / "exported"
    console.cmd_loot(["export", str(dest)])
    # All three kinds exported, including the cleartext credential.
    assert (dest / "cleartext.txt").exists()
    assert (dest / "ntlm_hash.txt").exists()
    assert (dest / "kerberos_tgs.txt").exists()
    assert "CORP\\alice:Summer2024!" in (dest / "cleartext.txt").read_text()


def test_loot_export_defaults_to_evidence_loot_dir(tmp_path):
    ev = EvidenceWriter(tmp_path, run_stamp="run-x")
    console = Console(_looted_session(evidence=ev))
    console.cmd_loot(["export"])
    assert (ev.loot_dir / "cleartext.txt").exists()


def test_loot_export_with_no_loot(capsys):
    target = Target(host="dc01", domain="corp.local")
    session = Session(runner=ToolRunner(dry_run=True), target=target, targets=[target])
    console = Console(session)
    console.cmd_loot(["export"])
    assert "No loot to export" in capsys.readouterr().out


def test_loot_rejects_unknown_subcommand(capsys):
    console = Console(_looted_session())
    console.cmd_loot(["bogus"])
    assert "Unknown loot subcommand" in capsys.readouterr().out
