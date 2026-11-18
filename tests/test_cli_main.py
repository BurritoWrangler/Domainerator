"""End-to-end tests for domainerator.cli.main().

These invoke the real CLI entrypoint with --dry-run (no external tools
required, no subprocess calls made) to exercise argument handling and the
report-writing paths without needing nxc/nmap/etc. installed.
"""

from __future__ import annotations

from domainerator.cli import main


def _run(args, capsys):
    """Run main() with the given argv, returning (exit_code, out, err)."""
    exit_code = main(args)
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_output_to_existing_directory_errors_cleanly_instead_of_crashing(
    tmp_path, capsys
):
    """Regression: pointing --output at an existing directory (e.g. an
    operator confusing it with --output-dir) must not crash with a raw
    IsADirectoryError traceback. It should print a clear error on stderr
    and exit with a distinct, non-zero code."""
    out_dir = tmp_path / "output"
    out_dir.mkdir()

    exit_code, out, err = _run(
        [
            "--target", "10.0.0.1",
            "--domain", "corp.local",
            "--dry-run",
            "--no-status",
            "-o", str(out_dir),
        ],
        capsys,
    )

    assert exit_code == 2
    assert "error: could not write Markdown report" in err
    assert str(out_dir) in err
    # The scan itself still completed and its summary was printed, even
    # though the report write failed.
    assert "Domainerator scan complete" in out


def test_json_output_to_existing_directory_errors_cleanly(tmp_path, capsys):
    out_dir = tmp_path / "output"
    out_dir.mkdir()

    exit_code, out, err = _run(
        [
            "--target", "10.0.0.1",
            "--domain", "corp.local",
            "--dry-run",
            "--no-status",
            "--json", str(out_dir),
        ],
        capsys,
    )

    assert exit_code == 2
    assert "error: could not write JSON report" in err
    assert str(out_dir) in err


def test_output_to_a_real_file_still_succeeds(tmp_path, capsys):
    """Confirms the fix's error handling doesn't break the normal, working
    case: writing to an actual file path still succeeds with exit 0."""
    out_file = tmp_path / "report.md"

    exit_code, out, err = _run(
        [
            "--target", "10.0.0.1",
            "--domain", "corp.local",
            "--dry-run",
            "--no-status",
            "-o", str(out_file),
        ],
        capsys,
    )

    assert exit_code == 0
    assert out_file.exists()
    assert f"Markdown report written to {out_file}" in out
    assert err == ""
