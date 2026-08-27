"""Tests for scope loading and enforcement."""

from __future__ import annotations

import pytest

from domainerator.runner import Scope, ScopeError, ToolRunner


def _write_scope(tmp_path, contents: str):
    p = tmp_path / "scope.txt"
    p.write_text(contents, encoding="utf-8")
    return str(p)


def test_scope_membership_ip_and_cidr(tmp_path):
    scope = Scope.from_file(
        _write_scope(tmp_path, "# hdr\n10.0.0.0/24\n10.0.5.10\n192.168.50.0/26\n\n")
    )
    assert scope.active
    assert scope.contains("10.0.0.10")       # in /24
    assert scope.contains("10.0.5.10")        # explicit host
    assert scope.contains("192.168.50.5")     # in /26
    assert not scope.contains("10.0.1.10")    # outside /24
    assert not scope.contains("192.168.50.100")  # outside /26
    assert not scope.contains("8.8.8.8")      # far outside


def test_empty_scope_rejected(tmp_path):
    with pytest.raises(ScopeError):
        Scope.from_file(_write_scope(tmp_path, "# nothing useful\n\n"))


def test_runner_refuses_out_of_scope(tmp_path):
    scope = Scope.from_file(_write_scope(tmp_path, "10.0.0.0/24\n"))
    runner = ToolRunner(dry_run=True, scope=scope)

    ok = runner.run(["nxc", "smb", "10.0.0.10", "-u", "", "-p", ""])
    assert ok.error is None

    bad = runner.run(["nxc", "smb", "10.0.1.99", "-u", "", "-p", ""])
    assert bad.error is not None
    assert "outside the configured scope" in bad.error


def test_flag_values_not_treated_as_hosts(tmp_path):
    # The domain after -d must not be scope-checked as a host.
    scope = Scope.from_file(_write_scope(tmp_path, "10.0.5.0/24\n"))
    runner = ToolRunner(dry_run=True, scope=scope)
    out = runner.run(
        ["nxc", "ldap", "10.0.5.10", "-d", "corp.local", "-u", "a",
         "-p", "x", "--kerberoasting", "/dev/stdout"]
    )
    assert out.error is None


def test_positional_target_enforced_with_flags_present(tmp_path):
    scope = Scope.from_file(_write_scope(tmp_path, "10.0.0.0/24\n"))
    runner = ToolRunner(dry_run=True, scope=scope)
    bad = runner.run(["nxc", "ldap", "10.9.9.9", "-d", "corp.local", "-u", "a", "-p", "x"])
    assert bad.error is not None
    assert "10.9.9.9" in bad.error


def test_dry_run_previews_without_tool(tmp_path):
    scope = Scope.from_file(_write_scope(tmp_path, "10.0.0.0/24\n"))
    runner = ToolRunner(dry_run=True, scope=scope)
    out = runner.run(["nxc", "smb", "10.0.0.10"])
    assert out.stdout.startswith("[dry-run]")


def test_password_redaction():
    runner = ToolRunner()
    display = runner._redact(
        ["nxc", "smb", "10.0.0.10", "-u", "alice", "-p", "SuperSecret", "-H", "aad3b:31d6c"]
    )
    assert "SuperSecret" not in display
    assert "31d6c" not in display
    assert "******" in display
