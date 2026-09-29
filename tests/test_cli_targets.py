"""Tests for target parsing / CIDR expansion in the CLI."""

from __future__ import annotations

import argparse

import pytest

from domainerator.cli import MAX_CIDR_HOSTS, expand_target, load_targets

# --- expand_target ---------------------------------------------------------

def test_expand_plain_ip_unchanged():
    assert expand_target("10.0.0.10") == ["10.0.0.10"]


def test_expand_hostname_unchanged():
    assert expand_target("dc01.corp.local") == ["dc01.corp.local"]


def test_expand_cidr_slash30_gives_usable_hosts():
    # /30 has 2 usable hosts (network/broadcast excluded).
    assert expand_target("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_expand_slash32_single_host():
    assert expand_target("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_cidr_with_host_bits_normalizes():
    # strict=False: host bits set are interpreted as the containing network.
    hosts = expand_target("10.0.0.7/24")
    assert hosts[0] == "10.0.0.1"
    assert len(hosts) == 254


def test_expand_ipv6_cidr():
    assert expand_target("2001:db8::/126") == [
        "2001:db8::1", "2001:db8::2", "2001:db8::3",
    ]


def test_expand_pathlike_string_is_opaque():
    # Not a valid network -> passed through untouched (downstream decides).
    assert expand_target("corp.local/user") == ["corp.local/user"]


def test_expand_oversized_cidr_raises():
    with pytest.raises(ValueError) as exc:
        expand_target("10.0.0.0/8")
    assert str(MAX_CIDR_HOSTS) in str(exc.value)


# --- load_targets ----------------------------------------------------------

def _args(target=None, targets=None):
    return argparse.Namespace(target=target, targets=targets)


def test_load_targets_expands_single_cidr():
    assert load_targets(_args(target="10.0.0.0/30")) == ["10.0.0.1", "10.0.0.2"]


def test_load_targets_dedupes_across_sources(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("10.0.0.1\n# comment\n10.0.0.0/30\n", encoding="utf-8")
    # --target overlaps the CIDR expansion from the file; result de-duplicates.
    result = load_targets(_args(target="10.0.0.1", targets=str(f)))
    assert result == ["10.0.0.1", "10.0.0.2"]


def test_load_targets_preserves_order():
    f_target = "10.0.0.5"
    assert load_targets(_args(target=f_target)) == ["10.0.0.5"]


def test_load_targets_oversized_cidr_propagates_valueerror():
    with pytest.raises(ValueError):
        load_targets(_args(target="10.0.0.0/8"))
