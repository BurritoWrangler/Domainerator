"""Tests for AD CS ESC parsing and path-step generation."""

from __future__ import annotations

from domainerator.checks import adcs
from domainerator.paths import Capability
from domainerator.runner import CheckResult, Target


def test_esc_map_covers_esc1_to_esc16():
    # The extended set must be present in the path-grant map.
    for esc in ("ESC1", "ESC8", "ESC9", "ESC10", "ESC13", "ESC15", "ESC16"):
        assert esc in adcs.ESC_PATH_GRANTS
        assert adcs.ESC_PATH_GRANTS[esc] == Capability.CERT_AS_DA


def test_new_esc_ids_have_info():
    for esc in ("ESC13", "ESC15", "ESC16"):
        assert esc in adcs.ESC_INFO


def test_text_parser_recognizes_two_digit_esc():
    findings = adcs._parse_certipy_text(
        "Template T\n  ESC15 : EKUwu application policies\n  ESC16 : security ext disabled\n",
        "corp.local",
    )
    titles = {f.title for f in findings}
    assert any("ESC15" in t for t in titles)
    assert any("ESC16" in t for t in titles)


def test_add_esc_steps_emits_cert_and_pkinit():
    target = Target(host="dc", domain="corp.local", username="u", password="p", dc_ip="1.2.3.4")
    result = CheckResult(name="t", category="adcs")
    adcs._add_esc_steps(result, "ESC15", target)
    grants = {s.grants for s in result.path_steps}
    # cert-as-DA then PKINIT -> DCSYNC
    assert Capability.CERT_AS_DA in grants
    assert Capability.DCSYNC in grants
