"""Tests for BloodHound-CE ingestion and edge translation."""

from __future__ import annotations

import json

from domainerator import bloodhound as bh
from domainerator.paths import Capability


def _write_ce(tmp_path, doc: dict, name: str = "groups.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(tmp_path)


def test_ce_format_and_high_value_shortcircuit(tmp_path):
    doc = {
        "meta": {"type": "groups", "count": 3, "version": 5, "methods": 0},
        "data": [
            {"Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
             "Aces": [{"RightName": "GenericAll", "PrincipalSID": "S-1-5-21-LOW"}]},
            {"Properties": {"name": "DC01.CORP.LOCAL"},
             "Aces": [{"RightName": "GetChangesAll", "PrincipalSID": "S-1-5-21-LOW"}]},
            {"Properties": {"name": "SVC-SQL@CORP.LOCAL"},
             "Aces": [{"RightName": "ForceChangePassword", "PrincipalSID": "S-1-5-21-LOW"}]},
        ],
    }
    res = bh.ingest(_write_ce(tmp_path, doc))
    grants = {s.grants for s in res.path_steps}
    assert Capability.DOMAIN_ADMIN in grants   # GenericAll over Domain Admins
    assert Capability.DCSYNC in grants          # GetChangesAll on a DC
    # Non-high-value target keeps its base capability.
    assert Capability.RESET_PASSWORD in grants
    assert res.findings and res.findings[0].severity.label == "High"


def test_ce_right_names_case_insensitive(tmp_path):
    doc = {
        "meta": {"type": "computers", "version": 5},
        "data": [
            {"Properties": {"name": "WS01.CORP.LOCAL"},
             "Aces": [
                 {"RightName": "writespn", "PrincipalSID": "S-1-5-21-LOW"},
                 {"RightName": "SyncLAPSPassword", "PrincipalSID": "S-1-5-21-LOW"},
             ]},
        ],
    }
    res = bh.ingest(_write_ce(tmp_path, doc))
    techs = {s.technique for s in res.path_steps}
    assert "WriteSPN" in techs
    assert "SyncLAPSPassword" in techs


def test_unknown_edges_ignored(tmp_path):
    doc = {
        "meta": {"type": "groups", "version": 5},
        "data": [
            {"Properties": {"name": "USERS@CORP.LOCAL"},
             "Aces": [{"RightName": "SomeUnknownRight", "PrincipalSID": "S-1-5-21-LOW"}]},
        ],
    }
    res = bh.ingest(_write_ce(tmp_path, doc))
    assert res.skipped or not res.path_steps


def test_missing_path_skipped():
    res = bh.ingest("/nonexistent/path/does/not/exist")
    assert res.skipped


def test_gpo_control_edge(tmp_path):
    # A GenericAll over a GPO object should grant GPO_CONTROL, not generic DACL.
    doc = {
        "meta": {"type": "gpos", "version": 5},
        "data": [
            {"Properties": {"name": "DEFAULT DOMAIN POLICY@CORP.LOCAL"},
             "Aces": [{"RightName": "GenericAll", "PrincipalSID": "S-1-5-21-LOW"}]},
        ],
    }
    res = bh.ingest(_write_ce(tmp_path, doc, name="gpos.json"))
    grants = {s.grants for s in res.path_steps}
    assert Capability.GPO_CONTROL in grants


def test_write_gplink_edge(tmp_path):
    doc = {
        "meta": {"type": "ous", "version": 5},
        "data": [
            {"Properties": {"name": "SERVERS-OU@CORP.LOCAL"},
             "Aces": [{"RightName": "WriteGPLink", "PrincipalSID": "S-1-5-21-LOW"}]},
        ],
    }
    res = bh.ingest(_write_ce(tmp_path, doc, name="ous.json"))
    grants = {s.grants for s in res.path_steps}
    assert Capability.GPO_CONTROL in grants
