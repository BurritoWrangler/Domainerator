"""Tests for the resume/state file."""

from __future__ import annotations

import json

from domainerator.paths import Capability
from domainerator.state import State


def test_load_missing_returns_empty(tmp_path):
    st = State.load(str(tmp_path / "nope.json"))
    assert st.capabilities == set()
    assert st.seed_capabilities() == set()


def test_roundtrip_and_seed(tmp_path):
    path = str(tmp_path / "state.json")
    st = State()
    st.record_discovered({Capability.VALID_CREDENTIALS, Capability.SPN_TGS})
    st.add_history("scanned dc01")
    st.save(path)

    loaded = State.load(path)
    assert "valid_credentials" in loaded.capabilities
    assert "spn_tgs" in loaded.capabilities
    seeded = loaded.seed_capabilities()
    assert Capability.VALID_CREDENTIALS in seeded
    assert loaded.history == ["scanned dc01"]


def test_invalid_capability_strings_dropped(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"capabilities": ["valid_credentials", "bogus_cap"]}))
    st = State.load(str(path))
    # Unknown capability names are dropped so they can't crash the path engine.
    assert "valid_credentials" in st.capabilities
    assert "bogus_cap" not in st.capabilities


def test_corrupt_file_returns_empty(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ not valid json ")
    st = State.load(str(path))
    assert st.capabilities == set()
