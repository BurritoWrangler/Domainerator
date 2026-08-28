"""Resume / state file support.

Domainerator's workflow is iterative: enumerate, run some commands manually
(crack a hash, gain creds, collect BloodHound), then re-run to get updated
paths. A state file persists what has been *discovered* so a re-run doesn't
have to redo enumeration and so operator-gained capabilities can be fed back
in.

The state is intentionally small and human-editable JSON:

* ``capabilities`` - extra starting capabilities the operator has obtained
  (e.g. after cracking a hash you can add ``valid_credentials``). These seed
  the path engine on the next run.
* ``notes`` - free-form operator notes (not interpreted).

We keep this separate from the report: the report is an output artifact, the
state file is an input+output that carries context between runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .paths import Capability


@dataclass
class State:
    """Persistent, cross-run scan state."""

    # Capability values (strings matching Capability enum values) the operator
    # has manually obtained and wants seeded into the next run.
    capabilities: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    # Free-form record of prior runs (targets scanned), for context only.
    history: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> State:
        """Load state from ``path``. A missing file yields empty state."""
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls()
        caps = set(data.get("capabilities", []))
        # Keep only capability strings we recognise, so a typo can't crash the
        # path engine later.
        valid = {c.value for c in Capability}
        caps = {c for c in caps if c in valid}
        return cls(
            capabilities=caps,
            notes=list(data.get("notes", [])),
            history=list(data.get("history", [])),
        )

    def seed_capabilities(self) -> set[Capability]:
        """Translate stored capability strings into Capability enum members."""
        by_value = {c.value: c for c in Capability}
        return {by_value[c] for c in self.capabilities if c in by_value}

    def record_discovered(self, caps: set[Capability]) -> None:
        """Merge newly discovered capabilities into the state."""
        for cap in caps:
            self.capabilities.add(cap.value)

    def add_history(self, entry: str) -> None:
        self.history.append(entry)

    def to_dict(self) -> dict:
        return {
            "capabilities": sorted(self.capabilities),
            "notes": self.notes,
            "history": self.history,
        }

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
