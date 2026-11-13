"""Exploitation state machine for tracking step execution across sessions.

This module provides persistent tracking of step execution, including:
- Step status (PENDING, RUNNING, SUCCEEDED, FAILED, SKIPPED, NEEDS_HUMAN)
- Capability provenance (which step granted each capability)
- Dependency tracking (which capabilities are prerequisites for which steps)
- Orphan detection (manually granted capabilities without step provenance)

The state machine is append-only for audit trail purposes.
"""

from __future__ import annotations

import datetime
import enum
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..paths import Capability

if TYPE_CHECKING:
    from .session import Session


class StepStatus(enum.Enum):
    """Status of a step execution attempt."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    NEEDS_HUMAN = "needs_human"


@dataclass
class StepRecord:
    """Record of a step execution attempt."""

    step_id: str
    path_id: str
    step_index: int
    technique: str
    status: StepStatus
    timestamp: datetime.datetime
    command: str = ""
    output_summary: str = ""
    capability_granted: Capability | None = None
    loot: list[str] = field(default_factory=list)
    failure_reason: str = ""
    retry_count: int = 0

    def to_dict(self) -> dict:
        """Serialize for persistence."""
        return {
            "step_id": self.step_id,
            "path_id": self.path_id,
            "step_index": self.step_index,
            "technique": self.technique,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "command": self.command,
            "output_summary": self.output_summary,
            "capability_granted": self.capability_granted.value
            if self.capability_granted
            else None,
            "loot": self.loot,
            "failure_reason": self.failure_reason,
            "retry_count": self.retry_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> StepRecord:
        """Deserialize from persistence."""
        return cls(
            step_id=data["step_id"],
            path_id=data["path_id"],
            step_index=data["step_index"],
            technique=data["technique"],
            status=StepStatus(data["status"]),
            timestamp=datetime.datetime.fromisoformat(data["timestamp"]),
            command=data.get("command", ""),
            output_summary=data.get("output_summary", ""),
            capability_granted=Capability(data["capability_granted"])
            if data.get("capability_granted")
            else None,
            loot=data.get("loot", []),
            failure_reason=data.get("failure_reason", ""),
            retry_count=data.get("retry_count", 0),
        )


@dataclass
class CapabilityProvenance:
    """Tracks the source of a capability."""

    capability: Capability
    source: str  # "step:<step_id>" or "manual"
    timestamp: datetime.datetime
    detail: str = ""

    def to_dict(self) -> dict:
        """Serialize for persistence."""
        return {
            "capability": self.capability.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CapabilityProvenance:
        """Deserialize from persistence."""
        return cls(
            capability=Capability(data["capability"]),
            source=data["source"],
            timestamp=datetime.datetime.fromisoformat(data["timestamp"]),
            detail=data.get("detail", ""),
        )


class ExploitationStateMachine:
    """Tracks step execution and capability provenance across sessions."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._steps: dict[str, StepRecord] = {}
        self._provenance: dict[Capability, CapabilityProvenance] = {}
        self._step_counter = 0

    def _make_step_id(self) -> str:
        """Generate a unique step ID."""
        self._step_counter += 1
        return f"step-{self._step_counter:04d}-{uuid.uuid4().hex[:8]}"

    def record_step(
        self,
        path_id: str,
        step_index: int,
        technique: str,
        status: StepStatus,
        command: str = "",
        output_summary: str = "",
        capability_granted: Capability | None = None,
        loot: list[str] | None = None,
        failure_reason: str = "",
    ) -> StepRecord:
        """Record a step execution attempt."""
        step_id = self._make_step_id()
        record = StepRecord(
            step_id=step_id,
            path_id=path_id,
            step_index=step_index,
            technique=technique,
            status=status,
            timestamp=datetime.datetime.now(),
            command=command,
            output_summary=output_summary,
            capability_granted=capability_granted,
            loot=loot or [],
            failure_reason=failure_reason,
        )
        self._steps[step_id] = record

        # Track capability provenance
        if capability_granted and status == StepStatus.SUCCEEDED:
            self._provenance[capability_granted] = CapabilityProvenance(
                capability=capability_granted,
                source=f"step:{step_id}",
                timestamp=record.timestamp,
                detail=f"{technique} succeeded",
            )

        return record

    def record_retry(self, step_id: str, status: StepStatus) -> StepRecord | None:
        """Record a retry attempt for an existing step."""
        record = self._steps.get(step_id)
        if not record:
            return None

        record.retry_count += 1
        record.status = status
        record.timestamp = datetime.datetime.now()
        return record

    def grant_manual_capability(
        self,
        capability: Capability,
        detail: str = "",
    ) -> None:
        """Record a manually granted capability."""
        self._provenance[capability] = CapabilityProvenance(
            capability=capability,
            source="manual",
            timestamp=datetime.datetime.now(),
            detail=detail,
        )

    def can_execute(self, required_caps: set[Capability]) -> tuple[bool, set[Capability]]:
        """Check if prerequisites are satisfied. Returns (can_execute, missing)."""
        current_caps = self._session.capabilities
        missing = {c for c in required_caps if c not in current_caps}
        return len(missing) == 0, missing

    def get_orphaned_capabilities(self) -> list[CapabilityProvenance]:
        """Find manually granted capabilities without step provenance."""
        return [
            prov
            for cap, prov in self._provenance.items()
            if prov.source == "manual"
        ]

    def get_step_history(
        self,
        path_id: str | None = None,
        status: StepStatus | None = None,
        limit: int = 100,
    ) -> list[StepRecord]:
        """Get step history with optional filtering."""
        records = list(self._steps.values())
        if path_id:
            records = [r for r in records if r.path_id == path_id]
        if status:
            records = [r for r in records if r.status == status]
        records.sort(key=lambda r: r.timestamp, reverse=True)
        return records[:limit]

    def get_status_summary(self) -> dict:
        """Get summary of step statuses."""
        status_counts = {s.value: 0 for s in StepStatus}
        for record in self._steps.values():
            status_counts[record.status.value] += 1

        total = len(self._steps)
        succeeded = status_counts[StepStatus.SUCCEEDED.value]
        success_rate = (succeeded / total * 100) if total > 0 else 0.0

        return {
            "total_steps": total,
            "status_counts": status_counts,
            "success_rate": round(success_rate, 1),
            "capabilities_held": len(self._provenance),
            "orphaned_capabilities": len(self.get_orphaned_capabilities()),
        }

    def get_capability_source(self, capability: Capability) -> CapabilityProvenance | None:
        """Get the provenance of a specific capability."""
        return self._provenance.get(capability)

    def rebuild_capabilities(self) -> set[Capability]:
        """Rebuild capabilities from step history (for session restoration)."""
        caps: set[Capability] = set()
        for record in self._steps.values():
            if record.status == StepStatus.SUCCEEDED and record.capability_granted:
                caps.add(record.capability_granted)
        return caps

    def to_dict(self) -> dict:
        """Serialize for persistence."""
        return {
            "steps": {k: v.to_dict() for k, v in self._steps.items()},
            "provenance": {
                k.value: v.to_dict() for k, v in self._provenance.items()
            },
            "step_counter": self._step_counter,
        }

    @classmethod
    def from_dict(cls, data: dict, session: Session) -> ExploitationStateMachine:
        """Deserialize from persistence."""
        machine = cls(session)
        machine._step_counter = data.get("step_counter", 0)
        for step_id, step_data in data.get("steps", {}).items():
            machine._steps[step_id] = StepRecord.from_dict(step_data)
        for cap_str, prov_data in data.get("provenance", {}).items():
            machine._provenance[Capability(cap_str)] = CapabilityProvenance.from_dict(
                prov_data
            )
        return machine
