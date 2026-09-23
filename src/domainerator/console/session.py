"""Session management for interactive console."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..paths import AttackPath, Capability, PathEngine, PathStep
from ..runner import CheckResult, Target, ToolRunner
from ..state import State
from .variables import Variables


@dataclass
class Session:
    """Runtime state for an interactive Domainerator session.

    This object holds all discovered information and tracks the operator's
    current privilege state, enabling iterative exploitation workflows.
    """

    # Core components
    runner: ToolRunner
    target: Target                       # the active target
    state: State = field(default_factory=State)

    # All scanned hosts, so the operator can switch the active target and so
    # 'relay' can pick a victim from real, in-scope hosts. Populated by the CLI
    # at launch; the active ``target`` is always one of these (or a lone host).
    targets: list[Target] = field(default_factory=list)

    # Accumulated results from all scans
    check_results: list[CheckResult] = field(default_factory=list)

    # Current privilege state (runtime tracking)
    capabilities: set[Capability] = field(default_factory=set)

    # Discovered attack paths (computed from check_results)
    attack_paths: list[AttackPath] = field(default_factory=list)

    # Currently selected path/module for exploitation
    selected_path: AttackPath | None = None
    selected_step_index: int = 0  # Current step within selected path

    # Operator-settable variables for command substitution.
    variables: Variables = field(default_factory=Variables)

    # Loot collected from executed step output (hashes, tickets, certs).
    loot: list[str] = field(default_factory=list)

    # Optional evidence writer: when set, executed steps and generated reports
    # are saved to the engagement output folder for report screenshots.
    evidence: object | None = None

    # Session metadata
    state_path: str | None = None
    modified: bool = False

    def __post_init__(self) -> None:
        # Ensure the active target is always represented in the targets list so
        # 'targets'/'target <id>' and relay victim selection see a complete set.
        if not self.targets:
            self.targets = [self.target]
        elif self.target not in self.targets:
            self.targets.insert(0, self.target)
        # Auto-populate variables from the target so common placeholders
        # (DC, DOMAIN, USER, PASS, DC_IP) are filled without manual `set`.
        self.variables.seed_from_target(self.target)

    def target_hosts(self) -> list[str]:
        """Return the host string of every scanned target, order preserved."""
        return [t.host for t in self.targets]

    def switch_target(self, index: int) -> bool:
        """Make the target at ``index`` (0-based) active. Returns False if bad.

        Switching re-seeds command variables from the newly active target so
        DC/DOMAIN/USER/PASS/DC_IP follow the host you're working on. Explicitly
        operator-set variables are preserved (seed_from_target never overrides
        a value already present).
        """
        if not (0 <= index < len(self.targets)):
            return False
        self.target = self.targets[index]
        self.variables.seed_from_target(self.target)
        return True

    def add_loot(self, items: list[str]) -> None:
        """Record loot strings, de-duplicating against what we already have."""
        for item in items:
            if item not in self.loot:
                self.loot.append(item)
                self.modified = True

    def add_result(self, result: CheckResult) -> None:
        """Add a check result and update capabilities."""
        self.check_results.append(result)
        # Extract granted capabilities from path steps
        for step in result.path_steps or []:
            self.capabilities.add(step.grants)
        self.modified = True

    def add_results(self, results: list[CheckResult]) -> None:
        """Add multiple check results."""
        for r in results:
            self.add_result(r)

    def recompute_paths(self, max_depth: int = 8) -> None:
        """Rebuild attack paths from accumulated check results."""
        engine = PathEngine()
        # Add baseline glue steps
        from ..paths import baseline_steps
        engine.add_steps(baseline_steps())

        # Add all steps from check results
        for result in self.check_results:
            for step in result.path_steps or []:
                engine.add_step(step)

        # Include seed capabilities from state
        start_caps = self.capabilities | self.state.seed_capabilities()

        # Find paths to goals
        self.attack_paths = engine.find_paths(start_caps, max_depth=max_depth)

    def current_step(self) -> PathStep | None:
        """Return the currently selected step, if any."""
        if not self.selected_path:
            return None
        if self.selected_step_index >= len(self.selected_path.steps):
            return None
        return self.selected_path.steps[self.selected_step_index]

    def next_step(self) -> PathStep | None:
        """Advance to the next step in the selected path."""
        if not self.selected_path:
            return None
        self.selected_step_index += 1
        return self.current_step()

    def select_path(self, path_id: int) -> bool:
        """Select an attack path by index (0-based). Returns False if invalid."""
        if 0 <= path_id < len(self.attack_paths):
            self.selected_path = self.attack_paths[path_id]
            self.selected_step_index = 0
            return True
        return False

    def clear_selection(self) -> None:
        """Deselect the current path."""
        self.selected_path = None
        self.selected_step_index = 0

    def has_capability(self, cap: Capability) -> bool:
        """Check if a capability is currently held."""
        return cap in self.capabilities

    def grant_capability(self, cap: Capability) -> None:
        """Manually grant a capability (e.g., after successful exploitation)."""
        self.capabilities.add(cap)
        self.state.record_discovered({cap})
        self.modified = True

    def save(self, path: str | None = None) -> None:
        """Persist session state to file."""
        save_path = path or self.state_path
        if save_path:
            # Record discovered capabilities to state
            self.state.record_discovered(self.capabilities)
            self.state.save(save_path)
            self.state_path = save_path
            self.modified = False

    def load(self, path: str) -> None:
        """Load session state from file."""
        self.state = State.load(path)
        self.state_path = path
        # Seed capabilities from loaded state
        self.capabilities |= self.state.seed_capabilities()

    def describe_capabilities(self) -> str:
        """Return a human-readable summary of current capabilities."""
        if not self.capabilities:
            return "No capabilities obtained yet"

        # Group by category
        by_category: dict[str, list[Capability]] = {
            "starting": [],
            "footholds": [],
            "escalation": [],
            "goals": [],
        }

        for cap in sorted(self.capabilities, key=lambda c: c.value):
            if cap.is_goal:
                by_category["goals"].append(cap)
            elif cap in {
                Capability.UNAUTHENTICATED,
                Capability.VALID_CREDENTIALS,
                Capability.LOW_PRIV_USER,
            }:
                by_category["starting"].append(cap)
            else:
                by_category["footholds"].append(cap)

        lines = []
        if by_category["starting"]:
            lines.append(
                "Starting: " + ", ".join(c.value for c in by_category["starting"])
            )
        if by_category["footholds"]:
            lines.append(
                "Footholds: " + ", ".join(c.value for c in by_category["footholds"])
            )
        if by_category["goals"]:
            lines.append(
                "Goals achieved: " + ", ".join(c.value for c in by_category["goals"])
            )

        return "\n".join(lines) if lines else "No capabilities obtained yet"
