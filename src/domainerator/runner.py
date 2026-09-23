"""Core runner framework for executing external tools and collecting results.

This module provides the plumbing that all check modules build on:

* ``Severity``  - an ordered enum used to rank findings.
* ``Finding``   - a single observation produced by a check.
* ``CheckResult`` - the outcome of running one named check (command that was
  run, raw output, parsed findings, and any error).
* ``ToolRunner`` - a thin wrapper around ``subprocess`` that knows how to locate
  binaries, run them safely, honour timeouts, and record everything for the
  report.

Nothing in here talks to a target directly; the check modules supply the
command arguments. This keeps command construction (and therefore escaping)
in one auditable place.
"""

from __future__ import annotations

import enum
import ipaddress
import logging
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("domainerator")


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value == more serious."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


@dataclass
class Finding:
    """A single security observation produced by a check."""

    title: str
    severity: Severity
    description: str
    # Host/target the finding applies to (may be None for domain-wide items).
    target: str | None = None
    # Free-form supporting evidence (command snippet, matched line, etc.).
    evidence: str = ""
    # Actionable guidance for the operator.
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class CheckResult:
    """The outcome of a single named check."""

    name: str
    category: str
    command: str = ""
    raw_output: str = ""
    return_code: int | None = None
    duration_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    skipped: bool = False
    skip_reason: str = ""
    # Inconclusive: the tool ran successfully but its output did not match any
    # known pattern, so we can neither confirm nor rule out the issue. This is
    # deliberately distinct from "ran and found nothing" (clean) so a parser
    # miss or a changed tool-output format is never read as all-clear.
    inconclusive: bool = False
    inconclusive_reason: str = ""
    # Attack-path steps this check contributes (typed as Any to avoid a circular
    # import with paths.py; populated with paths.PathStep instances).
    path_steps: list = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_step(self, step) -> None:
        """Attach a paths.PathStep discovered by this check."""
        self.path_steps.append(step)

    def mark_inconclusive(self, reason: str) -> None:
        """Flag that the tool ran but produced no interpretable signal.

        Only meaningful when the check found nothing; if a finding was already
        recorded the result is conclusive and this is a no-op.
        """
        if not self.findings:
            self.inconclusive = True
            self.inconclusive_reason = reason

    @property
    def status(self) -> str:
        """One-word status for reporting."""
        if self.skipped:
            return "skipped"
        if self.error:
            return "error"
        if self.findings:
            return "findings"
        if self.inconclusive:
            return "inconclusive"
        return "clean"

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "command": self.command,
            "return_code": self.return_code,
            "duration_seconds": round(self.duration_seconds, 2),
            "status": self.status,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "inconclusive": self.inconclusive,
            "inconclusive_reason": self.inconclusive_reason,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output": self.raw_output,
        }


@dataclass
class CommandOutput:
    """Raw result of executing an external command."""

    command: str
    return_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: str | None = None

    @property
    def combined(self) -> str:
        """stdout and stderr merged, which is what most CLI tools want."""
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(self.stderr)
        return "\n".join(parts).strip()


class ScopeError(Exception):
    """Raised when an operation would touch a target outside the allowed scope."""


class Scope:
    """An allowlist of IPs / CIDR subnets that testing must stay within.

    Loaded from a file with one entry per line. Blank lines and ``#`` comments
    are ignored. Each entry is either a single IP (``10.0.0.5``), a CIDR subnet
    (``10.0.0.0/24``), or a bare hostname/IP. When a scope is active, every
    command the runner executes is checked: any host argument that resolves to
    an address outside the scope aborts the command.

    This is a safety control for authorized engagements - it prevents the tool
    (or a mistyped target) from ever touching systems outside the agreed range.
    """

    # Tokens that look like a host/IP we should scope-check. We deliberately
    # keep this conservative: flags (starting with '-') and obvious non-hosts
    # are ignored, and hostname resolution failures are treated as in-scope-
    # unknown and reported rather than silently allowed.
    _HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

    def __init__(self) -> None:
        self._networks: list[ipaddress._BaseNetwork] = []
        self._hostnames: set[str] = set()
        self._raw_entries: list[str] = []
        self.active: bool = False

    @classmethod
    def from_file(cls, path: str) -> Scope:
        scope = cls()
        text = Path(path).read_text(encoding="utf-8")
        for lineno, raw in enumerate(text.splitlines(), 1):
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            scope._add_entry(entry, lineno)
        if not scope._networks and not scope._hostnames:
            raise ScopeError(f"scope file '{path}' contained no usable entries")
        scope.active = True
        return scope

    def _add_entry(self, entry: str, lineno: int) -> None:
        self._raw_entries.append(entry)
        # Try CIDR / network first, then single IP, then treat as hostname.
        try:
            if "/" in entry:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
                return
            ip = ipaddress.ip_address(entry)
            # Store single IPs as /32 or /128 networks for uniform matching.
            self._networks.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
            return
        except ValueError:
            pass
        if self._HOST_RE.match(entry):
            self._hostnames.add(entry.lower())
        else:
            raise ScopeError(f"scope file line {lineno}: invalid entry '{entry}'")

    def _addresses_for(self, host: str) -> list[ipaddress._BaseAddress]:
        """Resolve ``host`` to IP addresses. Returns [] if it can't resolve."""
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, UnicodeError, OSError):
            return []
        addrs: list[ipaddress._BaseAddress] = []
        for info in infos:
            sockaddr = info[4]
            try:
                addrs.append(ipaddress.ip_address(sockaddr[0]))
            except ValueError:
                continue
        return addrs

    def contains(self, host: str) -> bool:
        """True if ``host`` is within scope (by IP membership or hostname match)."""
        if not self.active:
            return True
        if host.lower() in self._hostnames:
            return True
        addrs = self._addresses_for(host)
        if not addrs:
            # Unresolvable and not an explicit hostname entry -> out of scope.
            return False
        for addr in addrs:
            for net in self._networks:
                if addr.version == net.version and addr in net:
                    return True
        return False

    def check_argv(self, argv: list[str]) -> str | None:
        """Return an out-of-scope host found in ``argv``, or None if all clear.

        Only the tokens that plausibly look like hostnames/IPs are examined.
        The first out-of-scope host encountered is returned so the caller can
        refuse the command and report which target violated scope.
        """
        if not self.active:
            return None

        prev_was_flag = False
        for token in argv[1:]:  # argv[0] is the tool binary
            if token.startswith("-"):
                # This is a flag; its following token is the flag's value, not
                # the positional target, so we skip that value from scoping.
                prev_was_flag = True
                continue
            if prev_was_flag:
                # Value of a flag (e.g. the domain after -d, the file after
                # -usersfile, the dc-ip after --dc-ip). Not the positional
                # target - scope of those hosts is validated separately at
                # startup (target and dc-ip), so we don't guess here.
                prev_was_flag = False
                continue
            prev_was_flag = False

            if "/" in token or "\\" in token or "@" in token or "=" in token:
                # paths, UPNs, key=value options - not a bare host
                continue
            if not self._HOST_RE.match(token):
                continue
            # Only treat it as a host if it looks like an IP or a dotted
            # hostname. Bare words like 'smb'/'ldap' (nxc protocol) are skipped.
            if not (_looks_like_ip(token) or "." in token):
                continue
            if not self.contains(token):
                return token
        return None

    def describe(self) -> str:
        return ", ".join(self._raw_entries)


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


class ToolRunner:
    """Locates and executes external penetration-testing tools.

    Commands are always passed as an argument *list* (never a shell string) so
    that target-supplied values such as usernames and passwords cannot break
    out into shell metacharacters.

    When a :class:`Scope` is provided, every command is checked against it
    before execution; a command targeting an out-of-scope host is refused.
    """

    def __init__(
        self,
        timeout: int = 300,
        dry_run: bool = False,
        verbose: bool = False,
        scope: Scope | None = None,
    ) -> None:
        self.timeout = timeout
        self.dry_run = dry_run
        self.verbose = verbose
        self.scope = scope
        # Cache of tool name -> resolved absolute path (or None if missing).
        self._tool_cache: dict[str, str | None] = {}

    def find_tool(self, name: str) -> str | None:
        """Return the absolute path to ``name`` on PATH, or None if absent."""
        if name not in self._tool_cache:
            self._tool_cache[name] = shutil.which(name)
        return self._tool_cache[name]

    def is_available(self, name: str) -> bool:
        return self.find_tool(name) is not None

    def get_version(self, name: str, version_args: tuple[str, ...] = ("--version",)) -> str | None:
        """Best-effort version string for a tool, or None if unavailable.

        Version flags are not standardized across these tools, so we try the
        common ones and return the first non-empty line of output. This is for
        the report's tool inventory, letting an operator correlate a parser
        miss with a tool-version change; it is never used for logic.
        """
        if not self.is_available(name):
            return None
        # Version discovery is not scope-relevant (it hits no target), and it
        # must work even in dry-run, so we bypass ToolRunner.run() here.
        resolved = self.find_tool(name)
        if resolved is None:
            return None
        import subprocess as _sp

        for arg in version_args:
            try:
                proc = _sp.run(
                    [resolved, arg],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, _sp.TimeoutExpired):
                continue
            out = (proc.stdout or "") + (proc.stderr or "")
            for line in out.splitlines():
                line = line.strip()
                if line:
                    return line[:200]
        return "unknown"

    @staticmethod
    def _redact(argv: list[str]) -> str:
        """Build a display string for the command, masking password values.

        We look for the common password flags and replace the *following*
        token so secrets never land in the report or logs.
        """
        password_flags = {"-p", "--password", "-H", "--hash", "-k", "--pass"}
        redacted: list[str] = []
        mask_next = False
        for token in argv:
            if mask_next:
                redacted.append("******")
                mask_next = False
                continue
            redacted.append(token)
            if token in password_flags:
                mask_next = True
        return " ".join(redacted)

    def run(self, argv: list[str], timeout: int | None = None) -> CommandOutput:
        """Execute ``argv`` and capture its output.

        The first element of ``argv`` is resolved against PATH. If the binary
        cannot be found a CommandOutput with an ``error`` is returned rather
        than raising, so a single missing tool never aborts the whole run.
        """
        if not argv:
            raise ValueError("argv must not be empty")

        display = self._redact(argv)
        tool = argv[0]

        # Scope enforcement: refuse anything targeting an out-of-scope host.
        if self.scope is not None and self.scope.active:
            offending = self.scope.check_argv(argv)
            if offending is not None:
                return CommandOutput(
                    command=display,
                    return_code=None,
                    stdout="",
                    stderr="",
                    duration_seconds=0.0,
                    error=(
                        f"refused: target '{offending}' is outside the "
                        "configured scope"
                    ),
                )

        if self.verbose:
            logger.info("running: %s", display)

        # In dry-run we show the (scope-approved) command without needing the
        # tool installed, so operators can preview a plan on any machine.
        if self.dry_run:
            return CommandOutput(
                command=display,
                return_code=0,
                stdout="[dry-run] command not executed",
                stderr="",
                duration_seconds=0.0,
            )

        resolved = self.find_tool(tool)

        if resolved is None:
            return CommandOutput(
                command=display,
                return_code=None,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                error=f"tool '{tool}' not found on PATH",
            )

        real_argv = [resolved, *argv[1:]]
        effective_timeout = timeout if timeout is not None else self.timeout

        start = time.monotonic()
        try:
            proc = subprocess.run(
                real_argv,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - start
            partial_out = exc.stdout or ""
            partial_err = exc.stderr or ""
            if isinstance(partial_out, bytes):
                partial_out = partial_out.decode(errors="replace")
            if isinstance(partial_err, bytes):
                partial_err = partial_err.decode(errors="replace")
            return CommandOutput(
                command=display,
                return_code=None,
                stdout=partial_out,
                stderr=partial_err,
                duration_seconds=elapsed,
                timed_out=True,
                error=f"timed out after {effective_timeout}s",
            )
        except OSError as exc:
            elapsed = time.monotonic() - start
            return CommandOutput(
                command=display,
                return_code=None,
                stdout="",
                stderr="",
                duration_seconds=elapsed,
                error=f"failed to execute: {exc}",
            )

        elapsed = time.monotonic() - start
        return CommandOutput(
            command=display,
            return_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_seconds=elapsed,
        )

    def run_background(self, argv: list[str]) -> BackgroundProcess:
        """Start ``argv`` as a long-running background process.

        Unlike :meth:`run`, this returns immediately with a
        :class:`BackgroundProcess` handle whose stdout/stderr are captured to a
        thread-safe buffer. It is intended for listeners (e.g. ``ntlmrelayx``)
        that must keep running while another command (a coercion trigger) is
        fired against them.

        Scope enforcement and dry-run behaviour mirror :meth:`run`. A refused or
        missing-tool start yields a handle that is not ``alive`` and carries an
        ``error`` string, so callers never have to distinguish a raised
        exception from a failed launch.
        """
        if not argv:
            raise ValueError("argv must not be empty")

        display = self._redact(argv)
        tool = argv[0]

        if self.scope is not None and self.scope.active:
            offending = self.scope.check_argv(argv)
            if offending is not None:
                return BackgroundProcess.failed(
                    display,
                    f"refused: target '{offending}' is outside the configured scope",
                )

        if self.verbose:
            logger.info("starting background: %s", display)

        if self.dry_run:
            return BackgroundProcess.dry_run(display)

        resolved = self.find_tool(tool)
        if resolved is None:
            return BackgroundProcess.failed(
                display, f"tool '{tool}' not found on PATH"
            )

        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                [resolved, *argv[1:]],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            return BackgroundProcess.failed(display, f"failed to start: {exc}")

        return BackgroundProcess(command=display, process=proc)


@dataclass
class BackgroundProcess:
    """A handle to a long-running child process with captured output.

    Output is drained on a daemon thread into an internal buffer so a caller
    can poll :meth:`read_new` without risking a pipe-buffer deadlock. Use
    :meth:`stop` to terminate cleanly (SIGTERM, then SIGKILL on timeout).
    """

    command: str
    process: subprocess.Popen | None = None
    error: str | None = None
    # Whole captured output so far.
    _buffer: list[str] = field(default_factory=list)
    _read_index: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _reader: threading.Thread | None = None
    _dry_run: bool = False

    def __post_init__(self) -> None:
        if self.process is not None:
            self._reader = threading.Thread(target=self._drain, daemon=True)
            self._reader.start()

    # --- constructors for non-started handles ---------------------------
    @classmethod
    def failed(cls, command: str, error: str) -> BackgroundProcess:
        return cls(command=command, process=None, error=error)

    @classmethod
    def dry_run(cls, command: str) -> BackgroundProcess:
        handle = cls(command=command, process=None)
        handle._dry_run = True
        handle._buffer.append("[dry-run] background process not started")
        return handle

    # --- lifecycle -------------------------------------------------------
    def _drain(self) -> None:
        assert self.process is not None
        stream = self.process.stdout
        if stream is None:
            return
        for line in stream:
            with self._lock:
                self._buffer.append(line.rstrip("\n"))

    @property
    def alive(self) -> bool:
        """True while the process is running."""
        if self._dry_run:
            return False
        if self.process is None:
            return False
        return self.process.poll() is None

    @property
    def started(self) -> bool:
        """True if the process was actually launched (not refused/missing)."""
        return self.process is not None or self._dry_run

    def output(self) -> str:
        """Return all captured output so far."""
        with self._lock:
            return "\n".join(self._buffer)

    def read_new(self) -> str:
        """Return output captured since the last call to :meth:`read_new`."""
        with self._lock:
            new = self._buffer[self._read_index:]
            self._read_index = len(self._buffer)
        return "\n".join(new)

    def stop(self, timeout: float = 5.0) -> None:
        """Terminate the process (SIGTERM, then SIGKILL) and reap it."""
        if self.process is None:
            return
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass


@dataclass
class Target:
    """Everything a check needs to know about what and how to test."""

    host: str
    domain: str | None = None
    username: str | None = None
    password: str | None = None
    nthash: str | None = None
    use_kerberos: bool = False
    dc_ip: str | None = None

    @property
    def authenticated(self) -> bool:
        """True when we have some form of credential to authenticate with."""
        return bool(self.username and (self.password or self.nthash))

    def nxc_auth_args(self) -> list[str]:
        """Return the netexec auth arguments for this target.

        Empty username/password produce a null/anonymous session, which is
        exactly what the unauthenticated checks want.
        """
        args: list[str] = []
        if self.domain:
            args += ["-d", self.domain]
        args += ["-u", self.username or ""]
        if self.nthash:
            args += ["-H", self.nthash]
        else:
            args += ["-p", self.password or ""]
        if self.use_kerberos:
            args += ["-k"]
        return args
