"""Step classification for seamless autorun.

``autorun`` walks a selected attack path and executes each step unattended
*where that is safe and deterministic*. This module decides, for a single step,
whether the console can run it on its own or must pause for the operator.

A step is **auto-runnable** only when all of these hold:
  * its command is a single external binary invocation (not ``#`` guidance),
  * every placeholder resolves (no leftover literals like ``VULN-TEMPLATE``),
  * it uses no shell metacharacters (we run without a shell), and
  * its outcome is deterministically checkable from tool output (so we can tell
    success from failure) - i.e. it is not an inherently non-deterministic or
    multi-process step such as offline cracking or a relay/coercion listener.

Everything else is classified ``NEEDS_HUMAN`` with a short reason the console
surfaces, so autorun pauses with a clear instruction instead of stalling or
executing something broken.
"""

from __future__ import annotations

import enum
import shlex
from dataclasses import dataclass

# Shell metacharacters we cannot execute (the runner uses argv, no shell).
_SHELL_META = {"|", ">", "<", ">>", "&&", ";", "&", "||", "`"}

# Techniques whose success cannot be confirmed from a single command's output
# or which require out-of-band work. Autorun pauses on these and hands the
# operator a clear next action rather than pretending they completed.
#   - Hash-crack: offline, depends on the wordlist; no reliable success signal.
#   - Password-spray: lockout-sensitive and timing-dependent; operator decides.
#   - Coercion / relay techniques: multi-process (listener + trigger); handled
#     by the dedicated 'relay' command, not a single blocking exec.
NON_DETERMINISTIC_TECHNIQUES = {
    "Hash-crack",
    "Password-spray",
    "Coercion",
    "WebClientCoercion",
    "RelayToLDAP-RBCD",
    "RelayToLDAP-ShadowCreds",
    "NTLM-Reflection",
    "NTLMv1-crack",
}


class StepClass(enum.Enum):
    """How autorun should treat a step."""

    AUTO = "auto"              # safe to execute unattended
    NEEDS_HUMAN = "needs_human"  # pause and prompt the operator


@dataclass
class Classification:
    """Result of classifying a step for autorun."""

    kind: StepClass
    reason: str = ""
    # The resolved (substituted) command, computed once for reuse.
    resolved_command: str = ""
    # Variables the operator still needs to set (when blocked on that).
    missing_vars: list[str] | None = None


def classify_step(step, variables) -> Classification:
    """Classify ``step`` for autorun using the session's ``variables``.

    ``variables`` is a :class:`~domainerator.console.variables.Variables`.
    This mirrors the guards in ``Console._execute_step`` exactly, so a step
    classified ``AUTO`` here is one that interactive ``run`` would also execute.
    """
    resolved = variables.substitute(step.command)
    stripped = resolved.strip()

    # 1. Guidance / multi-command steps (comment-prefixed) are manual.
    if stripped.startswith("#") or not stripped:
        return Classification(
            StepClass.NEEDS_HUMAN,
            reason="manual/multi-step guidance (not a single command)",
            resolved_command=resolved,
        )

    # 2. Unresolved placeholders -> needs the operator to set variables.
    unresolved = variables.unresolved_placeholders(step.command)
    if unresolved:
        needed = sorted({variables.owner(tok) for tok in unresolved})
        return Classification(
            StepClass.NEEDS_HUMAN,
            reason=f"needs variable(s): {', '.join(needed)}",
            resolved_command=resolved,
            missing_vars=needed,
        )

    # 3. Shell features we can't execute without a shell.
    try:
        argv = shlex.split(resolved, comments=True)
    except ValueError:
        return Classification(
            StepClass.NEEDS_HUMAN,
            reason="command could not be parsed safely",
            resolved_command=resolved,
        )
    if not argv:
        return Classification(
            StepClass.NEEDS_HUMAN,
            reason="empty command",
            resolved_command=resolved,
        )
    if any(tok in _SHELL_META for tok in argv):
        return Classification(
            StepClass.NEEDS_HUMAN,
            reason="uses shell features (pipe/redirect); run it manually",
            resolved_command=resolved,
        )

    # 4. Non-deterministic / multi-process techniques (crack, spray, relay).
    if step.technique in NON_DETERMINISTIC_TECHNIQUES:
        return Classification(
            StepClass.NEEDS_HUMAN,
            reason=(
                f"'{step.technique}' needs operator action "
                "(offline or multi-process); run it, then 'grant' the result"
            ),
            resolved_command=resolved,
        )

    return Classification(StepClass.AUTO, resolved_command=resolved)
