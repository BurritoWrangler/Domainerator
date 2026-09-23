"""Output-driven outcome detection for executed steps.

After a step's command runs, we inspect its output to decide whether it
succeeded and, if so, which capability was obtained. This turns the console
from a viewer into a reactive loop: a successful Kerberoast auto-grants the
resulting capability and re-triggers path recomputation.

Detection is intentionally conservative and technique-aware. Each entry pairs a
regex against the tool output with the capability that a match implies. We key
primarily off the step's ``technique`` (stable, tool-independent) and fall back
to generic signals. A non-match is reported as "unconfirmed" rather than
"failed" so an operator is never misled into thinking a step did nothing when a
parser simply didn't recognise a new output format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..paths import Capability


@dataclass
class Outcome:
    """The interpreted result of running a step."""

    success: bool
    capability: Capability | None
    detail: str
    # Any loot strings extracted from the output (hashes, tickets, etc.).
    loot: list[str]


# Technique-id -> (compiled regex, extract group description). A match means the
# step's ``grants`` capability was obtained. Techniques not listed fall through
# to generic detection.
_TECHNIQUE_SIGNALS: dict[str, re.Pattern[str]] = {
    "Kerberoast": re.compile(r"\$krb5tgs\$", re.IGNORECASE),
    "AS-REP-roast": re.compile(r"\$krb5asrep\$", re.IGNORECASE),
    "RID-cycling": re.compile(r"SidTypeUser", re.IGNORECASE),
    "Password-spray": re.compile(r"\[\+\]\s+\S+\\\S+:", re.IGNORECASE),
    # certipy prints the saved cert on success.
    "ESC1": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC8": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "PKINIT-auth": re.compile(r"Got hash for|Saved credential cache|got TGT", re.IGNORECASE),
    "DCSync": re.compile(r":::|Administrator:500:", re.IGNORECASE),
    "noPac": re.compile(r"Saved.*ccache|Impersonat", re.IGNORECASE),
    "RelayToLDAP-RBCD": re.compile(r"Delegation rights|rbcd|Attribute msDS", re.IGNORECASE),
}

# Loot extraction patterns: capture the whole matching token(s).
_LOOT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$krb5tgs\$[^\s]+"),
    re.compile(r"\$krb5asrep\$[^\s]+"),
    re.compile(r"[A-Za-z0-9_.$-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::"),  # NTLM hashes
]

# Generic failure signals that suggest the command did not achieve anything.
_FAILURE_SIGNALS = re.compile(
    r"STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|connection refused|"
    r"timed out|could not connect|No entries|error:|Traceback",
    re.IGNORECASE,
)


def interpret(technique: str, grants: Capability, output: str) -> Outcome:
    """Interpret command ``output`` for a step of ``technique`` granting ``grants``.

    Returns an :class:`Outcome`. ``success`` is True only when a positive signal
    is found; a bare non-error output is treated as unconfirmed (success=False)
    so we never over-claim.
    """
    loot = _extract_loot(output)

    signal = _TECHNIQUE_SIGNALS.get(technique)
    if signal is not None and signal.search(output):
        return Outcome(
            success=True,
            capability=grants,
            detail=f"{technique} succeeded (matched success signal)",
            loot=loot,
        )

    # Generic positive: a certipy/impacket "saved"/"got" line even for a
    # technique without a specific pattern.
    if re.search(r"Saved (certificate|credential|TGT)|Got (certificate|hash|TGT)",
                 output, re.IGNORECASE):
        return Outcome(
            success=True,
            capability=grants,
            detail=f"{technique}: generic success signal matched",
            loot=loot,
        )

    if _FAILURE_SIGNALS.search(output):
        return Outcome(
            success=False,
            capability=None,
            detail=f"{technique}: output shows a failure/error signal",
            loot=loot,
        )

    # Ran but no recognised signal - unconfirmed.
    return Outcome(
        success=False,
        capability=None,
        detail=(
            f"{technique}: no recognised success signal in output "
            "(unconfirmed - verify manually and use 'grant' if it worked)"
        ),
        loot=loot,
    )


def _extract_loot(output: str) -> list[str]:
    loot: list[str] = []
    for pat in _LOOT_PATTERNS:
        loot.extend(pat.findall(output))
    # De-duplicate, preserve order.
    seen: set[str] = set()
    unique: list[str] = []
    for item in loot:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
