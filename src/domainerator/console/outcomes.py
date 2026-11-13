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
    # Kerberos attacks
    "Kerberoast": re.compile(r"\$krb5tgs\$", re.IGNORECASE),
    "AS-REP-roast": re.compile(r"\$krb5asrep\$", re.IGNORECASE),
    "RID-cycling": re.compile(r"SidTypeUser", re.IGNORECASE),
    "Password-spray": re.compile(r"\[\+\]\s+\S+\\\S+:", re.IGNORECASE),
    # ADCS ESC techniques - certipy prints the saved cert on success
    "ESC1": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC2": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC3": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC4": re.compile(r"Updated template|Modified template|Saved certificate", re.IGNORECASE),
    "ESC6": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC8": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC9": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC10": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC11": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC12": re.compile(r"Exported.*key|Private key|Saved certificate", re.IGNORECASE),
    "ESC13": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC14": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC15": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    "ESC16": re.compile(r"Saved certificate.*\.pfx|Got certificate", re.IGNORECASE),
    # PKINIT and authentication
    "PKINIT-auth": re.compile(r"Got hash for|Saved credential cache|got TGT", re.IGNORECASE),
    "DCSync": re.compile(r":::|Administrator:500:", re.IGNORECASE),
    "noPac": re.compile(r"Saved.*ccache|Impersonat", re.IGNORECASE),
    # Relay techniques
    "RelayToLDAP-RBCD": re.compile(r"Delegation rights|rbcd|Attribute msDS", re.IGNORECASE),
    "RelayToLDAP-ShadowCreds": re.compile(r"KeyCredential|Shadow credential", re.IGNORECASE),
    "NTLM-Reflection": re.compile(r"Authenticating|SMBD-Thread|Authentication success", re.IGNORECASE),
    # Coercion
    "Coercion": re.compile(r"authenticated to|VULNERABLE|coerc.*success", re.IGNORECASE),
    "PetitPotam": re.compile(r"authenticated to|VULNERABLE", re.IGNORECASE),
    "PrinterBug": re.compile(r"authenticated to|VULNERABLE", re.IGNORECASE),
    "DFSCoerce": re.compile(r"authenticated to|VULNERABLE", re.IGNORECASE),
    "ShadowCoerce": re.compile(r"authenticated to|VULNERABLE", re.IGNORECASE),
    # RBCD and Shadow Credentials
    "RBCD": re.compile(r"Delegation rights|was set successfully", re.IGNORECASE),
    "RBCD-Configure": re.compile(r"Delegation rights|was set successfully", re.IGNORECASE),
    "Shadow-Credentials": re.compile(r"KeyCredential|Shadow credential|Updated", re.IGNORECASE),
    # GPP and credential recovery
    "GPP-cpassword": re.compile(r"Username:.*Password:|Found credentials", re.IGNORECASE),
    "SYSVOL-script-creds": re.compile(r"password|Password|credential", re.IGNORECASE),
    # Pre-2k and legacy accounts
    "Pre2k": re.compile(r"\[\+\]|\[Pp\]wn3d|SMB.*success", re.IGNORECASE),
    "Pre2k-auth": re.compile(r"\[\+\]|\[Pp\]wn3d|SMB.*success", re.IGNORECASE),
    "Pre-Windows 2000": re.compile(r"\[\+\]|\[Pp\]wn3d|SMB.*success", re.IGNORECASE),
    # Machine account abuse
    "MAQ-abuse": re.compile(r"Successfully added|Computer created|password:", re.IGNORECASE),
    "Certifried": re.compile(r"Successfully added|Computer created", re.IGNORECASE),
    # DNS and enumeration
    "DNS-AXFR": re.compile(r"XFR size|Transfer succeeded", re.IGNORECASE),
    "DNS-zone-transfer": re.compile(r"XFR size|Transfer succeeded", re.IGNORECASE),
    "Timeroast": re.compile(r"\$sntp-ms\$", re.IGNORECASE),
    "Kerberos-user-enum": re.compile(r"VALID USERNAME", re.IGNORECASE),
    # Relay targets
    "NTLM-relay-target": re.compile(r"signing.*False|signing.*disabled", re.IGNORECASE),
    "LDAP-relay-target": re.compile(r"NOT.*Enforced|NOT.*Require|Signing.*False", re.IGNORECASE),
    # NTLM variants
    "NTLMv1": re.compile(r"NTLMv1|LM.*NT", re.IGNORECASE),
    "NTLMv1-crack": re.compile(r"\$NTLM\$|cracked", re.IGNORECASE),
    # Credential dumping
    "Cred-dump": re.compile(r"\$krb5tgs\$|:::|[a-f0-9]{32}:[a-f0-9]{32}", re.IGNORECASE),
    "Local-admin": re.compile(r"Pwn3d!|\[\+\].*admin", re.IGNORECASE),
    # LAPS and gMSA
    "LAPS": re.compile(r"Password:|LAPS.*password", re.IGNORECASE),
    "gMSA": re.compile(r"NTLM:|managed.*password", re.IGNORECASE),
    # DnsAdmins
    "DnsAdmins": re.compile(r"member:|DnsAdmins", re.IGNORECASE),
    # SCCM
    "SCCM-NAA": re.compile(r"Network Access Account|NAA|password:", re.IGNORECASE),
    # Network footholds
    "EternalBlue": re.compile(r"VULNERABLE|exploit.*success", re.IGNORECASE),
    "SMBGhost": re.compile(r"VULNERABLE|exploit.*success", re.IGNORECASE),
    "Cisco-SMI": re.compile(r"VULNERABLE|enabled", re.IGNORECASE),
    "Anonymous-FTP": re.compile(r"Anonymous.*login|230.*Login", re.IGNORECASE),
    "NFS-export": re.compile(r"export|share", re.IGNORECASE),
    "SNMP-community": re.compile(r"Valid credentials|public.*valid", re.IGNORECASE),
    # Zerologon
    "Zerologon": re.compile(r"VULNERABLE|password.*reset", re.IGNORECASE),
}

# Technique-specific failure signals for more accurate failure detection
_TECHNIQUE_FAILURES: dict[str, re.Pattern[str]] = {
    "ESC1": re.compile(r"template.*not found|enrollment.*denied|Access is denied", re.IGNORECASE),
    "ESC8": re.compile(r"connection.*refused|HTTP.*401|HTTP.*403", re.IGNORECASE),
    "PKINIT-auth": re.compile(r"invalid certificate|cert.*expired|KDC_ERR", re.IGNORECASE),
    "DCSync": re.compile(r"access.*denied|replication.*failed|ERROR", re.IGNORECASE),
    "Coercion": re.compile(r"STATUS_ACCESS_DENIED|not vulnerable|blocked", re.IGNORECASE),
    "RBCD": re.compile(r"access.*denied|insufficient.*rights", re.IGNORECASE),
    "Shadow-Credentials": re.compile(r"access.*denied|insufficient.*rights", re.IGNORECASE),
    "Kerberoast": re.compile(r"KDC_ERR|no.*SPN|not found", re.IGNORECASE),
    "AS-REP-roast": re.compile(r"KDC_ERR|preauth.*required|not found", re.IGNORECASE),
    "Pre2k": re.compile(r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED_OUT", re.IGNORECASE),
    "Zerologon": re.compile(r"not vulnerable|failed|error", re.IGNORECASE),
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

    # Check technique-specific success signal first
    signal = _TECHNIQUE_SIGNALS.get(technique)
    if signal is not None and signal.search(output):
        return Outcome(
            success=True,
            capability=grants,
            detail=f"{technique} succeeded (matched success signal)",
            loot=loot,
        )

    # Check technique-specific failure signal
    failure_signal = _TECHNIQUE_FAILURES.get(technique)
    if failure_signal is not None and failure_signal.search(output):
        return Outcome(
            success=False,
            capability=None,
            detail=f"{technique}: output shows technique-specific failure signal",
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
