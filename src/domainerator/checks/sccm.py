"""SCCM / MECM discovery and PXE Network Access Account (NAA) checks.

Microsoft Configuration Manager (SCCM/MECM) is a frequent, high-value path to
domain compromise. Two low-effort, high-signal items are covered here:

* **Management-point / site discovery** - SCCM publishes management points in
  AD (the ``mSSMSManagementPoint`` / ``mSSMSMPName`` objects and the System
  Management container). Finding these confirms an SCCM deployment and the
  hosts worth attacking.
* **PXE / NAA credential retrieval** - if PXE boot (OS deployment) is enabled
  and not password-protected, boot media can be requested and its embedded
  policy decrypted to recover the Network Access Account (NAA) credentials,
  which are ordinary domain credentials - a useful foothold.

These use NetExec's SCCM-related modules where available (module names and
output have shifted across versions, so parsing is tolerant). This module is
authenticated for LDAP discovery; PXE retrieval can work unauthenticated
against an open PXE responder.

Detection only: Domainerator reports what it finds and the operator commands to
recover credentials; it does not perform the PXE media decryption itself.
"""

from __future__ import annotations

import re

from ..paths import Capability, Noise, PathStep, Reliability
from ..runner import CheckResult, Finding, Severity, Target, ToolRunner
from . import looks_like_failure, require_tool, skipped_result

CATEGORY = "sccm"


def check_sccm_discovery(
    runner: ToolRunner, target: Target, timeout: int = 180
) -> CheckResult:
    """Discover SCCM management points / sites published in AD (authenticated)."""
    name = "SCCM management-point / site discovery"
    if not target.authenticated:
        return skipped_result(name, CATEGORY, "SCCM AD discovery requires credentials")
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    # NetExec's LDAP sccm module enumerates management points / site info.
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "-M", "sccm"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # Look for management-point hostnames / site codes in the output.
    mps = re.findall(r"(?:Management ?Point|mSSMSMPName)\D*([A-Za-z0-9._-]+)", text)
    site_codes = re.findall(r"Site ?Code\D*([A-Za-z0-9]{3})", text)
    if mps or site_codes or re.search(r"\bSCCM\b|System Management", text, re.IGNORECASE):
        evidence = text[:600]
        result.add_finding(
            Finding(
                title="SCCM deployment discovered",
                severity=Severity.MEDIUM,
                target=target.domain or target.host,
                description=(
                    "SCCM/MECM management point(s) or site information were "
                    "found in AD. SCCM is a common route to widespread code "
                    "execution and credential exposure (NAA, client push, "
                    "site takeover)."
                ),
                evidence=evidence,
                remediation=(
                    "Harden SCCM: enforce PKI/HTTPS, disable NTLM for site "
                    "systems, protect PXE with a strong password, and remove "
                    "Network Access Accounts where possible."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="SCCM management point discovered",
                technique="SCCM-discovery",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.SCCM_MANAGEMENT_POINT,
                command=f"nxc ldap {target.host} -u USER -p PASS -M sccm",
                description="An SCCM management point / site was found in AD.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=", ".join(sorted(set(mps)))[:200],
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"SCCM discovery inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"sccm|management point|site", text, re.IGNORECASE):
            result.mark_inconclusive(
                "sccm module produced no recognizable output (module unavailable "
                "or output changed)"
            )
    return result


def check_sccm_pxe_naa(
    runner: ToolRunner, target: Target, timeout: int = 240
) -> CheckResult:
    """Probe for PXE OS-deployment exposure and recoverable NAA credentials.

    A distribution point with PXE enabled and no (or weak) boot-media password
    lets an attacker request boot media and decrypt its policy to recover the
    Network Access Account credentials. Uses NetExec's PXE/SCCM module against
    the target distribution point.
    """
    name = "SCCM PXE / Network Access Account exposure"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    # PXE probing can work unauthenticated against an open PXE/DP responder.
    auth = target.nxc_auth_args() if target.authenticated else ["-u", "", "-p", ""]
    argv = ["nxc", "smb", target.host, *auth, "-M", "sccm", "-o", "PXE=True"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    pxe_open = re.search(r"PXE.*(enabled|no password|not.*password|open)", text, re.IGNORECASE)
    naa_found = re.search(r"Network Access Account|NAADomain|\bNAA\b", text, re.IGNORECASE)

    if naa_found:
        result.add_finding(
            Finding(
                title="SCCM Network Access Account credentials recoverable",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "SCCM PXE boot media / policy exposed Network Access Account "
                    "credentials. NAA accounts are valid domain credentials and "
                    "provide an immediate foothold."
                ),
                evidence=text[:600],
                remediation=(
                    "Set a strong PXE boot password, prefer 'enhanced HTTP' / "
                    "PKI, and stop using Network Access Accounts (use Enhanced "
                    "HTTP or client-token auth instead)."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Recover SCCM NAA credentials via PXE",
                technique="SCCM-PXE-NAA",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.SCCM_NAA_CREDS,
                command=(
                    "# request PXE boot media from the DP and decrypt the policy "
                    "to recover NAA creds (e.g. PXEThief / sccmhunter)"
                ),
                description="PXE media exposed recoverable NAA domain credentials.",
                reliability=Reliability.MODERATE,
                noise=Noise.MODERATE,
                detail=target.host,
                source="check",
            )
        )
    elif pxe_open:
        result.add_finding(
            Finding(
                title="SCCM PXE boot exposed (no/weak password)",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    "A PXE-enabled distribution point responded without a strong "
                    "boot password. Boot media may be retrievable and its policy "
                    "decrypted to recover Network Access Account credentials."
                ),
                evidence=text[:600],
                remediation="Require a strong PXE boot password or disable PXE.",
            )
        )
        result.add_step(
            PathStep(
                name="PXE distribution point exposed",
                technique="SCCM-PXE",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.SCCM_NAA_CREDS,
                command="# PXEThief / sccmhunter against the exposed PXE DP",
                description="PXE DP is retrievable; NAA recovery likely possible.",
                reliability=Reliability.SPECULATIVE,
                noise=Noise.MODERATE,
                detail=target.host,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(f"PXE probe inconclusive; output shows '{signal}'")
        elif not re.search(r"pxe|sccm|naa", text, re.IGNORECASE):
            result.mark_inconclusive(
                "PXE/SCCM probe produced no recognizable output (module "
                "unavailable or output changed)"
            )
    return result


def run_all(runner: ToolRunner, target: Target, timeout: int = 300) -> list[CheckResult]:
    """Run SCCM discovery and PXE/NAA checks."""
    return [
        check_sccm_discovery(runner, target, timeout=min(timeout, 180)),
        check_sccm_pxe_naa(runner, target, timeout=min(timeout, 240)),
    ]
