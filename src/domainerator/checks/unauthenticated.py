"""Unauthenticated checks - no valid credentials required.

These checks probe a target the way an attacker with no foothold would:

* SMB protocol / signing posture
* NULL session and anonymous share enumeration
* Anonymous RID cycling / user enumeration
* LDAP anonymous bind
* Kerberos pre-auth (AS-REP roastable accounts) when a userlist is known

All commands are built as argument lists and executed via ``ToolRunner`` so no
untrusted value ever touches a shell.
"""

from __future__ import annotations

import re

from ..paths import Capability, Noise, PathStep, Reliability
from ..runner import CheckResult, Finding, Severity, Target, ToolRunner
from . import require_tool

CATEGORY = "unauthenticated"


def check_smb_signing(runner: ToolRunner, target: Target, timeout: int = 120) -> CheckResult:
    """Detect SMB signing status. Signing not required enables NTLM relay."""
    name = "SMB signing posture"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = ["nxc", "smb", target.host, "-u", "", "-p", ""]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # netexec prints "signing:True" / "signing:False" on the banner line.
    m = re.search(r"signing:\s*(True|False)", text, re.IGNORECASE)
    if m:
        signing = m.group(1).lower() == "true"
        if not signing:
            result.add_finding(
                Finding(
                    title="SMB signing not required",
                    severity=Severity.HIGH,
                    target=target.host,
                    description=(
                        "The host does not require SMB signing. Combined with "
                        "captured NTLM authentication this allows SMB relay "
                        "attacks (e.g. ntlmrelayx) to authenticate as other users."
                    ),
                    evidence=m.group(0),
                    remediation=(
                        "Enforce SMB signing via Group Policy: 'Microsoft network "
                        "server: Digitally sign communications (always)'."
                    ),
                )
            )
            # This host is a viable NTLM relay target.
            result.add_step(
                PathStep(
                    name="SMB signing disabled -> relay target",
                    technique="NTLM-relay-target",
                    requires=frozenset({Capability.UNAUTHENTICATED}),
                    grants=Capability.RELAY_TARGET,
                    command=(
                        f"# {target.host} accepts unsigned SMB; usable as an "
                        "ntlmrelayx target once auth is coerced"
                    ),
                    description=(
                        "Host does not enforce SMB signing, so captured/coerced "
                        "NTLM can be relayed to it."
                    ),
                    reliability=Reliability.HIGH,
                    noise=Noise.MODERATE,
                    detail=target.host,
                    source="check",
                )
            )
        else:
            result.add_finding(
                Finding(
                    title="SMB signing required",
                    severity=Severity.INFO,
                    target=target.host,
                    description="SMB signing is enforced on this host.",
                    evidence=m.group(0),
                )
            )

    # Flag SMBv1 if the banner advertises it.
    if re.search(r"SMBv1:\s*True", text, re.IGNORECASE):
        result.add_finding(
            Finding(
                title="SMBv1 enabled",
                severity=Severity.MEDIUM,
                target=target.host,
                description="Legacy SMBv1 is enabled and is vulnerable to a range "
                "of exploits (e.g. EternalBlue).",
                evidence="SMBv1:True",
                remediation="Disable the SMBv1 feature on all hosts.",
            )
        )
    return result


def check_null_session(runner: ToolRunner, target: Target, timeout: int = 120) -> CheckResult:
    """Attempt an anonymous/NULL session and enumerate shares."""
    name = "SMB NULL session & share enumeration"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = ["nxc", "smb", target.host, "-u", "", "-p", "", "--shares"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # If shares are listed under a null session that's notable.
    if re.search(r"\bREAD\b|\bWRITE\b", text) and "shares" not in text.lower()[:0]:
        # Heuristic: presence of READ/WRITE permission tokens implies shares
        # were enumerated anonymously.
        readable = re.findall(r"^\s*(\S+)\s+READ", text, re.MULTILINE)
        result.add_finding(
            Finding(
                title="Anonymous SMB share enumeration possible",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    "A NULL/anonymous SMB session was able to enumerate shares. "
                    "This can leak the share layout and sometimes readable data."
                ),
                evidence="\n".join(readable[:20]) or text[:500],
                remediation=(
                    "Restrict anonymous access: set 'RestrictAnonymous' and "
                    "'RestrictNullSessAccess', and review share permissions."
                ),
            )
        )
    return result


def check_rid_cycling(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Attempt anonymous RID cycling to enumerate domain users."""
    name = "Anonymous RID cycling (user enumeration)"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = ["nxc", "smb", target.host, "-u", "", "-p", "", "--rid-brute"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    users = re.findall(r"SidTypeUser\s+(\S+\\\S+)", out.combined)
    if users:
        result.add_finding(
            Finding(
                title="Domain users enumerable via anonymous RID cycling",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    f"Enumerated {len(users)} domain principals without "
                    "authentication via RID cycling. This provides a userlist "
                    "for password spraying and AS-REP roasting."
                ),
                evidence="\n".join(users[:30]),
                remediation=(
                    "Restrict anonymous enumeration (RestrictAnonymous=1) and "
                    "monitor for SAMR enumeration."
                ),
            )
        )
        # Anonymous enumeration yields a userlist that feeds later steps.
        result.add_step(
            PathStep(
                name="Anonymous RID cycling -> userlist",
                technique="RID-cycling",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.USER_LIST,
                command=(
                    f"nxc smb {target.host} -u '' -p '' --rid-brute "
                    "| grep SidTypeUser"
                ),
                description="Enumerate a domain userlist without credentials.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=f"{len(users)} principals",
                source="check",
            )
        )
        # A userlist enables an (unauthenticated) password spray attempt.
        result.add_step(
            PathStep(
                name="Password spray with enumerated userlist",
                technique="Password-spray",
                requires=frozenset({Capability.USER_LIST}),
                grants=Capability.VALID_CREDENTIALS,
                command=(
                    f"nxc smb {target.host} -u users.txt -p 'Season2025!' "
                    "--continue-on-success  # tune to lockout policy"
                ),
                description=(
                    "Spray a likely password across enumerated users. Depends on "
                    "weak passwords and lockout policy; run carefully."
                ),
                reliability=Reliability.SPECULATIVE,
                noise=Noise.LOUD,
                source="check",
            )
        )
    return result


def check_ldap_anonymous_bind(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Test for anonymous LDAP bind that leaks naming context info."""
    name = "LDAP anonymous bind"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = ["nxc", "ldap", target.host, "-u", "", "-p", ""]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    # A successful anonymous bind typically shows a [+] with the domain.
    if re.search(r"\[\+\]", out.combined):
        result.add_finding(
            Finding(
                title="LDAP anonymous bind allowed",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    "The domain controller permitted an anonymous LDAP bind, "
                    "which can disclose directory information."
                ),
                evidence=out.combined[:500],
                remediation=(
                    "Set the DC's 'dsHeuristics' to deny anonymous LDAP "
                    "operations and require signing/channel binding."
                ),
            )
        )
    return result


def check_asrep_roast(
    runner: ToolRunner, target: Target, userlist: str | None, timeout: int = 300
) -> CheckResult:
    """AS-REP roast: find accounts with Kerberos pre-auth disabled.

    Requires a userlist since we have no credentials. If none is supplied the
    check is skipped.
    """
    name = "AS-REP roasting (pre-auth not required)"
    skip = require_tool(runner, "GetNPUsers.py", name, CATEGORY)
    if skip:
        # impacket may install the script without the .py suffix too.
        skip2 = require_tool(runner, "impacket-GetNPUsers", name, CATEGORY)
        if skip2:
            return skip2
        tool = "impacket-GetNPUsers"
    else:
        tool = "GetNPUsers.py"

    if not target.domain:
        from . import skipped_result

        return skipped_result(name, CATEGORY, "no domain supplied")
    if not userlist:
        from . import skipped_result

        return skipped_result(
            name, CATEGORY, "no userlist supplied (use --userlist for unauthenticated AS-REP roast)"
        )

    result = CheckResult(name=name, category=CATEGORY)
    argv = [
        tool,
        f"{target.domain}/",
        "-usersfile",
        userlist,
        "-no-pass",
        "-format",
        "hashcat",
    ]
    if target.dc_ip:
        argv += ["-dc-ip", target.dc_ip]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    hashes = re.findall(r"\$krb5asrep\$\S+", out.combined)
    if hashes:
        result.add_finding(
            Finding(
                title="AS-REP roastable accounts found",
                severity=Severity.HIGH,
                target=target.domain,
                description=(
                    f"{len(hashes)} account(s) do not require Kerberos "
                    "pre-authentication. Their AS-REP hashes can be cracked "
                    "offline to recover plaintext passwords."
                ),
                evidence="\n".join(h[:80] + "..." for h in hashes[:10]),
                remediation=(
                    "Enable 'Do not require Kerberos preauthentication' only "
                    "where strictly necessary and enforce strong passwords."
                ),
            )
        )
        # AS-REP hash -> crack -> valid credentials.
        result.add_step(
            PathStep(
                name="AS-REP roast (no pre-auth) -> hash",
                technique="AS-REP-roast",
                requires=frozenset({Capability.USER_LIST}),
                grants=Capability.ASREP_HASH,
                command=(
                    f"{tool} {target.domain}/ -usersfile users.txt -no-pass "
                    "-format hashcat"
                ),
                description="Obtain AS-REP hashes for pre-auth-disabled accounts.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                source="check",
            )
        )
        result.add_step(
            PathStep(
                name="Crack AS-REP hash -> credentials",
                technique="Hash-crack",
                requires=frozenset({Capability.ASREP_HASH}),
                grants=Capability.VALID_CREDENTIALS,
                command="hashcat -m 18200 asrep.hash wordlist.txt",
                description="Crack the AS-REP hash offline to recover a password.",
                reliability=Reliability.SPECULATIVE,
                noise=Noise.QUIET,
                source="check",
            )
        )
    return result


def run_all(
    runner: ToolRunner,
    target: Target,
    timeout: int = 300,
    userlist: str | None = None,
) -> list[CheckResult]:
    """Run every unauthenticated check and return the results."""
    return [
        check_smb_signing(runner, target, timeout=min(timeout, 120)),
        check_null_session(runner, target, timeout=min(timeout, 120)),
        check_rid_cycling(runner, target, timeout=min(timeout, 180)),
        check_ldap_anonymous_bind(runner, target, timeout=min(timeout, 120)),
        check_asrep_roast(runner, target, userlist, timeout=timeout),
    ]
