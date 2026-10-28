"""Unauthenticated checks - no valid credentials required.

These checks probe a target the way an attacker with no foothold would:

* SMB protocol / signing posture
* NULL session and anonymous share enumeration
* Anonymous RID cycling / user enumeration
* LDAP anonymous bind
* LDAP signing / channel-binding exposure (cross-protocol relay target)
* WebDAV / WebClient service discovery (HTTP coercion source)
* NTLMv1 acceptance (crackable / downgradable authentication)
* NTLM reflection exposure (coerced auth relayable back to the same host)
* Kerberos pre-auth (AS-REP roastable accounts) when a userlist is known
* "Big win" network footholds that often yield reusable credentials without
  any domain context: Cisco Smart Install, MS17-010 (EternalBlue), anonymous
  FTP / NFS exports, and SNMP default community strings

All commands are built as argument lists and executed via ``ToolRunner`` so no
untrusted value ever touches a shell.
"""

from __future__ import annotations

import re

from ..paths import Capability, Noise, PathStep, Reliability
from ..runner import CheckResult, Finding, Severity, Target, ToolRunner
from . import looks_like_failure, require_tool

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
    if not m:
        result.mark_inconclusive(
            "could not find SMB 'signing:' status in tool output (host "
            "unreachable or output format changed)"
        )
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
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"no shares enumerated but output shows '{signal}' - NULL session "
                "may have been refused rather than truly restricted"
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

    # NetExec prints e.g. "1104: CORP\jsmith (SidTypeUser)" - the domain\user
    # precedes the "(SidTypeUser)" tag.
    users = re.findall(r"(\S+\\[^\s(]+)\s*\(SidTypeUser\)", out.combined)
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
    else:
        signal = looks_like_failure(out.combined)
        if signal:
            result.mark_inconclusive(
                f"no users enumerated but output shows '{signal}' - RID cycling "
                "may have been blocked rather than unavailable"
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
    else:
        signal = looks_like_failure(out.combined)
        if signal:
            result.mark_inconclusive(
                f"anonymous bind not confirmed and output shows '{signal}'"
            )
    return result


def check_ldap_relay_exposure(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Check whether the DC's LDAP is a viable cross-protocol relay target.

    LDAP signing not enforced and/or LDAPS channel binding not required means
    coerced HTTP authentication (e.g. from a WebClient host) can be relayed to
    LDAP(S) to write RBCD or shadow credentials. NetExec's ``ldap-checks``
    module reports these settings.
    """
    name = "LDAP signing / channel-binding (relay exposure)"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    if target.authenticated:
        auth = target.nxc_auth_args()
    else:
        auth = ["-u", "", "-p", ""]
    argv = ["nxc", "ldap", target.host, *auth, "-M", "ldap-checks"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # ldap-checks reports lines like "LDAP Signing NOT Enforced" and
    # "LDAPS Channel Binding is NOT set to Required".
    signing_off = re.search(r"LDAP Signing\s+NOT\s+Enforced", text, re.IGNORECASE)
    cb_off = re.search(r"Channel Binding.*NOT.*Require", text, re.IGNORECASE)
    if signing_off or cb_off:
        result.add_finding(
            Finding(
                title="LDAP relay protections not fully enforced",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "The DC does not fully enforce LDAP signing / LDAPS channel "
                    "binding. Coerced NTLM authentication can be relayed to "
                    "LDAP(S) to configure RBCD or add shadow credentials."
                ),
                evidence=text[:600],
                remediation=(
                    "Enforce LDAP signing (require) and LDAPS channel binding "
                    "(Extended Protection for Authentication) on all DCs."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="DC LDAP is a relay target",
                technique="LDAP-relay-target",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.LDAP_RELAY_TARGET,
                command=(
                    f"nxc ldap {target.host} -u USER -p PASS -M ldap-checks  "
                    "# signing/channel-binding not enforced"
                ),
                description=(
                    "DC LDAP lacks signing/channel-binding enforcement, so "
                    "coerced auth can be relayed to it."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    else:
        # ldap-checks explicitly reports enforcement; only inconclusive if the
        # module output doesn't mention signing/channel-binding at all.
        if not re.search(r"signing|channel binding", text, re.IGNORECASE):
            result.mark_inconclusive(
                "ldap-checks output did not report signing/channel-binding "
                "status (module unavailable or output changed)"
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


def check_webdav(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Discover hosts running the WebClient (WebDAV) service.

    A running WebClient service means the host can be coerced to authenticate
    over HTTP. Unlike SMB, HTTP authentication can be relayed cross-protocol to
    LDAP(S) on a DC that lacks channel binding, enabling RBCD or shadow-
    credential attacks. This check uses NetExec's ``webdav`` module.

    It runs with whatever credentials are available (a null session works in
    some environments; supplied creds are used when present), so it is useful
    both unauthenticated and authenticated.
    """
    name = "WebDAV / WebClient service discovery"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    # Use supplied creds when available, else a null session.
    if target.authenticated:
        auth = target.nxc_auth_args()
    else:
        auth = ["-u", "", "-p", ""]
    argv = ["nxc", "smb", target.host, *auth, "-M", "webdav"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # The webdav module reports when the WebClient service is running, e.g.
    # "WEBDAV ... WebClient Service enabled on: <host>".
    enabled = re.search(r"WebClient Service enabled", text, re.IGNORECASE) or re.search(
        r"\bWEBDAV\b.*enabled", text, re.IGNORECASE
    )
    if enabled:
        result.add_finding(
            Finding(
                title="WebClient (WebDAV) service enabled",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "The WebClient service is running on this host. It can be "
                    "coerced to authenticate over HTTP, which is relayable to "
                    "LDAP(S) (unlike SMB auth) to configure RBCD or add shadow "
                    "credentials, leading to host/user takeover."
                ),
                evidence=text[:600],
                remediation=(
                    "Disable the WebClient service where not required, enforce "
                    "LDAP channel binding and signing on DCs, and enable EPA."
                ),
            )
        )
        # This host is a WebDAV/HTTP coercion source for cross-protocol relay.
        result.add_step(
            PathStep(
                name="WebClient host enables HTTP coercion",
                technique="WebDAV-host",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.WEBDAV_HOST,
                command=(
                    f"nxc smb {target.host} -u USER -p PASS -M webdav  "
                    "# WebClient running -> HTTP-coercible"
                ),
                description=(
                    "Host runs WebClient; usable as an HTTP coercion source for "
                    "relay to LDAP."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    else:
        if not re.search(r"webdav|webclient", text, re.IGNORECASE):
            result.mark_inconclusive(
                "webdav module produced no WebClient status (module unavailable "
                "or output changed)"
            )
    return result


def check_ntlmv1(runner: ToolRunner, target: Target, timeout: int = 120) -> CheckResult:
    """Detect whether the host accepts legacy NTLMv1 authentication.

    NTLMv1 responses are DES-based and crackable (e.g. via crack.sh / hashcat
    -m 5500) to recover the NT hash, and are downgrade/relay-friendly. NetExec's
    ``ntlmv1`` module reports the host's LmCompatibilityLevel posture.
    """
    name = "NTLMv1 authentication accepted"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    auth = target.nxc_auth_args() if target.authenticated else ["-u", "", "-p", ""]
    argv = ["nxc", "smb", target.host, *auth, "-M", "ntlmv1"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # The ntlmv1 module reports e.g. "NTLMv1 allowed / enabled" when vulnerable.
    if re.search(r"NTLMv1.*(allow|enabl|vulnerab)", text, re.IGNORECASE) or re.search(
        r"LmCompatibilityLevel.*(0|1|2)\b", text, re.IGNORECASE
    ):
        result.add_finding(
            Finding(
                title="NTLMv1 authentication accepted",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "The host permits NTLMv1. NTLMv1 net-NTLM responses are "
                    "DES-based and can be cracked offline to recover the NT "
                    "hash, and are easier to downgrade/relay."
                ),
                evidence=text[:600],
                remediation=(
                    "Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse "
                    "LM & NTLM) via Group Policy on all hosts."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Host accepts NTLMv1",
                technique="NTLMv1",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.NTLMV1_HOST,
                command=f"nxc smb {target.host} -u '' -p '' -M ntlmv1",
                description=(
                    "Host negotiates NTLMv1; a coerced response can be cracked "
                    "to the NT hash."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    else:
        if not re.search(r"ntlmv1|lmcompatibility", text, re.IGNORECASE):
            result.mark_inconclusive(
                "ntlmv1 module produced no NTLMv1/LmCompatibilityLevel status "
                "(module unavailable or output changed)"
            )
    return result


def check_ntlm_reflection(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Detect NTLM reflection exposure (coerced auth relayable to the same host).

    When a host is vulnerable to NTLM reflection, coerced authentication can be
    relayed back to the originating host to execute as it (local admin). NetExec
    exposes this via its reflection module. Names/output vary across versions,
    so parsing is deliberately tolerant.
    """
    name = "NTLM reflection exposure"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    auth = target.nxc_auth_args() if target.authenticated else ["-u", "", "-p", ""]
    argv = ["nxc", "smb", target.host, *auth, "-M", "ntlm_reflection"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    if re.search(r"reflection.*(vulnerab|possible|allow)", text, re.IGNORECASE) or re.search(
        r"\bVULNERABLE\b", text
    ):
        result.add_finding(
            Finding(
                title="Host vulnerable to NTLM reflection",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "Coerced authentication from this host can be relayed back "
                    "to itself (NTLM reflection), granting privileged local "
                    "access on the same host."
                ),
                evidence=text[:600],
                remediation=(
                    "Apply the relevant patches (e.g. CVE-2025-33073 and related "
                    "reflection fixes), enforce SMB signing, and restrict NTLM."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Host vulnerable to NTLM reflection",
                technique="NTLM-Reflection-target",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.SELF_RELAY_TARGET,
                command=f"nxc smb {target.host} -u '' -p '' -M ntlm_reflection",
                description="Host reflects coerced auth back to itself.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    else:
        if not re.search(r"reflection", text, re.IGNORECASE):
            result.mark_inconclusive(
                "ntlm_reflection module produced no reflection status (module "
                "unavailable or output changed)"
            )
    return result


def check_timeroast(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Timeroasting: recover crackable computer-account hashes via NTP.

    A DC's NTP service returns an authenticated response signed with the RID's
    computer-account NT hash. Requesting these for enumerated RIDs yields
    crackable machine-account hashes and needs **no domain credentials**, so
    this runs in the shared phase both unauthenticated and authenticated;
    supplied creds are used when present, otherwise a null session.
    """
    name = "Timeroasting (NTP computer-account hashes)"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    # Use supplied creds when available, else a null session.
    if target.authenticated:
        auth = target.nxc_auth_args()
    else:
        auth = ["-u", "", "-p", ""]
    # NetExec's timeroast module queries the DC's NTP and emits hashcat hashes.
    argv = ["nxc", "smb", target.host, *auth, "-M", "timeroast"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    # Timeroast hashes are emitted in the hashcat -m 31300 "$sntp-ms$" format.
    hashes = re.findall(r"\$sntp-ms\$\S+|\d+:\$sntp-ms\$\S+", text)
    if hashes or re.search(r"timeroast|sntp-ms", text, re.IGNORECASE):
        result.add_finding(
            Finding(
                title="Timeroastable computer-account hashes obtained",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    f"{len(hashes)} computer-account hash(es) were recovered via "
                    "NTP timeroasting. These crack offline; a weak machine "
                    "password yields the account's NT hash for further attacks."
                ),
                evidence="\n".join(h[:80] for h in hashes[:10]) or text[:600],
                remediation=(
                    "Timeroasting abuses legacy MS-SNTP authentication; restrict "
                    "NTP where feasible and ensure machine passwords rotate."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Timeroast -> computer-account hash",
                technique="Timeroast",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.CRACKABLE_HASH,
                command=f"nxc smb {target.host} -M timeroast",
                description="Recover crackable computer-account hashes via NTP.",
                reliability=Reliability.HIGH,
                noise=Noise.QUIET,
                source="check",
            )
        )
        result.add_step(
            PathStep(
                name="Crack timeroast hash -> credentials",
                technique="Hash-crack",
                requires=frozenset({Capability.CRACKABLE_HASH}),
                grants=Capability.VALID_CREDENTIALS,
                command="hashcat -m 31300 timeroast.hash wordlist.txt",
                description=(
                    "Crack the recovered computer-account hash offline; a weak "
                    "machine password yields usable credentials."
                ),
                reliability=Reliability.SPECULATIVE,
                noise=Noise.QUIET,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"timeroast inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"timeroast|sntp|ntp|no.*hash", text, re.IGNORECASE):
            result.mark_inconclusive(
                "timeroast module produced no recognizable output (module "
                "unavailable or output changed)"
            )
    return result


def check_cisco_smart_install(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Detect Cisco Smart Install (SMI) exposure on TCP 4786.

    An exposed, unauthenticated SMI service lets an attacker pull the device's
    running configuration, which routinely contains local/enable passwords,
    SNMP community strings, and TACACS keys - credentials that are frequently
    reused against the Windows/AD estate. This is a classic unauthenticated
    "big win" foothold with no domain context required.
    """
    name = "Cisco Smart Install exposure (TCP 4786)"
    skip = require_tool(runner, "nmap", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    # The vuln NSE script reports whether SMI is active/abusable.
    argv = ["nmap", "-Pn", "-p", "4786", "--script", "cisco-smart-install", target.host]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    open_port = re.search(r"4786/tcp\s+open", text, re.IGNORECASE)
    smi_active = re.search(r"Smart Install|SMI|is enabled|VULNERABLE", text, re.IGNORECASE)
    if open_port and smi_active:
        result.add_finding(
            Finding(
                title="Cisco Smart Install enabled and exposed",
                severity=Severity.HIGH,
                target=target.host,
                description=(
                    "Cisco Smart Install is reachable and unauthenticated on "
                    "TCP 4786. An attacker can download the device's running "
                    "configuration (and push a new one), exposing local/enable "
                    "passwords, SNMP communities, and TACACS keys that are "
                    "commonly reused against the domain."
                ),
                evidence=text[:600],
                remediation=(
                    "Disable Smart Install ('no vstack') where not required and "
                    "restrict TCP 4786 to management networks."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="Dump Cisco config via Smart Install -> credentials",
                technique="Cisco-SMI",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.NETWORK_FOOTHOLD,
                command=(
                    f"nmap -p4786 --script cisco-smart-install {target.host}  "
                    "# or: SIET.py -i "
                    f"{target.host} -g   (grab running-config; crack type7/type5 creds)"
                ),
                description=(
                    "Pull the switch/router running-config over Smart Install "
                    "and recover reusable credentials (type-7/type-5, SNMP, "
                    "TACACS)."
                ),
                reliability=Reliability.HIGH,
                noise=Noise.MODERATE,
                detail=target.host,
                source="check",
            )
        )
    else:
        if not open_port and not re.search(r"4786", text):
            result.mark_inconclusive(
                "could not determine Smart Install status on TCP 4786 (host "
                "unreachable, filtered, or nmap output changed)"
            )
    return result


def check_eternalblue(runner: ToolRunner, target: Target, timeout: int = 180) -> CheckResult:
    """Detect MS17-010 (EternalBlue) - unauthenticated SMB RCE.

    When present this is the single biggest unauthenticated win: remote code
    execution as SYSTEM, from which SAM/LSASS secrets (local admin and cached
    domain credentials) can be dumped. Detection only; exploitation is left to
    the operator.
    """
    name = "MS17-010 / EternalBlue (SMB RCE)"
    skip = require_tool(runner, "nxc", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = ["nxc", "smb", target.host, "-u", "", "-p", "", "-M", "ms17-010"]
    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
        return result

    text = out.combined
    vulnerable = re.search(r"MS17-010.*VULNERABLE|VULNERABLE.*MS17-010|likely vulnerable",
                           text, re.IGNORECASE)
    if vulnerable:
        result.add_finding(
            Finding(
                title="Host vulnerable to MS17-010 (EternalBlue)",
                severity=Severity.CRITICAL,
                target=target.host,
                description=(
                    "The host is vulnerable to MS17-010 (EternalBlue), an "
                    "unauthenticated SMB remote-code-execution flaw. Exploiting "
                    "it yields SYSTEM, from which SAM and LSASS secrets - local "
                    "admin hashes and cached domain credentials - can be dumped."
                ),
                evidence=text[:600],
                remediation=(
                    "Apply MS17-010 patches immediately and disable SMBv1."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="EternalBlue -> SYSTEM -> dump SAM/LSASS",
                technique="MS17-010",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.NETWORK_FOOTHOLD,
                command=(
                    f"# MS17-010 against {target.host} (e.g. metasploit "
                    "ms17_010_eternalblue) -> SYSTEM -> dump SAM/LSASS for "
                    "local-admin and cached domain creds"
                ),
                description=(
                    "Exploit EternalBlue for SYSTEM on the host, then dump "
                    "credentials for reuse against the domain."
                ),
                reliability=Reliability.MODERATE,
                noise=Noise.LOUD,
                detail=target.host,
                source="check",
            )
        )
    else:
        signal = looks_like_failure(text)
        if signal:
            result.mark_inconclusive(
                f"MS17-010 check inconclusive; output shows '{signal}'"
            )
        elif not re.search(r"ms17-010|not vulnerable", text, re.IGNORECASE):
            result.mark_inconclusive(
                "ms17-010 module produced no recognizable output (module "
                "unavailable or output changed)"
            )
    return result


def check_anonymous_ftp_nfs(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Detect anonymous FTP access and exported (world-readable) NFS shares.

    Both are low-effort, high-hit-rate sources of config files, backups, and
    answer files (unattend.xml, web.config) that embed reusable credentials.
    """
    name = "Anonymous FTP / NFS export exposure"
    skip = require_tool(runner, "nmap", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = [
        "nmap", "-Pn", "-p", "21,111,2049",
        "--script", "ftp-anon,nfs-showmount",
        target.host,
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
    ftp_anon = re.search(r"ftp-anon:.*Anonymous FTP login allowed", text, re.IGNORECASE)
    nfs_exports = re.search(r"nfs-showmount:", text, re.IGNORECASE) and re.search(
        r"/\S+", text
    )
    found = False
    if ftp_anon:
        found = True
        result.add_finding(
            Finding(
                title="Anonymous FTP login allowed",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    "The FTP service permits anonymous login. Anonymous shares "
                    "frequently hold backups, scripts, and config/answer files "
                    "that contain reusable credentials."
                ),
                evidence=text[:600],
                remediation="Disable anonymous FTP or restrict and audit its contents.",
            )
        )
    if nfs_exports:
        found = True
        result.add_finding(
            Finding(
                title="NFS exports reachable (showmount)",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    "The host exports NFS shares that can be enumerated without "
                    "authentication. Exported filesystems often contain home "
                    "directories, backups, and config files with credentials."
                ),
                evidence=text[:600],
                remediation=(
                    "Restrict NFS exports to specific hosts, drop no_root_squash, "
                    "and avoid exporting sensitive paths."
                ),
            )
        )
    if found:
        result.add_step(
            PathStep(
                name="Loot anonymous FTP / NFS -> credentials",
                technique="Anon-file-share",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.NETWORK_FOOTHOLD,
                command=(
                    f"# FTP: ftp {target.host} (anonymous)  |  "
                    f"NFS: showmount -e {target.host} then mount and grep for "
                    "passwords/keys in configs, backups, unattend.xml/web.config"
                ),
                description=(
                    "Harvest config files, backups, and answer files from "
                    "anonymous FTP or exported NFS shares for reusable creds."
                ),
                reliability=Reliability.SPECULATIVE,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    else:
        if not re.search(r"ftp-anon|nfs-showmount|21/tcp|2049/tcp", text, re.IGNORECASE):
            result.mark_inconclusive(
                "could not determine FTP/NFS exposure (ports filtered, host "
                "unreachable, or nmap output changed)"
            )
    return result


def check_snmp_default_community(
    runner: ToolRunner, target: Target, timeout: int = 120
) -> CheckResult:
    """Detect SNMP reachable with a default community string (public/private).

    SNMP v1/v2c with a guessable community leaks system inventory and, on
    network gear, sometimes configuration/credentials. A writable 'private'
    community can even push config. A useful unauthenticated info/credential
    foothold.
    """
    name = "SNMP default community string"
    skip = require_tool(runner, "nmap", name, CATEGORY)
    if skip:
        return skip

    result = CheckResult(name=name, category=CATEGORY)
    argv = [
        "nmap", "-Pn", "-sU", "-p", "161",
        "--script", "snmp-brute,snmp-info",
        target.host,
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
    # snmp-brute reports valid community strings; snmp-info confirms a response.
    # Use DOTALL so the brute header and the recovered community on the next
    # line are matched together.
    community = re.search(
        r"snmp-brute:.*?(public|private|Valid credentials)", text,
        re.IGNORECASE | re.DOTALL,
    )
    snmp_open = re.search(r"161/udp\s+open", text, re.IGNORECASE)
    if community or (snmp_open and re.search(r"snmp-info:", text, re.IGNORECASE)):
        result.add_finding(
            Finding(
                title="SNMP accessible with a default/guessable community",
                severity=Severity.MEDIUM,
                target=target.host,
                description=(
                    "SNMP responded to a default or brute-forced community "
                    "string. SNMP exposes system inventory and, on network "
                    "devices, can leak configuration and credentials; a writable "
                    "community permits configuration changes."
                ),
                evidence=text[:600],
                remediation=(
                    "Use SNMPv3 with authentication/privacy, remove default "
                    "communities, and restrict UDP 161 to management hosts."
                ),
            )
        )
        result.add_step(
            PathStep(
                name="SNMP community -> enumerate / recover credentials",
                technique="SNMP-default",
                requires=frozenset({Capability.UNAUTHENTICATED}),
                grants=Capability.NETWORK_FOOTHOLD,
                command=(
                    f"snmpwalk -v2c -c public {target.host}  "
                    "# enumerate; on network gear pull config/creds for reuse"
                ),
                description=(
                    "Walk SNMP with the recovered community to enumerate the "
                    "host and, on devices, recover reusable credentials."
                ),
                reliability=Reliability.MODERATE,
                noise=Noise.QUIET,
                detail=target.host,
                source="check",
            )
        )
    else:
        if not re.search(r"snmp|161/udp", text, re.IGNORECASE):
            result.mark_inconclusive(
                "could not determine SNMP exposure (UDP 161 filtered, host "
                "unreachable, or nmap output changed)"
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
        check_ldap_relay_exposure(runner, target, timeout=min(timeout, 120)),
        check_webdav(runner, target, timeout=min(timeout, 180)),
        check_ntlmv1(runner, target, timeout=min(timeout, 120)),
        check_ntlm_reflection(runner, target, timeout=min(timeout, 120)),
        check_asrep_roast(runner, target, userlist, timeout=timeout),
        check_timeroast(runner, target, timeout=min(timeout, 180)),
        check_cisco_smart_install(runner, target, timeout=min(timeout, 120)),
        check_eternalblue(runner, target, timeout=min(timeout, 180)),
        check_anonymous_ftp_nfs(runner, target, timeout=min(timeout, 120)),
        check_snmp_default_community(runner, target, timeout=min(timeout, 120)),
    ]
