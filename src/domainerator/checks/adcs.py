"""AD CS (Active Directory Certificate Services) checks.

These checks locate Certificate Authorities and identify vulnerable
certificate templates (the ESC1-ESC8 family) using Certipy. Certipy's
``find`` command already classifies vulnerabilities, so we parse its output
(text and/or JSON) and translate each ESC label into a Domainerator finding
with severity and remediation guidance.

AD CS enumeration generally requires *some* authentication, so these checks
are skipped when no credentials are available. A CA that is web-enrollment
exposed (ESC8) can sometimes be probed with weak/relay auth, which is noted in
the remediation guidance rather than actively exploited here.
"""

from __future__ import annotations

import json
import re

from ..paths import Capability, Noise, PathStep, Reliability
from ..runner import CheckResult, Finding, Severity, Target, ToolRunner
from . import require_tool, skipped_result

CATEGORY = "adcs"

# ESC techniques that yield a certificate usable to authenticate as a
# privileged principal, and the capability they grant. Used to emit path steps.
ESC_PATH_GRANTS: dict[str, Capability] = {
    "ESC1": Capability.CERT_AS_DA,   # SAN injection -> request cert as DA
    "ESC2": Capability.CERT_AS_DA,
    "ESC3": Capability.CERT_AS_DA,
    "ESC4": Capability.CERT_AS_DA,   # rewrite template to vulnerable then ESC1
    "ESC6": Capability.CERT_AS_DA,   # CA-wide SAN injection
    "ESC8": Capability.CERT_AS_DA,   # relay to web enrollment -> DC cert
    "ESC9": Capability.CERT_AS_DA,   # no security ext -> cert mapping abuse
    "ESC10": Capability.CERT_AS_DA,  # weak cert mapping -> impersonation
    "ESC13": Capability.CERT_AS_DA,  # issuance policy linked to privileged group
    "ESC15": Capability.CERT_AS_DA,  # EKUwu / arbitrary application policies
    "ESC16": Capability.CERT_AS_DA,  # security-ext disabled CA-wide
}

# Map each ESC identifier to (severity, short human explanation, remediation).
ESC_INFO: dict[str, tuple[Severity, str, str]] = {
    "ESC1": (
        Severity.CRITICAL,
        "Template allows requester-supplied subject (SAN) with client auth EKU, "
        "enabling any enrollee to impersonate any user including domain admins.",
        "Remove 'Supply in the request' for the subject, or restrict enrollment "
        "and require manager approval.",
    ),
    "ESC2": (
        Severity.CRITICAL,
        "Template has the Any Purpose EKU (or no EKU), usable for authentication "
        "and impersonation.",
        "Restrict EKUs to only what is required; avoid Any Purpose.",
    ),
    "ESC3": (
        Severity.HIGH,
        "Enrollment Agent template allows requesting certs on behalf of other "
        "users.",
        "Restrict enrollment-agent enrollment and enable certificate manager "
        "approval.",
    ),
    "ESC4": (
        Severity.CRITICAL,
        "Overly permissive template ACLs allow low-privileged users to modify "
        "the template into a vulnerable state.",
        "Tighten template DACLs so only trusted admins can write to templates.",
    ),
    "ESC5": (
        Severity.HIGH,
        "Vulnerable PKI object access control (CA server / objects) allows "
        "escalation.",
        "Review and restrict ACLs on the CA and related AD objects.",
    ),
    "ESC6": (
        Severity.CRITICAL,
        "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled, allowing SAN injection "
        "in any request.",
        "Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA and restart "
        "certsvc.",
    ),
    "ESC7": (
        Severity.HIGH,
        "Dangerous CA permissions (ManageCA / ManageCertificates) held by "
        "non-admins.",
        "Remove ManageCA/ManageCertificates rights from untrusted principals.",
    ),
    "ESC8": (
        Severity.CRITICAL,
        "HTTP-based certificate enrollment (Web Enrollment) is enabled, allowing "
        "NTLM relay to the CA to obtain certificates.",
        "Disable HTTP enrollment or enforce HTTPS with Extended Protection for "
        "Authentication (channel binding).",
    ),
    "ESC9": (
        Severity.HIGH,
        "Template lacks the szOID_NTDS_CA_SECURITY_EXT security extension, "
        "enabling certificate mapping abuse.",
        "Ensure StrongCertificateBindingEnforcement and the security extension "
        "are configured.",
    ),
    "ESC10": (
        Severity.HIGH,
        "Weak certificate mapping configuration on the DC enables impersonation.",
        "Configure strong certificate mapping (KB5014754) and enforcement mode.",
    ),
    "ESC11": (
        Severity.HIGH,
        "IF_ENFORCEENCRYPTICERTREQUEST not enforced, enabling RPC relay to the "
        "CA.",
        "Enable encryption enforcement for ICertPassage RPC requests.",
    ),
    "ESC13": (
        Severity.HIGH,
        "Template has an issuance policy linked (OID group link) to a "
        "privileged group; enrolling grants that group's rights.",
        "Remove group links from issuance policies or restrict enrollment on "
        "affected templates.",
    ),
    "ESC15": (
        Severity.CRITICAL,
        "Schema V1 template allows attacker-supplied application policies "
        "(EKUwu / CVE-2024-49019), enabling client-auth or enrollment-agent "
        "abuse to impersonate privileged users.",
        "Patch the CA (CVE-2024-49019), remove 'Supply in the request', and "
        "retire V1 templates.",
    ),
    "ESC16": (
        Severity.CRITICAL,
        "The CA disables the szOID_NTDS_CA_SECURITY_EXT security extension "
        "for all requests, enabling certificate-mapping impersonation "
        "domain-wide.",
        "Re-enable the security extension on the CA and enforce strong "
        "certificate binding (KB5014754).",
    ),
}


def _make_finding_for_esc(esc: str, target: str, evidence: str) -> Finding:
    severity, description, remediation = ESC_INFO.get(
        esc,
        (
            Severity.HIGH,
            f"Certipy flagged {esc}, a known AD CS misconfiguration.",
            "Review the affected certificate template / CA configuration.",
        ),
    )
    return Finding(
        title=f"AD CS vulnerability: {esc}",
        severity=severity,
        target=target,
        description=description,
        evidence=evidence[:1000],
        remediation=remediation,
    )


def _parse_certipy_json(data: dict, target: str) -> list[Finding]:
    """Extract ESC findings from Certipy's JSON structure.

    Certipy JSON nests vulnerabilities under each template as a dict keyed by
    ESC id, e.g. {"Certificate Templates": {"0": {"Template Name": ...,
    "[!] Vulnerabilities": {"ESC1": "..."}}}}. We walk the structure defensively
    since the exact schema varies between Certipy versions.
    """
    findings: list[Finding] = []

    def walk(node, template_hint: str = "") -> None:
        if isinstance(node, dict):
            name_hint = node.get("Template Name") or node.get("CA Name") or template_hint
            for key, value in node.items():
                if isinstance(key, str) and "vulnerab" in key.lower() and isinstance(value, dict):
                    for esc_key, esc_desc in value.items():
                        esc_id = _normalize_esc(esc_key)
                        if esc_id:
                            evidence = f"{name_hint}: {esc_desc}" if name_hint else str(esc_desc)
                            findings.append(_make_finding_for_esc(esc_id, name_hint or target, evidence))
                else:
                    walk(value, name_hint)
        elif isinstance(node, list):
            for item in node:
                walk(item, template_hint)

    walk(data)
    return findings


def _normalize_esc(text: str) -> str | None:
    m = re.search(r"ESC\s*([0-9]{1,2})", text, re.IGNORECASE)
    if m:
        return f"ESC{m.group(1)}"
    return None


def _parse_certipy_text(text: str, target: str) -> list[Finding]:
    """Fallback parser: scan plain text output for ESC labels."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in text.splitlines():
        esc_id = _normalize_esc(line)
        if esc_id and esc_id not in seen:
            seen.add(esc_id)
            findings.append(_make_finding_for_esc(esc_id, target, line.strip()))
    return findings


def _add_esc_steps(result: CheckResult, esc: str, target: Target) -> None:
    """Attach attack-path steps for an exploitable ESC technique.

    Each vulnerable template/CA generally lets a low-privileged authenticated
    user obtain a certificate authenticating as a privileged principal, which
    then authenticates via PKINIT to recover a TGT / NT hash (potent enough to
    reach DCSync / Domain Admin).
    """
    grant = ESC_PATH_GRANTS[esc]
    domain = target.domain or "DOMAIN"
    upn = f"{target.username or 'USER'}@{domain}"

    # ESC8 is a relay path and needs a coercible/relayable auth, not just creds.
    if esc == "ESC8":
        requires = frozenset({Capability.RELAY_TARGET, Capability.COERCIBLE_AUTH})
        request_cmd = (
            "ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support "
            "--adcs --template DomainController"
        )
        reliability = Reliability.MODERATE
        noise = Noise.LOUD
        desc = (
            "Relay coerced DC authentication to the AD CS web-enrollment "
            "endpoint to obtain a DC certificate."
        )
    else:
        requires = frozenset({Capability.LOW_PRIV_USER})
        request_cmd = (
            f"certipy req -u {upn} -p PASS -ca CA-NAME "
            f"-template VULN-TEMPLATE -upn administrator@{domain}"
            + (f" -dc-ip {target.dc_ip}" if target.dc_ip else "")
        )
        reliability = Reliability.HIGH
        noise = Noise.MODERATE
        desc = (
            f"{esc}: request a certificate specifying a privileged UPN (SAN), "
            "yielding a certificate that authenticates as that principal."
        )

    result.add_step(
        PathStep(
            name=f"{esc}: request privileged certificate",
            technique=esc,
            requires=requires,
            grants=grant,
            command=request_cmd,
            description=desc,
            reliability=reliability,
            noise=noise,
            source="check",
        )
    )
    # Certificate -> authenticate (PKINIT) -> TGT/NT hash -> DCSync.
    result.add_step(
        PathStep(
            name=f"{esc}: authenticate with certificate (PKINIT)",
            technique="PKINIT-auth",
            requires=frozenset({grant}),
            grants=Capability.DCSYNC,
            command=(
                "certipy auth -pfx administrator.pfx -dc-ip "
                f"{target.dc_ip or 'DC-IP'}"
            ),
            description=(
                "Authenticate with the obtained certificate to recover the "
                "target's TGT / NT hash, enabling DCSync and Domain Admin."
            ),
            reliability=Reliability.HIGH,
            noise=Noise.MODERATE,
            source="check",
        )
    )


def check_adcs(runner: ToolRunner, target: Target, timeout: int = 300) -> CheckResult:
    """Run Certipy find and translate its output into findings."""
    name = "AD CS certificate template audit (ESC1-ESC11)"

    if not target.authenticated:
        return skipped_result(name, CATEGORY, "no credentials supplied (AD CS enumeration needs auth)")
    skip = require_tool(runner, "certipy", name, CATEGORY)
    if skip:
        # certipy may be installed as 'certipy-ad'.
        alt = require_tool(runner, "certipy-ad", name, CATEGORY)
        if alt:
            return alt
        tool = "certipy-ad"
    else:
        tool = "certipy"

    result = CheckResult(name=name, category=CATEGORY)

    argv = [
        tool,
        "find",
        "-u",
        f"{target.username}@{target.domain}" if target.domain else (target.username or ""),
        "-vulnerable",
        "-stdout",
    ]
    if target.nthash:
        argv += ["-hashes", target.nthash]
    elif target.password:
        argv += ["-p", target.password]
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

    findings: list[Finding] = []
    # Try JSON first (in case -stdout emitted structured data), then text.
    parsed_json = None
    stripped = out.stdout.strip()
    if stripped.startswith("{"):
        try:
            parsed_json = json.loads(stripped)
        except json.JSONDecodeError:
            parsed_json = None

    ca_target = target.domain or target.host
    if parsed_json is not None:
        findings = _parse_certipy_json(parsed_json, ca_target)
    if not findings:
        findings = _parse_certipy_text(out.combined, ca_target)

    if findings:
        # De-duplicate by (title, target).
        unique: dict[tuple[str, str | None], Finding] = {}
        for f in findings:
            unique[(f.title, f.target)] = f
        for f in unique.values():
            result.add_finding(f)

        # Emit attack-path steps for exploitable ESC techniques.
        emitted: set[str] = set()
        for f in unique.values():
            esc = _normalize_esc(f.title)
            if not esc or esc in emitted or esc not in ESC_PATH_GRANTS:
                continue
            emitted.add(esc)
            _add_esc_steps(result, esc, target)
    else:
        # Record that a CA was searched but nothing vulnerable was found.
        if re.search(r"Certificate Authorit", out.combined, re.IGNORECASE):
            result.add_finding(
                Finding(
                    title="AD CS present, no vulnerable templates detected",
                    severity=Severity.INFO,
                    target=ca_target,
                    description="Certipy located a CA but flagged no vulnerable templates.",
                    evidence=out.combined[:500],
                )
            )
    return result


def run_all(runner: ToolRunner, target: Target, timeout: int = 300) -> list[CheckResult]:
    return [check_adcs(runner, target, timeout=timeout)]
