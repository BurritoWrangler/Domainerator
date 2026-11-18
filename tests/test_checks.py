"""Tests for check parsing logic (RBCD enumeration, WebDAV discovery).

These drive the checks through a fake ToolRunner that returns canned tool
output, so we exercise the parsing/finding/path-step logic without needing the
real external tools installed.
"""

from __future__ import annotations

from domainerator.checks import (
    FailureKind,
    authenticated,
    classify_failure,
    looks_like_failure,
    unauthenticated,
)
from domainerator.paths import Capability
from domainerator.runner import CommandOutput, Target

# Verbatim text from the reported SMBGhost false-positive: a null-session
# login that the target refused (STATUS_ACCESS_DENIED), not a connectivity
# failure.
SMBGHOST_BUG_FIXTURE = (
    "SMB                      10.40.0.13      445    PRIFS02          "
    "[*] Windows Server 2019 Datacenter 17763 x64 (name:PRIFS02) "
    "(domain:abcdomain.com) (signing:True) (SMBv1:True) (Null Auth:True)\n"
    "SMB                      10.40.0.13      445    PRIFS02          "
    "[-] abcdomain.com\\: STATUS_ACCESS_DENIED"
)


class FakeRunner:
    """A ToolRunner stand-in that returns a scripted CommandOutput."""

    def __init__(self, combined: str = "", error: str | None = None):
        self._combined = combined
        self._error = error
        self.dry_run = False

    def is_available(self, name: str) -> bool:  # all tools "present"
        return True

    def run(self, argv, timeout=None) -> CommandOutput:
        stdout = "" if self._error else self._combined
        return CommandOutput(
            command=" ".join(argv),
            return_code=0 if not self._error else None,
            stdout=stdout,
            stderr="",
            duration_seconds=0.0,
            error=self._error,
        )


AUTH_TARGET = Target(
    host="10.0.0.10", domain="corp.local", username="alice", password="pw", dc_ip="10.0.0.10"
)
ANON_TARGET = Target(host="10.0.0.10", domain="corp.local")


def test_rbcd_enum_detects_existing_and_emits_step():
    output = (
        "LDAP  10.0.0.10  msDS-AllowedToActOnBehalfOfOtherIdentity\n"
        "SRV01$   <binary-sd>\n"
        "SRV02$   <binary-sd>\n"
    )
    res = authenticated.check_rbcd(FakeRunner(output), AUTH_TARGET)
    # A finding for existing RBCD relationships.
    assert any("RBCD" in f.title for f in res.findings)
    # And a DACL_CONTROL + MACHINE_ACCOUNT -> RBCD path step.
    grants = {s.grants for s in res.path_steps}
    assert Capability.RBCD in grants


def test_rbcd_enum_skips_without_creds():
    res = authenticated.check_rbcd(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_webdav_detects_service_and_emits_step():
    output = "SMB  10.0.0.20  WEBDAV  WebClient Service enabled on: WS01"
    res = unauthenticated.check_webdav(FakeRunner(output), ANON_TARGET)
    assert any("WebClient" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.WEBDAV_HOST in grants


def test_webdav_quiet_when_not_present():
    res = unauthenticated.check_webdav(FakeRunner("SMB 10.0.0.20  nothing here"), ANON_TARGET)
    assert not res.findings
    assert not res.path_steps


def test_webdav_module_tag_plus_unrelated_enabled_word_is_not_a_finding():
    """Regression: nxc prefixes every line from this module with the
    protocol tag WEBDAV, so a bare '\\bWEBDAV\\b.*enabled' match could
    previously fire from the module's own tag plus an unrelated 'enabled'
    word on the same line, without the WebClient service actually being
    confirmed enabled."""
    output = "SMB  10.0.0.20  WEBDAV  module enabled, scanning for WebClient service"
    res = unauthenticated.check_webdav(FakeRunner(output), ANON_TARGET)
    assert not res.findings


def test_coercion_detects_and_emits_step():
    output = (
        "SMB  10.0.0.10  COERCE_PLUS  MS-EFSR (EfsRpcOpenFileRaw) VULNERABLE\n"
        "SMB  10.0.0.10  COERCE_PLUS  MS-RPRN spooler coerce possible\n"
    )
    res = authenticated.check_coercion(FakeRunner(output), AUTH_TARGET)
    assert any("coercible" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.COERCIBLE_AUTH in grants


def test_coercion_quiet_when_not_vulnerable():
    res = authenticated.check_coercion(FakeRunner("SMB 10.0.0.10  nothing"), AUTH_TARGET)
    assert not res.findings


def test_coercion_module_name_alone_is_not_a_finding():
    """Regression: 'coerc' is a substring of the coerce_plus module's own
    name, so a buffer-wide (not line-scoped) 'vulnerable|coerc' search could
    previously fire from the module merely describing itself, combined with
    an unrelated line elsewhere mentioning one of the protocol names, with
    neither on the same line as an actual VULNERABLE verdict."""
    output = (
        "SMB  10.0.0.10  COERCE_PLUS  Running coerce_plus module (coercion check)\n"
        "SMB  10.0.0.10  SMB  MS-RPRN spooler service detected (unrelated line)\n"
    )
    res = authenticated.check_coercion(FakeRunner(output), AUTH_TARGET)
    assert not res.findings


def test_delegation_detects_unconstrained():
    output = "LDAP  10.0.0.10  Unconstrained delegation: DC01$"
    res = authenticated.check_delegation(FakeRunner(output), AUTH_TARGET)
    assert any("Unconstrained" in f.title for f in res.findings)


def test_delegation_bare_flag_name_alone_is_not_a_finding():
    """Regression: a bare 'Constrained|delegation' search matched the
    --find-delegation flag's own likely banner/description text (which
    necessarily contains the word 'delegation') with no account actually
    found and no negation handling."""
    output = "LDAP  10.0.0.10  Running --find-delegation module (checking delegation)"
    res = authenticated.check_delegation(FakeRunner(output), AUTH_TARGET)
    assert not res.findings


def test_delegation_detects_constrained_with_account():
    output = "LDAP  10.0.0.10  svc_app$  Delegation Type: Constrained"
    res = authenticated.check_delegation(FakeRunner(output), AUTH_TARGET)
    assert any("Delegation configured" in f.title for f in res.findings)


# --- Phase 1 roadmap: Zerologon, Kerberos user enum, DNS zone transfer -----

def test_zerologon_detects_vulnerable_dc_and_grants_dcsync():
    output = "SMB  10.0.0.10  445  DC01  [+] Vulnerable to Zerologon (CVE-2020-1472)"
    res = unauthenticated.check_zerologon(FakeRunner(output), ANON_TARGET)
    assert any("Zerologon" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.DCSYNC in grants


def test_zerologon_quiet_when_not_vulnerable():
    output = "SMB  10.0.0.10  445  DC01  [-] not vulnerable to zerologon"
    res = unauthenticated.check_zerologon(FakeRunner(output), ANON_TARGET)
    assert not res.findings
    assert not res.path_steps


def test_zerologon_skips_without_nxc():
    class NoTool(FakeRunner):
        def is_available(self, name):
            return False

    res = unauthenticated.check_zerologon(NoTool(""), ANON_TARGET)
    assert res.skipped


def test_kerberos_user_enum_confirms_users_and_grants_userlist():
    output = (
        "2024/01/01 00:00:00 >  [+] VALID USERNAME:       jsmith@corp.local\n"
        "2024/01/01 00:00:00 >  [+] VALID USERNAME:       asmith@corp.local\n"
    )
    res = unauthenticated.check_kerberos_user_enum(
        FakeRunner(output), ANON_TARGET, userlist="candidates.txt"
    )
    assert any("Kerberos pre-auth" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.USER_LIST in grants


def test_kerberos_user_enum_skips_without_userlist():
    res = unauthenticated.check_kerberos_user_enum(FakeRunner(""), ANON_TARGET, userlist=None)
    assert res.skipped


def test_kerberos_user_enum_skips_without_domain():
    target = Target(host="10.0.0.10")
    res = unauthenticated.check_kerberos_user_enum(
        FakeRunner(""), target, userlist="candidates.txt"
    )
    assert res.skipped


def test_dns_zone_transfer_detects_axfr_and_grants_host_list():
    output = (
        "corp.local.\t\t3600\tIN\tSOA\tdc01.corp.local. hostmaster.corp.local.\n"
        "dc01.corp.local.\t3600\tIN\tA\t10.0.0.10\n"
        "sql01.corp.local.\t3600\tIN\tA\t10.0.0.20\n"
        "ca01.corp.local.\t3600\tIN\tA\t10.0.0.30\n"
        ";; XFR size: 4 records\n"
    )
    res = unauthenticated.check_dns_zone_transfer(FakeRunner(output), ANON_TARGET)
    assert any("zone transfer" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.HOST_LIST in grants


def test_dns_zone_transfer_quiet_when_refused():
    output = "; Transfer failed.\n"
    res = unauthenticated.check_dns_zone_transfer(FakeRunner(output), ANON_TARGET)
    assert not res.findings
    assert not res.path_steps


def test_dns_zone_transfer_skips_without_domain():
    target = Target(host="10.0.0.10")
    res = unauthenticated.check_dns_zone_transfer(FakeRunner(""), target)
    assert res.skipped


# --- Phase 2 roadmap: LAPS, gMSA, DnsAdmins, Shadow Creds, Certifried ------

def test_laps_readability_detects_password_and_grants_capability():
    output = "LDAP  10.0.0.10  LAPS  WS01$: Password: Sup3rS3cr3t!"
    res = authenticated.check_laps_readability(FakeRunner(output), AUTH_TARGET)
    assert any("LAPS" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.LAPS_READABLE in grants


def test_laps_readability_skips_without_creds():
    res = authenticated.check_laps_readability(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_laps_readability_bare_attribute_name_alone_is_not_a_finding():
    """Regression: a bare 'ms-mcs-admpwd' match previously fired from the
    module's own description text with no password actually read."""
    output = "LDAP  10.0.0.10  LAPS  Checking ms-Mcs-AdmPwd readability..."
    res = authenticated.check_laps_readability(FakeRunner(output), AUTH_TARGET)
    assert not res.findings


def test_laps_readability_bind_success_echo_is_not_a_finding():
    """Regression (reported false positive): nxc's own LDAP bind-success
    banner echoes the operator's supplied credential as
    "[+] domain\\username:password" - the literal word "password" right
    after a colon previously satisfied the artifact regex even though it
    has nothing to do with LAPS, and the module's explicit NEGATIVE result
    line ("No result found with attribute ms-MCS-AdmPwd or
    msLAPS-Password !") was also misread as a recovered artifact because
    "msLAPS-Password" contains a hyphen the old regex accepted as a
    separator. Neither must produce a finding."""
    output = (
        "LDAP  172.16.0.200  389  DC1  [*] Windows 10 / Server 2016 Build "
        "14393 (name:DC1) (domain:scc.domain.com) (signing:None) "
        "(channel binding:Never)\n"
        "LDAP  172.16.0.200  389  DC1  [+] scc.domain.com\\r7t:password\n"
        "LAPS  172.16.0.200  389  DC1  [*] Getting LAPS Passwords\n"
        "LAPS  172.16.0.200  389  DC1  [-] No result found with attribute "
        "ms-MCS-AdmPwd or msLAPS-Password !"
    )
    res = authenticated.check_laps_readability(FakeRunner(output), AUTH_TARGET)
    assert not res.findings
    assert not res.path_steps


def test_gmsa_readability_decodes_hash_and_grants_capability():
    output = "LDAP  10.0.0.10  GMSA  Account: svc_app$   NTLM: aad3b435b51404eeaad3b435b51404ee"
    res = authenticated.check_gmsa_readability(FakeRunner(output), AUTH_TARGET)
    assert any("gMSA" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.GMSA_READABLE in grants


def test_gmsa_readability_quiet_when_no_gmsa_present():
    res = authenticated.check_gmsa_readability(
        FakeRunner("LDAP 10.0.0.10  no gmsa accounts found"), AUTH_TARGET
    )
    assert not res.findings
    assert not res.path_steps


def test_dnsadmins_membership_detects_members_and_grants_capability():
    output = "LDAP  10.0.0.10  member: CN=bob,CN=Users,DC=corp,DC=local"
    res = authenticated.check_dnsadmins_membership(FakeRunner(output), AUTH_TARGET)
    assert any("DnsAdmins" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.DNSADMINS_MEMBER in grants


def test_dnsadmins_membership_skips_without_creds():
    res = authenticated.check_dnsadmins_membership(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_shadow_credentials_writable_detects_success_and_grants_capability():
    output = "[*] Updated the msDS-KeyCredentialLink attribute of the target object\n[*] Saved PFX to alice.pfx"
    res = authenticated.check_shadow_credentials_writable(FakeRunner(output), AUTH_TARGET)
    assert any("Shadow Credentials" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.SHADOW_CRED_WRITABLE in grants


def test_shadow_credentials_writable_skips_without_creds():
    res = authenticated.check_shadow_credentials_writable(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_certifried_flags_nonzero_maq_and_grants_cert_as_da():
    output = "LDAP  10.0.0.10  MAQ  MachineAccountQuota: 10"
    res = authenticated.check_certifried(FakeRunner(output), AUTH_TARGET)
    assert any("Certifried" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.CERT_AS_DA in grants


def test_certifried_quiet_when_maq_is_zero():
    output = "LDAP  10.0.0.10  MAQ  MachineAccountQuota: 0"
    res = authenticated.check_certifried(FakeRunner(output), AUTH_TARGET)
    assert not res.findings
    assert not res.path_steps


def test_certifried_skips_without_creds():
    res = authenticated.check_certifried(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_phase1_and_phase2_checks_registered_in_run_all():
    unauth_names = {
        r.name for r in unauthenticated.run_all(
            FakeRunner("nothing"), ANON_TARGET, timeout=60, userlist="users.txt"
        )
    }
    assert "Zerologon (CVE-2020-1472)" in unauth_names
    assert "Kerberos pre-auth username enumeration" in unauth_names
    assert "DNS zone transfer (AXFR)" in unauth_names

    auth_names = {
        r.name for r in authenticated.run_all(FakeRunner("nothing"), AUTH_TARGET, timeout=60)
    }
    assert "LAPS password readability" in auth_names
    assert "gMSA managed-password readability" in auth_names
    assert "DnsAdmins group membership" in auth_names
    assert "Shadow Credentials (msDS-KeyCredentialLink) write access" in auth_names
    assert "Certifried (CVE-2022-26923) - LDAP attribute spoofing" in auth_names


def test_nopac_detects_and_emits_dcsync_step():
    output = "SMB  10.0.0.10  NOPAC  VULNERABLE - got TGT for domain controller"
    res = authenticated.check_nopac(FakeRunner(output), AUTH_TARGET)
    assert any("noPac" in f.title for f in res.findings)
    assert any(f.severity.label == "Critical" for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.DCSYNC in grants


def test_nopac_negated_not_vulnerable_is_not_a_finding():
    """Regression: a negated 'not vulnerable to noPac' result line contains
    the bare substring 'vulnerable' (and the module tag 'nopac'), which
    previously satisfied the unanchored finding condition despite being an
    explicit negative result - the same false-positive shape as the
    confirmed timeroast bug."""
    output = "SMB  10.0.0.10  NOPAC  Not vulnerable to noPac"
    res = authenticated.check_nopac(FakeRunner(output), AUTH_TARGET)
    assert not res.findings


def test_ldap_relay_exposure_detects_and_emits_step():
    output = (
        "LDAP  10.0.0.10  LDAP Signing NOT Enforced\n"
        "LDAP  10.0.0.10  LDAPS Channel Binding is NOT set to Required\n"
    )
    res = unauthenticated.check_ldap_relay_exposure(FakeRunner(output), ANON_TARGET)
    assert any("relay protections" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.LDAP_RELAY_TARGET in grants


def test_inconclusive_on_connection_failure():
    # SMB signing check with no 'signing:' banner -> inconclusive, not clean.
    res = unauthenticated.check_smb_signing(
        FakeRunner("SMB 10.0.0.10  [-] Connection refused"), ANON_TARGET
    )
    assert res.inconclusive
    assert not res.findings
    assert res.status == "inconclusive"


def test_auth_failure_marked_inconclusive_by_run_all_postprocess():
    # A ran-but-empty authenticated check whose output shows auth failure is
    # marked inconclusive by the run_all post-processor.
    from domainerator.runner import CheckResult

    clean = CheckResult(name="a", category="authenticated", raw_output="all good, nothing")
    failed = CheckResult(
        name="b", category="authenticated", raw_output="STATUS_LOGON_FAILURE"
    )
    denied = CheckResult(
        name="c", category="authenticated", raw_output="[-] STATUS_ACCESS_DENIED"
    )
    authenticated._mark_inconclusive_on_failure([clean, failed, denied])
    assert not clean.inconclusive
    assert failed.inconclusive
    assert denied.inconclusive


def test_ntlmv1_detected_and_emits_step():
    output = "SMB  10.0.0.10  NTLMV1  NTLMv1 allowed (LmCompatibilityLevel: 2)"
    res = unauthenticated.check_ntlmv1(FakeRunner(output), ANON_TARGET)
    assert any("NTLMv1" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NTLMV1_HOST in grants
    assert not res.inconclusive


def test_ntlmv1_inconclusive_on_unrecognized_output():
    res = unauthenticated.check_ntlmv1(FakeRunner("SMB 10.0.0.10  [-] something else"), ANON_TARGET)
    assert not res.findings
    assert res.inconclusive


def test_ntlmv1_generic_verb_near_module_name_is_not_a_finding():
    """Regression: an unbounded 'NTLMv1.*(allow|enabl|vulnerab)' match with
    no explicit success token previously fired from loose verb-adjacent
    text (e.g. a disclaimer) rather than the module's actual 'NTLMv1
    allowed' positive-result phrase."""
    output = "SMB  10.0.0.10  NTLMV1  this module checks whether NTLMv1 might be enabled"
    res = unauthenticated.check_ntlmv1(FakeRunner(output), ANON_TARGET)
    assert not res.findings


def test_ntlm_reflection_detected_and_emits_step():
    output = "SMB  10.0.0.10  NTLM_REFLECTION  Host is VULNERABLE to NTLM reflection"
    res = unauthenticated.check_ntlm_reflection(FakeRunner(output), ANON_TARGET)
    assert any("reflection" in f.title.lower() for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.SELF_RELAY_TARGET in grants


def test_ntlm_reflection_inconclusive_on_unrecognized_output():
    res = unauthenticated.check_ntlm_reflection(
        FakeRunner("SMB 10.0.0.10  [-] unrelated line"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_ntlm_reflection_bare_vulnerable_word_unrelated_to_module_is_not_a_finding():
    """Regression: a bare '\\bVULNERABLE\\b' match with zero context-binding
    to the ntlm_reflection module previously fired from the word
    'VULNERABLE' appearing anywhere in the combined buffer, even on a line
    about a completely different technique."""
    output = "SMB  10.0.0.10  SMBGHOST  unrelated finding text mentions VULNERABLE here"
    res = unauthenticated.check_ntlm_reflection(FakeRunner(output), ANON_TARGET)
    assert not res.findings


# --- GPP cpassword, pre-2000 computers, timeroasting -----------------------

def test_gpp_cpassword_recovers_credentials_and_emits_step():
    output = "[+] Found credentials Username: svc_backup Password: Sup3rS3cret!"
    res = authenticated.check_gpp_cpassword(FakeRunner(output), AUTH_TARGET)
    assert any("GPP cpassword" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.VALID_CREDENTIALS in grants


def test_gpp_cpassword_skips_without_creds():
    res = authenticated.check_gpp_cpassword(FakeRunner(""), ANON_TARGET)
    assert res.skipped


def test_gpp_cpassword_bare_attribute_name_alone_is_not_a_finding():
    """Regression: a bare 'cpassword' match previously fired from the
    module's own description text ('Searching for cpassword in SYSVOL...')
    with no credential actually recovered."""
    output = "SMB  10.0.0.10  GPP  Searching for cpassword in SYSVOL..."
    res = authenticated.check_gpp_cpassword(FakeRunner(output), AUTH_TARGET)
    assert not res.findings


def test_gpp_cpassword_inconclusive_on_unrecognized():
    res = authenticated.check_gpp_cpassword(FakeRunner("SMB 10.0.0.10 [-] blah"), AUTH_TARGET)
    assert not res.findings
    assert res.inconclusive


def test_pre2k_detects_vulnerable_computer_and_emits_step():
    output = "LDAP  10.0.0.10  PRE2K  WS01$ is VULNERABLE (pre2k default password)"
    res = authenticated.check_pre2k_computers(FakeRunner(output), AUTH_TARGET)
    assert any("Pre-Windows 2000" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.VALID_CREDENTIALS in grants


def test_pre2k_bare_flag_name_and_dollar_token_alone_is_not_a_finding():
    """Regression: a bare 'pre2k' fallback (the module's own flag name,
    `-M pre2k`) and a loose '[A-Za-z0-9._-]+\\$' 'artifact' (matching ANY
    $-suffixed token, not necessarily a flagged account) previously fired
    together from command-echo text with no account actually confirmed
    vulnerable."""
    output = "LDAP  10.0.0.10  Running -M pre2k module against CORP$ domain"
    res = authenticated.check_pre2k_computers(FakeRunner(output), AUTH_TARGET)
    assert not res.findings


def test_pre2k_inconclusive_on_unrecognized():
    res = authenticated.check_pre2k_computers(FakeRunner("LDAP 10.0.0.10 [-] none"), AUTH_TARGET)
    assert not res.findings
    assert res.inconclusive


def test_timeroast_recovers_hashes_and_emits_crack_chain():
    # Timeroasting needs no credentials, so it lives in the unauthenticated
    # module and works against an anonymous target.
    output = "1000:$sntp-ms$abcdef0123456789$deadbeef"
    res = unauthenticated.check_timeroast(FakeRunner(output), ANON_TARGET)
    assert any("Timeroast" in f.title for f in res.findings)
    techniques = {s.technique for s in res.path_steps}
    # Emits the roast step and the follow-on crack step.
    assert "Timeroast" in techniques
    assert "Hash-crack" in techniques
    grants = {s.grants for s in res.path_steps}
    assert Capability.CRACKABLE_HASH in grants
    assert Capability.VALID_CREDENTIALS in grants


def test_timeroast_works_authenticated_too():
    # With creds present it uses them but still functions the same.
    output = "$sntp-ms$abcdef0123456789$deadbeef"
    res = unauthenticated.check_timeroast(FakeRunner(output), AUTH_TARGET)
    assert any("Timeroast" in f.title for f in res.findings)


def test_timeroast_inconclusive_on_unrecognized():
    res = unauthenticated.check_timeroast(FakeRunner("SMB 10.0.0.10 [-] nope"), ANON_TARGET)
    assert not res.findings
    assert res.inconclusive


def test_timeroast_banner_alone_is_not_a_finding():
    """Regression: nxc's timeroast module always prints a 'Starting
    Timeroasting...' banner line whether or not it recovers any hash, so a
    bare search for the word 'timeroast'/'sntp-ms' anywhere in the output
    previously matched that banner and reported a finding on every run -
    including this exact reported false positive, where a null-session
    STATUS_ACCESS_DENIED meant the module never queried NTP at all."""
    output = (
        "SMB  10.40.0.13  445  PRIFS02  [*] Windows Server 2019 Datacenter "
        "17763 x64 (name:PRIFS02) (domain:abcDomain.com) (signing:True) "
        "(SMBv1:True) (Null Auth:True)\n"
        "SMB  10.40.0.13  445  PRIFS02  [-] abcDomain.com\\: STATUS_ACCESS_DENIED\n"
        "TIMEROAST  10.40.0.13  445  PRIFS02  [*] Starting Timeroasting..."
    )
    res = unauthenticated.check_timeroast(FakeRunner(output), ANON_TARGET)
    assert not res.findings, "banner-only output with no recovered hash must not be a finding"
    assert res.inconclusive
    assert "access_denied" in res.inconclusive_reason.lower()


def test_new_checks_registered_in_run_all():
    # GPP and pre-2000 are credentialed -> authenticated module.
    auth_results = authenticated.run_all(FakeRunner("nothing recognizable"), AUTH_TARGET, timeout=60)
    auth_names = {r.name for r in auth_results}
    assert "GPP cpassword in SYSVOL" in auth_names
    assert "Pre-Windows 2000 computer accounts" in auth_names
    assert "SYSVOL / NETLOGON script credential scraping" in auth_names
    # Timeroasting is credential-free -> unauthenticated (shared) phase.
    unauth_results = unauthenticated.run_all(FakeRunner("nothing"), ANON_TARGET, timeout=60)
    unauth_names = {r.name for r in unauth_results}
    assert "Timeroasting (NTP computer-account hashes)" in unauth_names


# --- unauthenticated "big win" network footholds ---------------------------

def test_cisco_smart_install_detected_and_emits_foothold():
    output = (
        "4786/tcp open  smart-install\n"
        "| cisco-smart-install: Smart Install is enabled / VULNERABLE\n"
    )
    res = unauthenticated.check_cisco_smart_install(FakeRunner(output), ANON_TARGET)
    assert any("Smart Install" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


def test_cisco_smart_install_inconclusive_when_unknown():
    res = unauthenticated.check_cisco_smart_install(
        FakeRunner("Note: Host seems down."), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_cisco_smart_install_negated_result_is_not_a_finding():
    """Regression: a negated 'Smart Install is NOT enabled' result line
    previously had no negative-case handling (unlike check_zerologon's
    explicit 'not vulnerable' guard), so the bare presence of 'Smart
    Install'/'is enabled' keywords could satisfy the finding condition
    despite the explicit negative verdict."""
    output = (
        "4786/tcp open  smart-install\n"
        "| cisco-smart-install: Smart Install is NOT enabled\n"
    )
    res = unauthenticated.check_cisco_smart_install(FakeRunner(output), ANON_TARGET)
    assert not res.findings


def test_eternalblue_detected_and_emits_foothold():
    output = "SMB  10.0.0.10  445  HOST  [+] HOST (name:HOST) MS17-010 VULNERABLE"
    res = unauthenticated.check_eternalblue(FakeRunner(output), ANON_TARGET)
    assert any("EternalBlue" in f.title or "MS17-010" in f.title for f in res.findings)
    # Critical severity for unauth RCE.
    assert any(f.severity.label == "Critical" for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


def test_eternalblue_inconclusive_on_connection_failure():
    res = unauthenticated.check_eternalblue(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_anonymous_ftp_detected():
    output = "| ftp-anon: Anonymous FTP login allowed (FTP code 230)"
    res = unauthenticated.check_anonymous_ftp_nfs(FakeRunner(output), ANON_TARGET)
    assert any("Anonymous FTP" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


def test_null_session_share_enumeration_detected():
    """Regression for M2: the finding-emission branch (READ/WRITE tokens
    present under a null session) must actually fire; previously a dead
    `"shares" not in text.lower()[:0]` clause was always True, which happened
    to leave this branch reachable, but was still worth a dedicated test
    since no test exercised it at all before this fix."""
    output = (
        "SMB  10.0.0.10  445  HOST  [+] corp.local\\: \n"
        "SMB  10.0.0.10  445  HOST  C$             READ,WRITE\n"
        "SMB  10.0.0.10  445  HOST  NETLOGON       READ\n"
    )
    res = unauthenticated.check_null_session(FakeRunner(output), ANON_TARGET)
    assert any("Anonymous SMB share enumeration possible" in f.title for f in res.findings)
    assert not res.inconclusive


def test_null_session_inconclusive_on_connection_failure():
    res = unauthenticated.check_null_session(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_nfs_exports_detected():
    output = "| nfs-showmount:\n|   /export/home 10.0.0.0/24\n"
    res = unauthenticated.check_anonymous_ftp_nfs(FakeRunner(output), ANON_TARGET)
    assert any("NFS" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


def test_nfs_exports_unrelated_slash_text_elsewhere_is_not_a_finding():
    """Regression: a slash-prefixed token appearing ANYWHERE in the combined
    nmap output (not actually inside the nfs-showmount script's own block)
    previously satisfied the export check - e.g. an unrelated comment or URL
    elsewhere in the output."""
    output = (
        "| nfs-showmount:\n"
        "|_  mount failed: RPC: Program not registered\n"
        "| some-other-script: see https://example.com/docs for details\n"
    )
    res = unauthenticated.check_anonymous_ftp_nfs(FakeRunner(output), ANON_TARGET)
    assert not any("NFS" in f.title for f in res.findings)


def test_ftp_nfs_inconclusive_when_ports_absent():
    res = unauthenticated.check_anonymous_ftp_nfs(
        FakeRunner("Note: Host seems down."), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_snmp_default_community_detected():
    output = (
        "161/udp open  snmp\n"
        "| snmp-brute:\n"
        "|   public - Valid credentials\n"
    )
    res = unauthenticated.check_snmp_default_community(FakeRunner(output), ANON_TARGET)
    assert any("SNMP" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


def test_snmp_inconclusive_when_filtered():
    res = unauthenticated.check_snmp_default_community(
        FakeRunner("Note: Host seems down."), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_snmp_info_header_alone_without_recovered_content_is_not_a_finding():
    """Regression: the snmp-info fallback previously only required the
    script's own header to be present (plus the port being open) - nmap
    prints that header whenever the script RUNS, independent of whether it
    actually received a response, so a bare header with nothing recovered
    after it must not be a finding."""
    output = "161/udp open  snmp\n| snmp-info:\n"
    res = unauthenticated.check_snmp_default_community(FakeRunner(output), ANON_TARGET)
    assert not res.findings


def test_network_foothold_chains_to_domain_user():
    # A NETWORK_FOOTHOLD (from any of the new checks) must chain via the
    # baseline credential-reuse glue to valid credentials -> low-priv user.
    from domainerator.paths import build_engine, starting_capabilities

    smi = unauthenticated.check_cisco_smart_install(
        FakeRunner("4786/tcp open\n| cisco-smart-install: VULNERABLE"), ANON_TARGET
    )
    engine = build_engine([smi])
    paths = engine.find_paths(
        starting_capabilities(authenticated=False),
        goals={Capability.LOW_PRIV_USER},
    )
    assert paths, "network foothold should chain to a domain user via credential reuse"


def test_new_network_checks_registered_in_run_all():
    results = unauthenticated.run_all(FakeRunner(""), ANON_TARGET, timeout=60)
    names = {r.name for r in results}
    assert "Cisco Smart Install exposure (TCP 4786)" in names
    assert "MS17-010 / EternalBlue (SMB RCE)" in names
    assert "Anonymous FTP / NFS export exposure" in names
    assert "SNMP default community string" in names


# --- batch 2: SMBGhost, PrintNightmare, IPMI, name poisoning ----------------

def test_smbghost_detected_critical_foothold():
    output = "SMB  10.0.0.10  445  HOST  [+] HOST smbghost VULNERABLE"
    res = unauthenticated.check_smbghost(FakeRunner(output), ANON_TARGET)
    assert any("SMBGhost" in f.title for f in res.findings)
    assert any(f.severity.label == "Critical" for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


def test_smbghost_inconclusive_on_failure():
    res = unauthenticated.check_smbghost(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_printnightmare_spooler_grants_coercion():
    output = "SMB  10.0.0.10  445  HOST  [+] Spooler service enabled"
    res = unauthenticated.check_printnightmare(FakeRunner(output), ANON_TARGET)
    assert any("Spooler" in f.title for f in res.findings)
    # Modeled as a coercion source so it feeds the relay chains (incl. ESC8).
    grants = {s.grants for s in res.path_steps}
    assert Capability.COERCIBLE_AUTH in grants


def test_printnightmare_inconclusive_when_absent():
    res = unauthenticated.check_printnightmare(
        FakeRunner("SMB 10.0.0.10 [-] timed out"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_printnightmare_bare_cve_name_alone_is_not_a_finding():
    """Regression: a bare 'PrintNightmare' CVE-name alternative previously
    fired from the spooler module's own help/description text (which exists
    specifically to probe for PrintNightmare) without the service actually
    being confirmed reachable/enabled."""
    output = "SMB  10.0.0.10  SPOOLER  checking for PrintNightmare (CVE-2021-34527)"
    res = unauthenticated.check_printnightmare(FakeRunner(output), ANON_TARGET)
    assert not res.findings


def test_ipmi_hash_disclosure_grants_crackable_hash():
    output = (
        "623/udp open  asf-rmcp\n"
        "| ipmi-dumphashes:\n"
        "|   admin:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n"
    )
    res = unauthenticated.check_ipmi_hash_disclosure(FakeRunner(output), ANON_TARGET)
    assert any("IPMI" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.CRACKABLE_HASH in grants


def test_ipmi_inconclusive_when_filtered():
    res = unauthenticated.check_ipmi_hash_disclosure(
        FakeRunner("Note: Host seems down."), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_ipmi_protocol_version_only_is_demoted_to_info_not_hash_disclosure():
    """Regression: detecting IPMI 2.0 only confirms the protocol version is
    in use - it previously triggered the same HIGH 'hash disclosure'
    finding as an actually-dumped hash, over-claiming CVE-2013-4786 from
    mere version detection. Protocol-version-only should be a separate,
    lower-severity INFO finding with no crackable-hash capability grant."""
    output = "623/udp open  asf-rmcp\n| ipmi-version: IPMI-2.0\n"
    res = unauthenticated.check_ipmi_hash_disclosure(FakeRunner(output), ANON_TARGET)
    assert any(f.severity.label == "Info" for f in res.findings)
    assert not any("CVE-2013-4786" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.CRACKABLE_HASH not in grants


def test_name_poisoning_exposure_grants_crackable_hash():
    output = "5355/udp open  llmnr\n| llmnr-resolve: host responded\n"
    res = unauthenticated.check_name_poisoning(FakeRunner(output), ANON_TARGET)
    assert any("LLMNR" in f.title or "mDNS" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.CRACKABLE_HASH in grants


def test_name_poisoning_inconclusive_when_absent():
    res = unauthenticated.check_name_poisoning(
        FakeRunner("Note: Host seems down."), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_crackable_hash_chains_to_domain_user():
    # A CRACKABLE_HASH from IPMI must chain via the baseline crack glue to
    # valid credentials -> low-priv user.
    from domainerator.paths import build_engine, starting_capabilities

    ipmi = unauthenticated.check_ipmi_hash_disclosure(
        FakeRunner("623/udp open\n| ipmi-dumphashes:\n|   admin:"
                   "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
        ANON_TARGET,
    )
    engine = build_engine([ipmi])
    paths = engine.find_paths(
        starting_capabilities(authenticated=False),
        goals={Capability.LOW_PRIV_USER},
    )
    assert paths, "a crackable hash should chain to a domain user"


def test_unauth_spooler_relay_chain_reaches_rbcd():
    # The headline internal-pentester win: no creds -> RBCD via an exposed
    # spooler (coercion) relayed to an unsigned DC LDAP.
    from domainerator.paths import build_engine, starting_capabilities

    def responder(argv, cmd):
        if "spooler" in cmd:
            return "SMB 10.0.0.10 [+] Spooler service enabled"
        if "ldap-checks" in cmd:
            return "LDAP Signing NOT Enforced\nLDAPS Channel Binding is NOT set to Required"
        return ""

    class CmdRunner(FakeRunner):
        def run(self, argv, timeout=None):
            return CommandOutput(
                command=" ".join(argv), return_code=0,
                stdout=responder(argv, " ".join(argv)), stderr="",
                duration_seconds=0.0,
            )

    r = CmdRunner()
    pn = unauthenticated.check_printnightmare(r, ANON_TARGET)
    ldap = unauthenticated.check_ldap_relay_exposure(r, ANON_TARGET)
    engine = build_engine([pn, ldap])
    paths = engine.find_paths(
        starting_capabilities(authenticated=False), goals={Capability.RBCD}
    )
    assert paths, "exposed spooler + unsigned LDAP should chain to RBCD from unauth"


def test_batch2_checks_registered_in_run_all():
    names = {r.name for r in unauthenticated.run_all(FakeRunner(""), ANON_TARGET, timeout=60)}
    assert "SMBGhost (CVE-2020-0796) SMBv3 RCE" in names
    assert "Print Spooler / PrintNightmare (MS-RPRN)" in names
    assert "IPMI 2.0 RAKP hash disclosure (CVE-2013-4786)" in names
    assert "LLMNR / NBT-NS / mDNS poisoning exposure" in names


def test_scrape_credentials_from_dir_detects_passwords():
    """Test that _scrape_credentials_from_dir finds embedded credentials."""
    import tempfile
    from pathlib import Path

    from domainerator.checks.authenticated import _scrape_credentials_from_dir

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # Create a script with an embedded password assignment (pattern: password[:=] or pwd[:=])
        (root / "deploy.bat").write_text("set DB_PASSWORD=SecretPass123\n")

        # Create a config file with a connection string
        (root / "web.config").write_text(
            '<connectionStrings><add name="db" connectionString="Server=db;User ID=sa;Password=SecretPass456"/></connectionStrings>'
        )

        # Create a file that should be ignored (wrong extension - .doc not in allowed list)
        (root / "readme.doc").write_text("password=ignored\n")

        hits = _scrape_credentials_from_dir(root)

        # Should find credentials in .bat and .config files
        assert len(hits) >= 2
        paths = [h[0] for h in hits]
        assert any("deploy.bat" in p for p in paths)
        assert any("web.config" in p for p in paths)
        # Should not find anything in .doc file (not in allowed extensions)
        assert not any("readme.doc" in p for p in paths)


def test_scrape_credentials_from_dir_ignores_binary_files():
    """Test that _scrape_credentials_from_dir ignores binary files."""
    import tempfile
    from pathlib import Path

    from domainerator.checks.authenticated import _scrape_credentials_from_dir

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # Create a binary file with a password string in it
        (root / "binary.exe").write_bytes(b"\x00\x01password=test\x00\xff")

        hits = _scrape_credentials_from_dir(root)

        # .exe is not in the allowed extensions
        assert len(hits) == 0


def test_scrape_credentials_from_dir_empty_dir():
    """Test that _scrape_credentials_from_dir returns empty list for empty directory."""
    import tempfile
    from pathlib import Path

    from domainerator.checks.authenticated import _scrape_credentials_from_dir

    with tempfile.TemporaryDirectory() as tmpdir:
        hits = _scrape_credentials_from_dir(Path(tmpdir))
        assert hits == []


def test_classify_failure_connectivity_only():
    result = classify_failure("SMB 10.0.0.10 [-] connection refused")
    assert result == (FailureKind.CONNECTIVITY, "connection refused")


def test_classify_failure_access_denied_only():
    result = classify_failure("SMB 10.0.0.10 [-] STATUS_ACCESS_DENIED")
    assert result == (FailureKind.ACCESS_DENIED, "access_denied")


def test_classify_failure_both_present_is_connectivity():
    result = classify_failure(
        "SMB 10.0.0.10 [-] connection timed out; STATUS_ACCESS_DENIED"
    )
    assert result[0] is FailureKind.CONNECTIVITY


def test_classify_failure_bug_fixture_is_access_denied():
    result = classify_failure(SMBGHOST_BUG_FIXTURE)
    assert result[0] is FailureKind.ACCESS_DENIED


def test_classify_failure_bare_dash_with_no_other_signal_is_connectivity():
    result = classify_failure("SMB 10.0.0.10 [-] no sccm")
    assert result == (FailureKind.CONNECTIVITY, "[-]")


def test_classify_failure_null_auth_banner_is_not_a_signal():
    result = classify_failure(
        "SMB 10.0.0.10 445 HOST (signing:True) (SMBv1:False) (Null Auth:True)"
    )
    assert result is None


def test_classify_failure_no_signal_returns_none():
    assert classify_failure("all good, nothing to see here") is None


def test_looks_like_failure_still_detects_both_kinds():
    assert looks_like_failure("SMB 10.0.0.10 [-] connection refused") == "connection refused"
    assert looks_like_failure("SMB 10.0.0.10 [-] STATUS_ACCESS_DENIED") == "access_denied"


def test_null_session_access_denied_is_finding_not_inconclusive():
    res = unauthenticated.check_null_session(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.status == "findings"
    assert res.inconclusive is False
    assert any(
        f.title == "Anonymous SMB session refused" and f.severity.label == "Info"
        for f in res.findings
    )


def test_null_session_connection_refused_stays_inconclusive():
    res = unauthenticated.check_null_session(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert res.inconclusive is True
    assert res.findings == []


def test_rid_cycling_access_denied_is_finding_not_inconclusive():
    res = unauthenticated.check_rid_cycling(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.status == "findings"
    assert res.inconclusive is False
    assert any(
        f.title == "Anonymous RID cycling refused" and f.severity.label == "Info"
        for f in res.findings
    )


def test_rid_cycling_connection_refused_stays_inconclusive():
    res = unauthenticated.check_rid_cycling(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert res.inconclusive is True
    assert res.findings == []


def test_ldap_anonymous_bind_access_denied_is_finding_not_inconclusive():
    res = unauthenticated.check_ldap_anonymous_bind(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.status == "findings"
    assert res.inconclusive is False
    assert any(
        f.title == "Anonymous LDAP bind refused" and f.severity.label == "Info"
        for f in res.findings
    )


def test_ldap_anonymous_bind_connection_refused_stays_inconclusive():
    res = unauthenticated.check_ldap_anonymous_bind(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert res.inconclusive is True
    assert res.findings == []


def test_ldap_anonymous_bind_success_detected():
    """The anonymous-bind-success line nxc prints, anchored the same way a
    failed null-session shows '[-] domain.com\\: STATUS_...'."""
    output = "LDAP  10.0.0.10  389  DC01  [+] corp.local\\:"
    res = unauthenticated.check_ldap_anonymous_bind(FakeRunner(output), ANON_TARGET)
    assert any("ldap anonymous bind allowed" in f.title.lower() for f in res.findings)


def test_smbghost_bug_fixture_stays_inconclusive_with_access_denied_reason():
    res = unauthenticated.check_smbghost(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.inconclusive is True
    assert "refused" in res.inconclusive_reason


def test_smbghost_timed_out_stays_inconclusive():
    res = unauthenticated.check_smbghost(
        FakeRunner("SMB 10.0.0.10 [-] timed out"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_eternalblue_access_denied_stays_inconclusive_with_specific_reason():
    res = unauthenticated.check_eternalblue(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.inconclusive is True
    assert "refused" in res.inconclusive_reason


def test_eternalblue_no_route_to_host_stays_inconclusive():
    res = unauthenticated.check_eternalblue(
        FakeRunner("SMB 10.0.0.10 [-] no route to host"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_zerologon_access_denied_stays_inconclusive_with_specific_reason():
    res = unauthenticated.check_zerologon(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.inconclusive is True
    assert "refused" in res.inconclusive_reason


def test_zerologon_connection_refused_stays_inconclusive():
    res = unauthenticated.check_zerologon(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_printnightmare_access_denied_stays_inconclusive_with_specific_reason():
    res = unauthenticated.check_printnightmare(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.inconclusive is True
    assert "refused" in res.inconclusive_reason


def test_printnightmare_connection_refused_stays_inconclusive():
    res = unauthenticated.check_printnightmare(
        FakeRunner("SMB 10.0.0.10 [-] connection refused"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive


def test_timeroast_access_denied_stays_inconclusive_with_specific_reason():
    res = unauthenticated.check_timeroast(FakeRunner(SMBGHOST_BUG_FIXTURE), ANON_TARGET)
    assert res.inconclusive is True
    assert "refused" in res.inconclusive_reason


def test_timeroast_no_route_to_host_stays_inconclusive():
    res = unauthenticated.check_timeroast(
        FakeRunner("SMB 10.0.0.10 [-] no route to host"), ANON_TARGET
    )
    assert not res.findings
    assert res.inconclusive
