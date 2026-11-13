"""Tests for check parsing logic (RBCD enumeration, WebDAV discovery).

These drive the checks through a fake ToolRunner that returns canned tool
output, so we exercise the parsing/finding/path-step logic without needing the
real external tools installed.
"""

from __future__ import annotations

from domainerator.checks import authenticated, unauthenticated
from domainerator.paths import Capability
from domainerator.runner import CommandOutput, Target


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
    authenticated._mark_inconclusive_on_failure([clean, failed])
    assert not clean.inconclusive
    assert failed.inconclusive


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


def test_nfs_exports_detected():
    output = "| nfs-showmount:\n|   /export/home 10.0.0.0/24\n"
    res = unauthenticated.check_anonymous_ftp_nfs(FakeRunner(output), ANON_TARGET)
    assert any("NFS" in f.title for f in res.findings)
    grants = {s.grants for s in res.path_steps}
    assert Capability.NETWORK_FOOTHOLD in grants


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
