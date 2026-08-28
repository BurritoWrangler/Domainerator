"""BloodHound integration: collect and ingest ACL-based attack edges.

BloodHound models Active Directory as a graph where edges such as
``GenericAll``, ``WriteDacl``, ``ForceChangePassword`` and ``AddMember``
describe control one principal has over another. Those ACL edges are exactly
the privilege-escalation routes that the NetExec/Certipy checks don't see, so
we ingest them and translate each into a Domainerator :class:`PathStep`.

Two entry points:

* :func:`collect` - shell out to ``bloodhound-python`` to gather data from a DC
  using the operator's credentials (authenticated only).
* :func:`ingest`  - read collected data from a directory of ``*.json`` files or
  a BloodHound ``.zip`` and produce path steps.

We keep parsing tolerant of both the legacy (pre-4.x, "computers"/"users") and
current (4.x+, with a ``data`` wrapper and ``Aces``) SharpHound/AzureHound JSON
shapes, because Kali ships different collector versions over time.

This module performs **no exploitation** - it only reads graph data and emits
the operator commands that would walk each edge.
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .paths import Capability, Noise, PathStep, Reliability
from .runner import CheckResult, Finding, Severity, Target, ToolRunner

CATEGORY = "bloodhound"

# High-value group name fragments that represent (near) domain/forest takeover.
# Matched case-insensitively against a node's name/objectid.
HIGH_VALUE_HINTS = (
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "DOMAIN CONTROLLERS",
    "ENTERPRISE DOMAIN CONTROLLERS",
    "SCHEMA ADMINS",
    "KEY ADMINS",
    "ADMINISTRATOR@",
)

# Map a BloodHound ACL/edge right to how Domainerator models the hop:
# right -> (capability granted, technique id, reliability, noise, operator cmd template,
#           human description)
EDGE_MODEL: dict[str, tuple[Capability, str, Reliability, Noise, str, str]] = {
    "GenericAll": (
        Capability.DACL_CONTROL,
        "GenericAll",
        Reliability.HIGH,
        Noise.QUIET,
        "# full control over {target}: reset password, add to group, or set SPN/RBCD",
        "Full control (GenericAll) over the target object.",
    ),
    "GenericWrite": (
        Capability.DACL_CONTROL,
        "GenericWrite",
        Reliability.HIGH,
        Noise.QUIET,
        "# GenericWrite on {target}: set targeted-kerberoast SPN or logon script",
        "Write access to the target's attributes.",
    ),
    "WriteDacl": (
        Capability.DACL_CONTROL,
        "WriteDacl",
        Reliability.HIGH,
        Noise.QUIET,
        "dacledit.py -action write -rights FullControl -principal USER -target '{target}' DOMAIN/USER:PASS",
        "Can rewrite the target's DACL to grant itself full control.",
    ),
    "WriteOwner": (
        Capability.DACL_CONTROL,
        "WriteOwner",
        Reliability.HIGH,
        Noise.QUIET,
        "owneredit.py -action write -new-owner USER -target '{target}' DOMAIN/USER:PASS",
        "Can take ownership of the target and then rewrite its DACL.",
    ),
    "Owns": (
        Capability.DACL_CONTROL,
        "Owns",
        Reliability.HIGH,
        Noise.QUIET,
        "# already owner of {target}: rewrite DACL to full control",
        "Owns the target object.",
    ),
    "ForceChangePassword": (
        Capability.RESET_PASSWORD,
        "ForceChangePassword",
        Reliability.HIGH,
        Noise.MODERATE,
        "nxc smb DC -u USER -p PASS -M change-password -o TARGET='{target}' NEWPASS='Passw0rd!'",
        "Can force-reset the target account's password.",
    ),
    "AddMember": (
        Capability.ADD_TO_GROUP,
        "AddMember",
        Reliability.HIGH,
        Noise.MODERATE,
        "net rpc group addmem '{target}' USER -U DOMAIN/USER%PASS -S DC",
        "Can add members to the target group.",
    ),
    "AddSelf": (
        Capability.ADD_TO_GROUP,
        "AddSelf",
        Reliability.HIGH,
        Noise.MODERATE,
        "net rpc group addmem '{target}' USER -U DOMAIN/USER%PASS -S DC",
        "Can add self to the target group.",
    ),
    "AllExtendedRights": (
        Capability.RESET_PASSWORD,
        "AllExtendedRights",
        Reliability.HIGH,
        Noise.MODERATE,
        "# AllExtendedRights on {target}: force password reset or read LAPS/GMSA",
        "Holds all extended rights (includes password reset) over the target.",
    ),
    "AddKeyCredentialLink": (
        Capability.RESET_PASSWORD,
        "ShadowCredentials",
        Reliability.HIGH,
        Noise.QUIET,
        "certipy shadow auto -u USER@DOMAIN -p PASS -account '{target}'",
        "Can add a Key Credential (shadow credentials) to authenticate as the target.",
    ),
    "AllowedToDelegate": (
        Capability.LOCAL_ADMIN,
        "ConstrainedDelegation",
        Reliability.MODERATE,
        Noise.MODERATE,
        "getST.py -spn 'cifs/{target}' -impersonate administrator DOMAIN/USER:PASS",
        "Constrained delegation to the target service.",
    ),
    "AllowedToAct": (
        Capability.LOCAL_ADMIN,
        "RBCD",
        Reliability.HIGH,
        Noise.MODERATE,
        "getST.py -spn 'cifs/{target}' -impersonate administrator DOMAIN/PWN$:PASS",
        "Resource-based constrained delegation configured to the target.",
    ),
    "DCSync": (
        Capability.DCSYNC,
        "DCSync",
        Reliability.GUARANTEED,
        Noise.MODERATE,
        "secretsdump.py -just-dc DOMAIN/USER@DC",
        "Holds replication rights (DS-Replication-Get-Changes*) = DCSync.",
    ),
    "GetChanges": (
        Capability.DCSYNC,
        "DCSync",
        Reliability.GUARANTEED,
        Noise.MODERATE,
        "secretsdump.py -just-dc DOMAIN/USER@DC",
        "Holds DS-Replication-Get-Changes (part of DCSync).",
    ),
    "GetChangesAll": (
        Capability.DCSYNC,
        "DCSync",
        Reliability.GUARANTEED,
        Noise.MODERATE,
        "secretsdump.py -just-dc DOMAIN/USER@DC",
        "Holds DS-Replication-Get-Changes-All (part of DCSync).",
    ),
    "ReadLAPSPassword": (
        Capability.LOCAL_ADMIN,
        "ReadLAPS",
        Reliability.HIGH,
        Noise.QUIET,
        "nxc ldap DC -u USER -p PASS -M laps",
        "Can read the LAPS local-admin password of the target computer.",
    ),
    "ReadGMSAPassword": (
        Capability.VALID_CREDENTIALS,
        "ReadGMSA",
        Reliability.HIGH,
        Noise.QUIET,
        "nxc ldap DC -u USER -p PASS --gmsa",
        "Can read the managed password of the target gMSA account.",
    ),
    # --- GPO abuse edges ------------------------------------------------
    # Control over a GPO (or the ability to link one) lets us run code on the
    # computers/users the GPO applies to.
    "WriteGPLink": (
        Capability.GPO_CONTROL,
        "WriteGPLink",
        Reliability.HIGH,
        Noise.MODERATE,
        "# WriteGPLink on {target}: link a malicious GPO to this OU/site/domain",
        "Can link GPOs to the target OU/site (WriteGPLink), enabling GPO abuse.",
    ),
    "GPOAppliesTo": (
        Capability.GPO_CONTROL,
        "GPO-Applies-To",
        Reliability.HIGH,
        Noise.MODERATE,
        "# controlled GPO applies to {target}",
        "A controlled GPO applies to the target; code runs on those principals.",
    ),
    # --- BloodHound-CE specific / explicit edge names -------------------
    "SyncLAPSPassword": (
        Capability.LOCAL_ADMIN,
        "SyncLAPSPassword",
        Reliability.HIGH,
        Noise.QUIET,
        "nxc ldap DC -u USER -p PASS -M laps",
        "Can sync/read the LAPS password of the target computer (CE edge).",
    ),
    "WriteSPN": (
        Capability.DACL_CONTROL,
        "WriteSPN",
        Reliability.HIGH,
        Noise.QUIET,
        "# WriteSPN on {target}: set an SPN then targeted Kerberoast",
        "Can write the target's servicePrincipalName (targeted Kerberoasting).",
    ),
    "WriteAccountRestrictions": (
        Capability.DACL_CONTROL,
        "WriteAccountRestrictions",
        Reliability.HIGH,
        Noise.QUIET,
        "# WriteAccountRestrictions on {target}: configure RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)",
        "Can write account restrictions, enabling RBCD configuration (CE edge).",
    ),
    "AddAllowedToAct": (
        Capability.DACL_CONTROL,
        "AddAllowedToAct",
        Reliability.HIGH,
        Noise.QUIET,
        "rbcd.py -delegate-to '{target}' -delegate-from 'PWN$' -action write DOMAIN/USER:PASS",
        "Can set msDS-AllowedToActOnBehalfOfOtherIdentity on the target (RBCD).",
    ),
    "DumpSMSAPassword": (
        Capability.VALID_CREDENTIALS,
        "DumpSMSAPassword",
        Reliability.HIGH,
        Noise.QUIET,
        "# read the sMSA managed password of {target}",
        "Can dump the managed password of the target sMSA (CE edge).",
    ),
    "MemberOf": (
        Capability.ADD_TO_GROUP,  # traversal only; treated specially below
        "MemberOf",
        Reliability.GUARANTEED,
        Noise.QUIET,
        "# group membership traversal",
        "Group membership relationship.",
    ),
}

# BloodHound-CE meta.type values we know how to read. Kept for clarity and to
# let the parser branch on object type when needed.
CE_KNOWN_TYPES = {
    "users", "groups", "computers", "domains", "gpos", "ous", "containers",
    "certtemplates", "cas", "rootcas", "ntauthstores", "aiacas",
}


@dataclass
class BHEdge:
    """A normalized BloodHound edge: source --right--> target."""

    source: str
    right: str
    target: str
    target_is_high_value: bool
    # BloodHound object type of the target ("gpos", "computers", ...) when known.
    target_type: str = ""


def _is_high_value(name: str) -> bool:
    upper = (name or "").upper()
    return any(hint in upper for hint in HIGH_VALUE_HINTS)


def _iter_json_objects(path: Path) -> Iterable[dict]:
    """Yield parsed JSON docs from a directory of *.json or a BloodHound .zip."""
    if path.is_dir():
        for jf in sorted(path.glob("*.json")):
            try:
                yield json.loads(jf.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
    elif path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as zf:
                for member in zf.namelist():
                    if member.lower().endswith(".json"):
                        try:
                            with zf.open(member) as fh:
                                yield json.loads(fh.read().decode("utf-8", errors="replace"))
                        except (json.JSONDecodeError, KeyError):
                            continue
        except zipfile.BadZipFile:
            return
    elif path.suffix.lower() == ".json":
        try:
            yield json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return


def _node_name(node: dict) -> str:
    """Best-effort principal name from a BloodHound node object."""
    props = node.get("Properties") or node.get("properties") or {}
    for key in ("name", "Name", "distinguishedname"):
        if props.get(key):
            return str(props[key])
    for key in ("ObjectIdentifier", "objectid", "Sid"):
        if node.get(key):
            return str(node[key])
    return "<unknown>"


def _extract_edges_from_doc(doc: dict) -> list[BHEdge]:
    """Pull ACL/edge relationships out of one collector JSON document.

    Handles the 4.x shape where each object carries an ``Aces`` list plus
    ``Members``/``AllowedToAct`` style relationships, as well as older shapes.
    We treat any recognised right as a candidate edge from the ACE principal to
    the object.
    """
    edges: list[BHEdge] = []

    # BloodHound-CE (and 4.x legacy) wrap records under "data"; very old files
    # used top-level type keys. Support both. CE also carries a "meta" object
    # with a "type" field naming the object type in this file.
    meta = doc.get("meta") or doc.get("Meta") or {}
    obj_type = str(meta.get("type") or "").lower()
    records: list[dict] = []
    if isinstance(doc.get("data"), list):
        records = doc["data"]
    else:
        for key in CE_KNOWN_TYPES:
            if isinstance(doc.get(key), list):
                records.extend(doc[key])
                if not obj_type:
                    obj_type = key

    for obj in records:
        if not isinstance(obj, dict):
            continue
        target_name = _node_name(obj)
        target_hv = _is_high_value(target_name)

        # ACE-based rights (GenericAll, WriteDacl, ForceChangePassword, ...).
        # CE nests these under "Aces"; each ACE has RightName + PrincipalSID.
        for ace in obj.get("Aces", []) or obj.get("aces", []) or []:
            right = _canonical_right(ace.get("RightName") or ace.get("rightname"))
            principal = (
                ace.get("PrincipalSID")
                or ace.get("principalsid")
                or ace.get("PrincipalID")
                or "<principal>"
            )
            if right:
                edges.append(
                    BHEdge(
                        source=str(principal),
                        right=right,
                        target=target_name,
                        target_is_high_value=target_hv,
                        target_type=obj_type,
                    )
                )

        # Group membership -> traversal (Members list on group objects).
        for member in obj.get("Members", []) or obj.get("members", []) or []:
            member_sid = (
                member.get("ObjectIdentifier")
                or member.get("MemberId")
                or member.get("objectid")
                or "<member>"
            )
            edges.append(
                BHEdge(
                    source=str(member_sid),
                    right="MemberOf",
                    target=target_name,
                    target_is_high_value=target_hv,
                    target_type=obj_type,
                )
            )

        # RBCD: principals allowed to act on behalf of this object.
        for act in obj.get("AllowedToAct", []) or obj.get("allowedtoact", []) or []:
            act_sid = act.get("ObjectIdentifier") or act.get("objectid") or "<principal>"
            edges.append(
                BHEdge(
                    source=str(act_sid),
                    right="AllowedToAct",
                    target=target_name,
                    target_is_high_value=target_hv,
                    target_type=obj_type,
                )
            )

    return edges


# Lower-cased lookup so we can match right names regardless of casing/whitespace.
_EDGE_MODEL_LC = {k.strip().lower(): k for k in EDGE_MODEL}


def _canonical_right(right: object) -> str | None:
    """Normalize a raw RightName to a key present in EDGE_MODEL, or None.

    BloodHound-CE right names are stable PascalCase strings, but we normalise
    casing/whitespace defensively so minor collector differences still match.
    """
    if not right or not isinstance(right, str):
        return None
    key = right.strip().lower()
    return _EDGE_MODEL_LC.get(key)


def _edge_to_step(edge: BHEdge) -> PathStep | None:
    """Translate a normalized BloodHound edge into a PathStep."""
    model = EDGE_MODEL.get(edge.right)
    if model is None:
        return None
    grant, technique, reliability, noise, cmd_tpl, desc = model

    # A full-control right over a GPO object grants GPO_CONTROL (code execution
    # on everything the GPO applies to), which the path engine turns into local
    # admin. This reinterprets generic object-control edges when the target is
    # a GPO.
    if edge.target_type == "gpos" and grant == Capability.DACL_CONTROL:
        grant = Capability.GPO_CONTROL
        technique = f"{technique} (GPO)"
        desc = "Control over a Group Policy Object. " + desc

    # A right over a high-value group/principal short-circuits toward the goal:
    # controlling Domain Admins (add member / reset a member) reaches DA.
    if edge.target_is_high_value:
        upper = edge.target.upper()
        if "ENTERPRISE ADMINS" in upper:
            grant = Capability.ENTERPRISE_ADMIN
        elif "DOMAIN CONTROLLERS" in upper or "ADMINISTRATOR@" in upper:
            grant = Capability.DCSYNC
        else:
            grant = Capability.DOMAIN_ADMIN

    # MemberOf into a high-value group is a direct grant; otherwise it's just a
    # traversal we don't need to emit as an actionable step.
    if edge.right == "MemberOf" and not edge.target_is_high_value:
        return None

    return PathStep(
        name=f"{technique} over {edge.target}",
        technique=technique,
        requires=frozenset({Capability.LOW_PRIV_USER}),
        grants=grant,
        command=cmd_tpl.format(target=edge.target),
        description=desc + f" Target: {edge.target}.",
        reliability=reliability,
        noise=noise,
        detail=f"{edge.source} -> {edge.target}",
        source="bloodhound",
    )


def ingest(path: str) -> CheckResult:
    """Ingest collected BloodHound data and emit ACL-based path steps."""
    name = "BloodHound ACL edge ingestion"
    result = CheckResult(name=name, category=CATEGORY)

    p = Path(path)
    if not p.exists():
        result.skipped = True
        result.skip_reason = f"bloodhound data not found: {path}"
        return result

    edges: list[BHEdge] = []
    for doc in _iter_json_objects(p):
        edges.extend(_extract_edges_from_doc(doc))

    if not edges:
        result.skipped = True
        result.skip_reason = f"no recognized ACL edges found in {path}"
        return result

    # De-duplicate identical (source, right, target) edges.
    seen: set[tuple[str, str, str]] = set()
    hv_count = 0
    for edge in edges:
        key = (edge.source, edge.right, edge.target)
        if key in seen:
            continue
        seen.add(key)
        step = _edge_to_step(edge)
        if step is not None:
            result.add_step(step)
            if edge.target_is_high_value:
                hv_count += 1

    result.raw_output = f"ingested {len(seen)} unique ACL edges from {path}"
    if hv_count:
        result.add_finding(
            Finding(
                title="ACL-based control over high-value targets",
                severity=Severity.HIGH,
                target=None,
                description=(
                    f"BloodHound data shows {hv_count} ACL edge(s) granting "
                    "control over Domain/Enterprise Admin or Domain Controller "
                    "objects, providing a direct privilege-escalation route."
                ),
                evidence="\n".join(
                    f"{e.source} --{e.right}--> {e.target}"
                    for e in edges if e.target_is_high_value
                )[:1000],
                remediation=(
                    "Review and remove excessive ACLs on privileged groups and "
                    "the domain object; enforce tiered administration."
                ),
            )
        )
    return result


def collect(
    runner: ToolRunner, target: Target, output_dir: str, timeout: int = 600
) -> CheckResult:
    """Run bloodhound-python to collect graph data (authenticated only)."""
    name = "BloodHound collection (bloodhound-python)"
    result = CheckResult(name=name, category=CATEGORY)

    if not target.authenticated:
        result.skipped = True
        result.skip_reason = "collection requires credentials"
        return result
    if not runner.is_available("bloodhound-python"):
        result.skipped = True
        result.skip_reason = "bloodhound-python not found on PATH"
        return result
    if not target.domain:
        result.skipped = True
        result.skip_reason = "no domain supplied"
        return result

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    argv = [
        "bloodhound-python",
        "-d", target.domain,
        "-u", target.username or "",
        "-c", "DCOnly",
        "-ns", target.dc_ip or target.host,
        "--zip",
    ]
    if target.nthash:
        argv += ["--hashes", target.nthash]
    else:
        argv += ["-p", target.password or ""]

    out = runner.run(argv, timeout=timeout)
    result.command = out.command
    result.raw_output = out.combined
    result.return_code = out.return_code
    result.duration_seconds = out.duration_seconds
    if out.error:
        result.error = out.error
    return result
