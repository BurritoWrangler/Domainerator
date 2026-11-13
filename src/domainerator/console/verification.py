"""Verification layer for high-risk findings.

This module provides verification of findings before presenting them as
exploitable paths. Verification reduces false positives by actually testing
whether a finding is exploitable, rather than just detecting its presence.

The verification layer is technique-specific:
- CoercionVerifier: Tests if coercion actually works
- ADCSVerifier: Checks if user has enrollment rights on vulnerable templates
- Pre2KAccountVerifier: Tests authentication with predicted passwords

Results are cached with TTL-based expiration and dependency-based invalidation.
"""

from __future__ import annotations

import datetime
import enum
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..paths import Capability

if TYPE_CHECKING:
    from ..runner import Finding, ToolRunner
    from .session import Session


class VerificationStatus(enum.Enum):
    """Status of a verification attempt."""

    VERIFIED = "verified"  # Confirmed exploitable
    NOT_EXPLOITABLE = "not_exploitable"  # Confirmed not exploitable
    UNVERIFIED = "unverified"  # Could not verify (network error, etc.)
    SKIPPED = "skipped"  # --no-verify or no credentials


class EnrollmentStatus(enum.Enum):
    """ADCS template enrollment status."""

    CAN_ENROLL = "can_enroll"
    NEEDS_APPROVAL = "needs_approval"
    NO_RIGHTS = "no_rights"
    UNKNOWN = "unknown"


@dataclass
class VerificationResult:
    """Result of verifying a finding."""

    status: VerificationStatus
    finding_id: str
    technique: str
    timestamp: datetime.datetime
    detail: str  # Human-readable explanation
    capability_granted: Capability | None = None
    loot: list[str] = field(default_factory=list)
    cache_key: str = ""  # For invalidation


@dataclass
class CacheEntry:
    """Entry in the verification cache."""

    result: VerificationResult
    timestamp: datetime.datetime
    dependencies: set[str] = field(default_factory=set)


class VerificationCache:
    """TTL-based cache for verification results with dependency-based invalidation."""

    def __init__(self, ttl_minutes: float = 30.0) -> None:
        self._entries: dict[str, CacheEntry] = {}
        self._ttl = datetime.timedelta(minutes=ttl_minutes)

    def get(self, key: str) -> VerificationResult | None:
        """Get cached result if not expired."""
        entry = self._entries.get(key)
        if not entry:
            return None

        if datetime.datetime.now() - entry.timestamp > self._ttl:
            del self._entries[key]
            return None

        return entry.result

    def set(
        self,
        key: str,
        result: VerificationResult,
        dependencies: set[str] | None = None,
    ) -> None:
        """Cache a verification result with optional dependencies."""
        self._entries[key] = CacheEntry(
            result=result,
            timestamp=datetime.datetime.now(),
            dependencies=dependencies or set(),
        )

    def invalidate(self, key_pattern: str | None = None) -> int:
        """Invalidate entries matching pattern. Returns count invalidated."""
        if key_pattern is None:
            count = len(self._entries)
            self._entries.clear()
            return count

        regex = re.compile(key_pattern, re.IGNORECASE)
        to_delete = [k for k in self._entries if regex.search(k)]
        for k in to_delete:
            del self._entries[k]
        return len(to_delete)

    def invalidate_by_dependency(self, dependency: str) -> int:
        """Invalidate all entries that depend on a changed value."""
        to_delete = [
            k
            for k, v in self._entries.items()
            if dependency in v.dependencies
        ]
        for k in to_delete:
            del self._entries[k]
        return len(to_delete)

    def to_dict(self) -> dict:
        """Serialize cache for persistence."""
        return {
            "ttl_minutes": self._ttl.total_seconds() / 60,
            "entries": {
                k: {
                    "result": {
                        "status": v.result.status.value,
                        "finding_id": v.result.finding_id,
                        "technique": v.result.technique,
                        "timestamp": v.result.timestamp.isoformat(),
                        "detail": v.result.detail,
                        "capability_granted": (
                            v.result.capability_granted.value
                            if v.result.capability_granted
                            else None
                        ),
                        "loot": v.result.loot,
                        "cache_key": v.result.cache_key,
                    },
                    "timestamp": v.timestamp.isoformat(),
                    "dependencies": list(v.dependencies),
                }
                for k, v in self._entries.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> VerificationCache:
        """Deserialize cache from persistence."""
        cache = cls(ttl_minutes=data.get("ttl_minutes", 30.0))
        for key, entry_data in data.get("entries", {}).items():
            result_data = entry_data["result"]
            result = VerificationResult(
                status=VerificationStatus(result_data["status"]),
                finding_id=result_data["finding_id"],
                technique=result_data["technique"],
                timestamp=datetime.datetime.fromisoformat(result_data["timestamp"]),
                detail=result_data["detail"],
                capability_granted=(
                    Capability(result_data["capability_granted"])
                    if result_data["capability_granted"]
                    else None
                ),
                loot=result_data.get("loot", []),
                cache_key=result_data.get("cache_key", ""),
            )
            cache._entries[key] = CacheEntry(
                result=result,
                timestamp=datetime.datetime.fromisoformat(entry_data["timestamp"]),
                dependencies=set(entry_data.get("dependencies", [])),
            )
        return cache


class CoercionVerifier:
    """Verifies coercion findings by attempting test authentication coercion."""

    def __init__(self, runner: ToolRunner, session: Session) -> None:
        self._runner = runner
        self._session = session

    def verify(self, finding: Finding) -> VerificationResult:
        """
        Attempt a test coercion to verify the host will authenticate to an
        attacker-controlled endpoint.

        Strategy: Use nxc coerce_plus module in CHECK mode, which probes
        without requiring a full relay setup.
        """
        target_host = finding.target or ""
        listener_ip = self._session.variables.get("LHOST")

        if not listener_ip:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique="Coercion",
                timestamp=datetime.datetime.now(),
                detail="LHOST not set; cannot verify coercion. Use 'set LHOST <ip>'.",
                cache_key=f"coercion:{target_host}",
            )

        # Run coerce_plus in check mode
        argv = [
            "nxc",
            "smb",
            target_host,
            *self._session.target.nxc_auth_args(),
            "-M",
            "coerce_plus",
            "-o",
            f"CHECK=True LISTENER_IP={listener_ip}",
        ]

        out = self._runner.run(argv, timeout=60)

        if self._coercion_succeeded(out.combined):
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique="Coercion",
                timestamp=datetime.datetime.now(),
                detail=f"Host {target_host} confirmed coercible to {listener_ip}",
                capability_granted=Capability.COERCIBLE_AUTH,
                cache_key=f"coercion:{target_host}",
            )
        elif self._coercion_blocked(out.combined):
            return VerificationResult(
                status=VerificationStatus.NOT_EXPLOITABLE,
                finding_id=getattr(finding, "id", ""),
                technique="Coercion",
                timestamp=datetime.datetime.now(),
                detail=f"Coercion blocked on {target_host} (patched or network filter)",
                cache_key=f"coercion:{target_host}",
            )
        else:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique="Coercion",
                timestamp=datetime.datetime.now(),
                detail=f"Coercion verification inconclusive: {out.combined[:200]}",
                cache_key=f"coercion:{target_host}",
            )

    def _coercion_succeeded(self, output: str) -> bool:
        return bool(
            re.search(
                r"VULNERABLE|coerc.*success|authenticated to",
                output,
                re.IGNORECASE,
            )
        )

    def _coercion_blocked(self, output: str) -> bool:
        return bool(
            re.search(
                r"STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE|"
                r"connection refused|blocked|patched|not vulnerable",
                output,
                re.IGNORECASE,
            )
        )


class ADCSVerifier:
    """Verifies ADCS ESC findings by checking template enrollment rights."""

    def __init__(self, runner: ToolRunner, session: Session) -> None:
        self._runner = runner
        self._session = session

    def verify(self, finding: Finding, technique: str = "ESC1") -> VerificationResult:
        """
        Verify the current user has enrollment rights on the vulnerable template.

        Uses certipy find with -template flag to check enrollment permissions
        without requesting a certificate.
        """
        template_name = self._extract_template_name(finding)
        ca_name = self._extract_ca_name(finding)

        if not template_name:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique=technique,
                timestamp=datetime.datetime.now(),
                detail="Could not extract template name from finding",
                cache_key=f"adcs:{template_name or 'unknown'}:{ca_name or 'unknown'}",
            )

        # Use certipy to check enrollment rights
        target = self._session.target
        argv = [
            "certipy",
            "find",
            "-u",
            f"{target.username}@{target.domain}" if target.domain else (target.username or ""),
            "-p",
            target.password or "",
            "-template",
            template_name,
        ]
        if target.dc_ip:
            argv.extend(["-dc-ip", target.dc_ip])

        out = self._runner.run(argv, timeout=120)

        enrollment_status = self._parse_enrollment_status(out.combined, template_name)

        if enrollment_status == EnrollmentStatus.CAN_ENROLL:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique=technique,
                timestamp=datetime.datetime.now(),
                detail=f"User can enroll in template {template_name}",
                cache_key=f"adcs:{template_name}:{ca_name}",
            )
        elif enrollment_status == EnrollmentStatus.NEEDS_APPROVAL:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,  # Still exploitable, just delayed
                finding_id=getattr(finding, "id", ""),
                technique=technique,
                timestamp=datetime.datetime.now(),
                detail=f"Enrollment in {template_name} requires manager approval",
                cache_key=f"adcs:{template_name}:{ca_name}",
            )
        elif enrollment_status == EnrollmentStatus.NO_RIGHTS:
            return VerificationResult(
                status=VerificationStatus.NOT_EXPLOITABLE,
                finding_id=getattr(finding, "id", ""),
                technique=technique,
                timestamp=datetime.datetime.now(),
                detail=(
                    f"User lacks enrollment rights on {template_name}. "
                    "Template takeover (ESC4) or delegation abuse may be required first."
                ),
                cache_key=f"adcs:{template_name}:{ca_name}",
            )
        else:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique=technique,
                timestamp=datetime.datetime.now(),
                detail=f"Could not verify enrollment status: {out.combined[:200]}",
                cache_key=f"adcs:{template_name}:{ca_name}",
            )

    def _extract_template_name(self, finding: Finding) -> str | None:
        # Parse from finding.evidence or detail
        evidence = finding.evidence or ""
        match = re.search(r"Template\s*[Nn]ame\s*:\s*(\S+)", evidence)
        if match:
            return match.group(1)
        # Try alternate format
        match = re.search(r"Template:\s*(\S+)", evidence)
        if match:
            return match.group(1)
        return None

    def _extract_ca_name(self, finding: Finding) -> str | None:
        evidence = finding.evidence or ""
        match = re.search(r"CA\s*[Nn]ame\s*:\s*(\S+)", evidence)
        if match:
            return match.group(1)
        match = re.search(r"CA:\s*(\S+)", evidence)
        if match:
            return match.group(1)
        return None

    def _parse_enrollment_status(self, output: str, template: str) -> EnrollmentStatus:
        if re.search(rf"{re.escape(template)}.*ENROLL|can enroll", output, re.IGNORECASE):
            return EnrollmentStatus.CAN_ENROLL
        if re.search(rf"{re.escape(template)}.*approval|pending", output, re.IGNORECASE):
            return EnrollmentStatus.NEEDS_APPROVAL
        if re.search(
            rf"{re.escape(template)}.*denied|no permission|ACCESS_DENIED",
            output,
            re.IGNORECASE,
        ):
            return EnrollmentStatus.NO_RIGHTS
        return EnrollmentStatus.UNKNOWN


class Pre2KAccountVerifier:
    """Verifies pre-Windows 2000 computer accounts by attempting authentication."""

    def __init__(self, runner: ToolRunner, session: Session) -> None:
        self._runner = runner
        self._session = session

    def verify(
        self, finding: Finding, force: bool = False
    ) -> VerificationResult:
        """
        Attempt authentication with the predicted password (lowercase account name).

        Pre-flight checks:
        1. Account lockout threshold - skip if lockout is aggressive
        2. --no-verify flag - skip if set
        """
        # Check for no_verify flag
        if getattr(self._session, "no_verify", False) and not force:
            return VerificationResult(
                status=VerificationStatus.SKIPPED,
                finding_id=getattr(finding, "id", ""),
                technique="Pre2k",
                timestamp=datetime.datetime.now(),
                detail="--no-verify flag set; skipping authentication attempt",
            )

        account_name = self._extract_account_name(finding)
        if not account_name:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique="Pre2k",
                timestamp=datetime.datetime.now(),
                detail="Could not extract account name from finding",
            )

        # Pre-flight: check lockout threshold
        if self._lockout_is_aggressive() and not force:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique="Pre2k",
                timestamp=datetime.datetime.now(),
                detail=(
                    "Account lockout threshold is aggressive; "
                    "skipping auth attempt to avoid lockout. "
                    "Use 'verify --force' to override."
                ),
            )

        # Predicted password is lowercase account name without trailing $
        predicted_password = account_name.rstrip("$").lower()
        target = self._session.target

        # Attempt authentication
        argv = [
            "nxc",
            "smb",
            target.host,
            "-u",
            account_name,
            "-p",
            predicted_password,
        ]
        if target.domain:
            argv.extend(["-d", target.domain])

        out = self._runner.run(argv, timeout=30)

        if "Pwn3d!" in out.combined or "[+]" in out.combined:
            domain = target.domain or "DOMAIN"
            loot = [f"{domain}\\\\{account_name}:{predicted_password}"]
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                finding_id=getattr(finding, "id", ""),
                technique="Pre2k",
                timestamp=datetime.datetime.now(),
                detail=f"Successfully authenticated as {account_name}",
                capability_granted=Capability.VALID_CREDENTIALS,
                loot=loot,
                cache_key=f"pre2k:{account_name}",
            )
        else:
            return VerificationResult(
                status=VerificationStatus.NOT_EXPLOITABLE,
                finding_id=getattr(finding, "id", ""),
                technique="Pre2k",
                timestamp=datetime.datetime.now(),
                detail=f"Authentication failed; password for {account_name} has been rotated",
                cache_key=f"pre2k:{account_name}",
            )

    def _extract_account_name(self, finding: Finding) -> str | None:
        evidence = finding.evidence or ""
        match = re.search(r"([A-Za-z0-9._-]+\$)", evidence)
        return match.group(1) if match else None

    def _lockout_is_aggressive(self) -> bool:
        # Check session's cached password policy for lockout threshold
        # Threshold <= 3 is considered aggressive
        threshold = getattr(self._session.state, "password_policy", {}).get(
            "lockout_threshold", 0
        )
        return 0 < threshold <= 3


class VerificationLayer:
    """Coordinates verification of high-risk findings."""

    # Mapping of technique names to their verifier classes
    TECHNIQUE_VERIFIERS: dict[str, type] = {
        "Coercion": CoercionVerifier,
        "PetitPotam": CoercionVerifier,
        "PrinterBug": CoercionVerifier,
        "DFSCoerce": CoercionVerifier,
        "ShadowCoerce": CoercionVerifier,
        "ESC1": ADCSVerifier,
        "ESC2": ADCSVerifier,
        "ESC3": ADCSVerifier,
        "ESC4": ADCSVerifier,
        "ESC6": ADCSVerifier,
        "ESC8": ADCSVerifier,
        "ESC9": ADCSVerifier,
        "ESC10": ADCSVerifier,
        "ESC11": ADCSVerifier,
        "ESC12": ADCSVerifier,
        "ESC13": ADCSVerifier,
        "ESC14": ADCSVerifier,
        "ESC15": ADCSVerifier,
        "ESC16": ADCSVerifier,
        "Pre2k": Pre2KAccountVerifier,
        "Pre-Windows 2000": Pre2KAccountVerifier,
    }

    def __init__(
        self,
        runner: ToolRunner,
        session: Session,
        cache_ttl_minutes: float = 30.0,
    ) -> None:
        self._runner = runner
        self._session = session
        self._cache = VerificationCache(ttl_minutes=cache_ttl_minutes)
        self._verifiers: dict[str, object] = {}

    def _get_verifier(self, technique: str) -> object | None:
        """Get or create a verifier for the given technique."""
        if technique in self._verifiers:
            return self._verifiers[technique]

        verifier_class = self.TECHNIQUE_VERIFIERS.get(technique)
        if not verifier_class:
            return None

        verifier = verifier_class(self._runner, self._session)
        self._verifiers[technique] = verifier
        return verifier

    def verify_finding(
        self,
        finding: Finding,
        force: bool = False,
        technique: str | None = None,
    ) -> VerificationResult:
        """Verify a finding is exploitable. Uses cache unless force=True."""
        # Determine technique from finding or parameter
        tech = technique or getattr(finding, "technique", None)
        if not tech:
            # Try to infer from title
            title = finding.title.lower()
            for known_tech in self.TECHNIQUE_VERIFIERS:
                if known_tech.lower() in title:
                    tech = known_tech
                    break

        if not tech:
            return VerificationResult(
                status=VerificationStatus.SKIPPED,
                finding_id=getattr(finding, "id", ""),
                technique="Unknown",
                timestamp=datetime.datetime.now(),
                detail="No verifier for this technique",
            )

        cache_key = self._cache_key(finding, tech)
        if not force:
            cached = self._cache.get(cache_key)
            if cached:
                return cached

        verifier = self._get_verifier(tech)
        if not verifier:
            return VerificationResult(
                status=VerificationStatus.SKIPPED,
                finding_id=getattr(finding, "id", ""),
                technique=tech,
                timestamp=datetime.datetime.now(),
                detail=f"No verifier for technique: {tech}",
            )

        # Call appropriate verify method
        if isinstance(verifier, Pre2KAccountVerifier):
            result = verifier.verify(finding, force=force)
        elif isinstance(verifier, ADCSVerifier):
            result = verifier.verify(finding, technique=tech)
        else:
            result = verifier.verify(finding)

        self._cache.set(cache_key, result)
        return result

    def verify_all(self, findings: list[Finding]) -> list[VerificationResult]:
        """Verify all findings that have verifiers."""
        return [self.verify_finding(f) for f in findings]

    def invalidate(self, cache_key_pattern: str | None = None) -> int:
        """Invalidate cache entries matching pattern. Returns count invalidated."""
        return self._cache.invalidate(cache_key_pattern)

    def invalidate_by_dependency(self, dependency: str) -> int:
        """Invalidate all entries that depend on a changed value."""
        return self._cache.invalidate_by_dependency(dependency)

    @staticmethod
    def _cache_key(finding: Finding, technique: str) -> str:
        target = finding.target or "unknown"
        finding_id = getattr(finding, "id", "")
        return f"{technique}:{target}:{finding_id}"

    def to_dict(self) -> dict:
        """Serialize verification state for persistence."""
        return {"cache": self._cache.to_dict()}

    @classmethod
    def from_dict(
        cls,
        data: dict,
        runner: ToolRunner,
        session: Session,
    ) -> VerificationLayer:
        """Deserialize verification state from persistence."""
        layer = cls(runner, session)
        if "cache" in data:
            layer._cache = VerificationCache.from_dict(data["cache"])
        return layer
