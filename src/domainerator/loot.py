"""Structured loot extraction and storage.

Loot is the sensitive, reusable material a step yields: cleartext credentials,
NTLM/Kerberos/other crackable hashes, and ticket/cert files. It is kept
separate from evidence screenshots because its value is machine-usable - you
feed it straight into hashcat, a spray, or secretsdump - so it is written in
the right format, de-duplicated, into its own ``loot/`` folder.

This module provides:
  * :class:`LootItem` - a typed piece of loot (kind + value).
  * :func:`extract_loot` - pull typed loot out of raw tool output.
  * :class:`LootStore` - append-only, de-duplicated per-kind files on disk.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass


class LootKind(enum.Enum):
    """A category of loot, which also names its on-disk file and crack mode."""

    CLEARTEXT = "cleartext"          # domain\\user:password or user:password
    NTLM_HASH = "ntlm_hash"          # user:rid:lm:nt::: (secretsdump/SAM)
    KERBEROS_TGS = "kerberos_tgs"    # $krb5tgs$ (Kerberoast)
    KERBEROS_ASREP = "kerberos_asrep"  # $krb5asrep$ (AS-REP roast)
    NETNTLM = "netntlm"              # NetNTLMv1/v2 (responder/relay capture)
    TIMEROAST = "timeroast"          # $sntp-ms$ (timeroasting)
    IPMI_HASH = "ipmi_hash"          # IPMI RAKP hash

    @property
    def filename(self) -> str:
        return f"{self.value}.txt"

    @property
    def hashcat_mode(self) -> str | None:
        """Hashcat mode for crackable kinds, for the file header. None if N/A."""
        return {
            LootKind.NTLM_HASH: "1000",
            LootKind.KERBEROS_TGS: "13100",
            LootKind.KERBEROS_ASREP: "18200",
            LootKind.NETNTLM: "5600",
            LootKind.TIMEROAST: "31300",
            LootKind.IPMI_HASH: "7300",
        }.get(self)


@dataclass(frozen=True)
class LootItem:
    """A single piece of loot."""

    kind: LootKind
    value: str

    def __str__(self) -> str:
        return self.value


# Ordered most-specific-first so, e.g., a full secretsdump NTLM line is not also
# captured as a weaker partial by a later pattern.
_PATTERNS: list[tuple[LootKind, re.Pattern[str]]] = [
    (LootKind.KERBEROS_TGS, re.compile(r"\$krb5tgs\$[^\s]+")),
    (LootKind.KERBEROS_ASREP, re.compile(r"\$krb5asrep\$[^\s]+")),
    (LootKind.TIMEROAST, re.compile(r"\$sntp-ms\$[^\s]+")),
    (LootKind.NETNTLM, re.compile(r"\$NETNTLM(?:v2)?\$[^\s]+", re.IGNORECASE)),
    # secretsdump / SAM dump: user:rid:lm:nt:::
    (LootKind.NTLM_HASH,
     re.compile(r"[A-Za-z0-9_.$\\-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::")),
    # nxc success line: DOMAIN\\user:password  (after a [+])
    (LootKind.CLEARTEXT,
     re.compile(r"\[\+\]\s+([A-Za-z0-9._-]+\\[^\s:]+:[^\s]+)")),
    # GPP / generic "Username: x Password: y"
    (LootKind.CLEARTEXT,
     re.compile(r"[Uu]sername\s*:\s*([^\s]+)\s+[Pp]assword\s*:\s*([^\s]+)")),
]


def extract_loot(output: str) -> list[LootItem]:
    """Extract typed, de-duplicated loot from raw tool ``output``.

    Conservative by design: only well-known credential/hash shapes are matched,
    so ordinary output is never mistaken for loot.
    """
    found: list[LootItem] = []
    seen: set[tuple[LootKind, str]] = set()

    for kind, pat in _PATTERNS:
        for m in pat.finditer(output):
            if kind is LootKind.CLEARTEXT and m.groups():
                # Normalise "Username: x Password: y" to user:pass.
                if m.lastindex and m.lastindex >= 2:
                    value = f"{m.group(1)}:{m.group(2)}"
                else:
                    value = m.group(1)
            else:
                value = m.group(0)
            value = value.strip()
            key = (kind, value)
            if value and key not in seen:
                seen.add(key)
                found.append(LootItem(kind=kind, value=value))
    return found


class LootStore:
    """Append-only, de-duplicated per-kind loot files under a ``loot/`` dir.

    The directory is created lazily on first write. Each :class:`LootKind` gets
    its own file (e.g. ``ntlm_hashes`` -> ``ntlm_hash.txt``) in a format ready
    to feed the relevant tool, with a one-line header noting the hashcat mode.
    Values already present in a file are not written again, so re-runs don't
    duplicate loot.
    """

    def __init__(self, loot_dir) -> None:
        from pathlib import Path

        self.loot_dir = Path(loot_dir)
        self._created = False
        # In-memory record of what each file already contains (for dedup without
        # re-reading on every write).
        self._seen: dict[LootKind, set[str]] = {}

    def _ensure(self) -> None:
        if not self._created:
            self.loot_dir.mkdir(parents=True, exist_ok=True)
            self._created = True

    def _load_existing(self, kind: LootKind) -> set[str]:
        if kind in self._seen:
            return self._seen[kind]
        values: set[str] = set()
        path = self.loot_dir / kind.filename
        if path.exists():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    values.add(line)
        self._seen[kind] = values
        return values

    def add(self, items: list[LootItem]) -> list[LootItem]:
        """Append new loot items to their per-kind files. Returns what was new."""
        if not items:
            return []
        self._ensure()
        newly: list[LootItem] = []
        # Group by kind so each file is opened once.
        by_kind: dict[LootKind, list[str]] = {}
        for item in items:
            existing = self._load_existing(item.kind)
            if item.value in existing:
                continue
            existing.add(item.value)
            by_kind.setdefault(item.kind, []).append(item.value)
            newly.append(item)

        for kind, values in by_kind.items():
            path = self.loot_dir / kind.filename
            new_file = not path.exists()
            with path.open("a", encoding="utf-8") as fh:
                if new_file:
                    mode = kind.hashcat_mode
                    hint = f" (hashcat -m {mode})" if mode else ""
                    fh.write(f"# {kind.value}{hint} - collected by Domainerator\n")
                for value in values:
                    fh.write(value + "\n")
        return newly
