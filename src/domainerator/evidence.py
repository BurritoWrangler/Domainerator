"""Evidence capture: write per-check command output to a dedicated folder.

During an engagement the operator needs clean, self-contained text artifacts to
screenshot for the customer report - one file per check (and per interactively
executed step) showing the exact command run and its raw output. This module
owns that folder and the file layout so both the scan phase and the interactive
console write evidence the same way.

Layout::

    <output-dir>/
      run-YYYYMMDD-HHMMSS/
        evidence/
          001_unauthenticated_smb-signing-posture.txt
          002_authenticated_kerberoastable-service-accounts.txt
          ...
          exec_001_kerberoast.txt        # console-executed steps
        report.md                        # written by the report command
        report.json

Each evidence file has a small header (check name, category, target, command,
status, timestamp) followed by the raw tool output, so a single screenshot
carries enough context to stand on its own in a report.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .runner import CheckResult

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    """Turn a check name into a short, filesystem-safe slug."""
    s = _SLUG_RE.sub("-", text.lower()).strip("-")
    return s[:60] or "item"


class EvidenceWriter:
    """Writes evidence artifacts under a per-run directory.

    The run directory (``run-<timestamp>``) is created lazily on first write so
    constructing a writer never touches the filesystem. ``base_dir`` is the
    operator-chosen output folder (``--output-dir``); many runs can share it,
    each getting its own timestamped subfolder.
    """

    def __init__(self, base_dir: str | Path, *, run_stamp: str | None = None) -> None:
        self.base_dir = Path(base_dir)
        self.run_stamp = run_stamp or datetime.now().strftime("run-%Y%m%d-%H%M%S")
        self._counter = 0
        self._exec_counter = 0
        self._created = False

    # --- directories -----------------------------------------------------
    @property
    def run_dir(self) -> Path:
        return self.base_dir / self.run_stamp

    @property
    def evidence_dir(self) -> Path:
        return self.run_dir / "evidence"

    def _ensure(self) -> None:
        if not self._created:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            self._created = True

    # --- writers ---------------------------------------------------------
    def write_result(self, result: CheckResult, *, target: str = "") -> Path | None:
        """Write one check's evidence file. Returns the path, or None if the
        check was skipped (nothing worth screenshotting)."""
        if result.skipped:
            return None
        self._ensure()
        self._counter += 1
        fname = f"{self._counter:03d}_{_slug(result.category)}_{_slug(result.name)}.txt"
        path = self.evidence_dir / fname
        path.write_text(self._render_result(result, target), encoding="utf-8")
        return path

    def write_results(self, results: list[CheckResult], *, target: str = "") -> list[Path]:
        """Write evidence for a list of results; returns the paths written."""
        written: list[Path] = []
        for r in results:
            p = self.write_result(r, target=target)
            if p is not None:
                written.append(p)
        return written

    def write_execution(
        self,
        *,
        technique: str,
        command: str,
        output: str,
        target: str = "",
        success: bool | None = None,
    ) -> Path:
        """Write evidence for a command executed interactively in the console."""
        self._ensure()
        self._exec_counter += 1
        fname = f"exec_{self._exec_counter:03d}_{_slug(technique)}.txt"
        path = self.evidence_dir / fname
        status = (
            "success" if success is True
            else "unconfirmed" if success is False
            else "n/a"
        )
        header = self._header(
            title=f"Executed: {technique}",
            fields={
                "Target": target,
                "Command": command,
                "Result": status,
                "Captured": datetime.now(timezone.utc).isoformat(),
            },
        )
        path.write_text(header + (output or "(no output)") + "\n", encoding="utf-8")
        return path

    def write_text(self, filename: str, content: str) -> Path:
        """Write an arbitrary artifact (e.g. a report) into the run directory."""
        self._ensure()
        path = self.run_dir / filename
        path.write_text(content, encoding="utf-8")
        return path

    # --- rendering -------------------------------------------------------
    def _render_result(self, result: CheckResult, target: str) -> str:
        fields = {
            "Category": result.category,
            "Target": target,
            "Status": result.status,
            "Command": result.command or "(none)",
            "Return code": str(result.return_code),
            "Duration (s)": f"{result.duration_seconds:.2f}",
            "Captured": datetime.now(timezone.utc).isoformat(),
        }
        if result.error:
            fields["Error"] = result.error
        if result.inconclusive and result.inconclusive_reason:
            fields["Inconclusive"] = result.inconclusive_reason

        body = self._header(title=result.name, fields=fields)

        if result.findings:
            body += "Findings:\n"
            for f in result.findings:
                tgt = f" ({f.target})" if f.target else ""
                body += f"  [{f.severity.label}] {f.title}{tgt}\n"
            body += "\n"

        body += "--- raw output ---\n"
        body += (result.raw_output or "(no output captured)") + "\n"
        return body

    @staticmethod
    def _header(*, title: str, fields: dict[str, str]) -> str:
        width = 72
        lines = ["=" * width, title, "=" * width]
        for key, value in fields.items():
            if value:
                lines.append(f"{key}: {value}")
        lines.append("")
        return "\n".join(lines) + "\n"
