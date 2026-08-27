"""Report generation - JSON and Markdown/plain-text output.

The report is built from the list of :class:`~domainerator.runner.CheckResult`
objects produced during a scan. We support two formats:

* ``json``     - machine readable, includes raw tool output.
* ``markdown`` - human readable summary grouped by category and severity.

The console summary reuses the markdown renderer but trims raw output.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone

from .runner import CheckResult, Finding, Severity

# Ordered high-to-low so the most serious items sort first in the report.
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Report:
    """Aggregates check results and renders them in the requested format."""

    def __init__(
        self,
        results: Iterable[CheckResult],
        *,
        target: str = "",
        authenticated: bool = False,
        attack_paths: Iterable = (),
    ) -> None:
        self.results: list[CheckResult] = list(results)
        self.target = target
        self.authenticated = authenticated
        # List of paths.AttackPath (typed loosely to avoid a circular import).
        self.attack_paths: list = list(attack_paths)
        self.generated_at = datetime.now(timezone.utc)

    # -- aggregation helpers -------------------------------------------------

    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def severity_counts(self) -> dict[str, int]:
        counts = {sev.label: 0 for sev in _SEVERITY_ORDER}
        for finding in self.all_findings():
            counts[finding.severity.label] += 1
        return counts

    def _findings_sorted(self) -> list[Finding]:
        return sorted(
            self.all_findings(),
            key=lambda f: int(f.severity),
            reverse=True,
        )

    # -- renderers -----------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "tool": "domainerator",
            "generated_at": self.generated_at.isoformat(),
            "target": self.target,
            "mode": "authenticated" if self.authenticated else "unauthenticated",
            "summary": {
                "checks_run": sum(1 for r in self.results if not r.skipped),
                "checks_skipped": sum(1 for r in self.results if r.skipped),
                "total_findings": len(self.all_findings()),
                "severity_counts": self.severity_counts(),
                "attack_paths_found": len(self.attack_paths),
            },
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "checks": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self, include_raw: bool = False) -> str:
        lines: list[str] = []
        lines.append("# Domainerator Report")
        lines.append("")
        lines.append(f"- **Target:** {self.target or 'n/a'}")
        lines.append(
            f"- **Mode:** {'authenticated' if self.authenticated else 'unauthenticated'}"
        )
        lines.append(f"- **Generated:** {self.generated_at.isoformat()}")
        lines.append("")

        # Severity summary table.
        counts = self.severity_counts()
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for sev in _SEVERITY_ORDER:
            lines.append(f"| {sev.label} | {counts[sev.label]} |")
        lines.append("")

        # Findings grouped by severity.
        findings = self._findings_sorted()
        lines.append("## Findings")
        lines.append("")
        if not findings:
            lines.append("_No findings recorded._")
            lines.append("")
        else:
            for finding in findings:
                target = f" — `{finding.target}`" if finding.target else ""
                lines.append(f"### [{finding.severity.label}] {finding.title}{target}")
                lines.append("")
                lines.append(finding.description)
                lines.append("")
                if finding.evidence:
                    lines.append("**Evidence:**")
                    lines.append("")
                    lines.append("```")
                    lines.append(finding.evidence.strip())
                    lines.append("```")
                    lines.append("")
                if finding.remediation:
                    lines.append(f"**Remediation:** {finding.remediation}")
                    lines.append("")

        # Attack paths to Domain / Enterprise Admin.
        lines.append("## Attack paths to Domain / Enterprise Admin")
        lines.append("")
        if not self.attack_paths:
            lines.append("_No complete escalation path to a goal was identified "
                         "from the current privilege level._")
            lines.append("")
        else:
            lines.append(
                f"Identified {len(self.attack_paths)} path(s), ranked by "
                "weakest-link reliability then brevity. **Detection only** — the "
                "commands below are for the operator to run manually.")
            lines.append("")
            for idx, path in enumerate(self.attack_paths, 1):
                lines.append(
                    f"### Path {idx}: {path.summary()}"
                )
                lines.append("")
                lines.append(
                    f"- **Goal:** {path.goal.value}"
                )
                lines.append(
                    f"- **Reliability (weakest link):** {path.min_reliability.label}"
                )
                lines.append(f"- **Noisiest step:** {path.max_noise.label}")
                lines.append(f"- **Steps:** {path.length}")
                lines.append("")
                for step_no, step in enumerate(path.steps, 1):
                    src = " _(BloodHound)_" if step.source == "bloodhound" else ""
                    lines.append(
                        f"{step_no}. **{step.technique}** — {step.description}{src}"
                    )
                    if step.detail:
                        lines.append(f"   - context: {step.detail}")
                    lines.append("")
                    lines.append("   ```")
                    lines.append(f"   {step.command}")
                    lines.append("   ```")
                lines.append("")

        # Per-check execution log.
        lines.append("## Checks executed")
        lines.append("")
        for result in self.results:
            status = "skipped" if result.skipped else "ran"
            if result.error:
                status = f"error: {result.error}"
            lines.append(f"- **{result.name}** ({result.category}) — {status}")
            if result.skipped and result.skip_reason:
                lines.append(f"  - reason: {result.skip_reason}")
            if include_raw and result.raw_output:
                lines.append("")
                lines.append("  ```")
                for out_line in result.raw_output.strip().splitlines():
                    lines.append(f"  {out_line}")
                lines.append("  ```")
        lines.append("")

        return "\n".join(lines)

    def console_summary(self, use_color: bool = True) -> str:
        """Compact colored summary for stdout at the end of a run."""

        color_map = {
            "Critical": "\033[95m",  # magenta
            "High": "\033[91m",  # red
            "Medium": "\033[93m",  # yellow
            "Low": "\033[94m",  # blue
            "Info": "\033[90m",  # grey
        }
        reset = "\033[0m"
        bold = "\033[1m"

        def c(text: str, code: str) -> str:
            if not use_color:
                return text
            return f"{code}{text}{reset}"

        lines: list[str] = []
        lines.append(c("Domainerator scan complete", bold))
        lines.append(f"Target: {self.target or 'n/a'}  "
                     f"Mode: {'authenticated' if self.authenticated else 'unauthenticated'}")
        counts = self.severity_counts()
        summary_bits = []
        for sev in _SEVERITY_ORDER:
            code = color_map[sev.label]
            summary_bits.append(c(f"{sev.label}:{counts[sev.label]}", code))
        lines.append("  ".join(summary_bits))
        lines.append("")

        for finding in self._findings_sorted():
            code = color_map[finding.severity.label]
            tag = c(f"[{finding.severity.label}]", code)
            target = f" ({finding.target})" if finding.target else ""
            lines.append(f"{tag} {finding.title}{target}")

        # Attack paths - the headline output of the tool.
        lines.append("")
        if self.attack_paths:
            lines.append(c(f"Attack paths to DA/EA ({len(self.attack_paths)}):", bold))
            for idx, path in enumerate(self.attack_paths, 1):
                rel = path.min_reliability.label
                lines.append(
                    c(f"  [{idx}] ", bold)
                    + f"{path.summary()}  "
                    + c(f"(reliability: {rel}, {path.length} steps)", "\033[90m")
                )
        else:
            lines.append(c("No complete escalation path identified.", "\033[90m"))

        skipped = [r for r in self.results if r.skipped]
        if skipped:
            lines.append("")
            lines.append(c(f"{len(skipped)} check(s) skipped:", "\033[90m"))
            for r in skipped:
                lines.append(f"  - {r.name}: {r.skip_reason}")

        return "\n".join(lines)
