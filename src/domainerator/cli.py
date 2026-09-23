"""CLI entry point for Domainerator.

Usage examples
--------------
Unauthenticated sweep of a domain controller::

    domainerator --target 10.0.0.10 --domain corp.local

Authenticated audit including AD CS::

    domainerator --target dc01.corp.local --domain corp.local \
        --username alice --password 'S3cret!' --dc-ip 10.0.0.10 \
        --output report.md --json report.json

The tool orchestrates the check modules based on the credentials supplied:
unauthenticated checks always run; authenticated and AD CS checks run only when
a username + password (or NT hash) are provided.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from . import __version__, bloodhound
from . import paths as paths_mod
from .evidence import EvidenceWriter
from .progress import KeypressStatus, ProgressTracker
from .report import Report
from .runner import CheckResult, Scope, ScopeError, Target, ToolRunner
from .scan import ScanOptions, count_units, scan_targets
from .state import State

logger = logging.getLogger("domainerator")

# Tools the various check modules rely on, with install hints.
KNOWN_TOOLS = {
    "nxc": "netexec (pip install netexec / pipx install netexec)",
    "certipy": "Certipy (pipx install certipy-ad)",
    "GetNPUsers.py": "Impacket (pipx install impacket)",
    "bloodhound-python": "BloodHound-CE collector (pipx install bloodhound-ce)",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domainerator",
        description="Audit Windows Domain infrastructure (AD, AD CS) using netexec "
        "and other penetration-testing tools, then produce a findings report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    tgt = parser.add_argument_group("target")
    tgt.add_argument("-t", "--target",
                     help="Target host/IP (typically a domain controller).")
    tgt.add_argument("-T", "--targets",
                     help="File of targets (one IP/host per line) to scan "
                          "concurrently. Mutually complementary with --target.")
    tgt.add_argument("-d", "--domain", help="Active Directory domain (FQDN).")
    tgt.add_argument("--dc-ip", help="Domain controller IP (for Kerberos/AD CS).")

    auth = parser.add_argument_group("authentication (optional)")
    auth.add_argument("-u", "--username", help="Domain username for authenticated checks.")
    auth.add_argument("-p", "--password", help="Password. Omit to be prompted securely.")
    auth.add_argument("-H", "--hash", dest="nthash",
                      help="NT hash (LM:NT or NT) instead of a password.")
    auth.add_argument("-k", "--kerberos", action="store_true",
                      help="Use Kerberos authentication.")
    auth.add_argument("--prompt-password", action="store_true",
                      help="Prompt for the password interactively.")

    scope = parser.add_argument_group("scope")
    scope.add_argument("--skip-unauth", action="store_true",
                       help="Skip unauthenticated checks.")
    scope.add_argument("--skip-auth", action="store_true",
                       help="Skip authenticated checks.")
    scope.add_argument("--skip-adcs", action="store_true",
                       help="Skip AD CS checks.")
    scope.add_argument("--skip-sccm", action="store_true",
                       help="Skip SCCM / PXE NAA checks.")
    scope.add_argument("--userlist",
                       help="User list file for unauthenticated AS-REP roasting.")

    bh = parser.add_argument_group("bloodhound (ACL-based paths)")
    bh.add_argument("--bloodhound", action="store_true",
                    help="Run bloodhound-python to collect graph data (needs creds).")
    bh.add_argument("--bloodhound-output", default="bloodhound-output",
                    help="Directory for bloodhound-python collection output.")
    bh.add_argument("--bloodhound-data",
                    help="Ingest existing BloodHound data (a .zip, a .json, or a "
                         "directory of *.json) for ACL-based path analysis.")

    paths_g = parser.add_argument_group("attack paths")
    paths_g.add_argument("--no-paths", action="store_true",
                         help="Disable attack-path correlation/output.")
    paths_g.add_argument("--assume-low-priv", dest="low_priv",
                         action="store_true", default=True,
                         help="Treat the supplied account as low-privileged (default).")
    paths_g.add_argument("--max-path-depth", type=int, default=8,
                         help="Maximum number of steps in a correlated path.")

    run = parser.add_argument_group("execution")
    run.add_argument("--scope",
                     help="Path to a scope file (one IP or CIDR subnet per "
                          "line). When set, all testing is confined to these "
                          "hosts; out-of-scope targets are refused.")
    run.add_argument("--timeout", type=int, default=300,
                     help="Per-command timeout in seconds.")
    run.add_argument("--workers", type=int, default=5,
                     help="Concurrent workers when scanning multiple targets.")
    run.add_argument("--state",
                     help="Path to a JSON state file. Loaded to seed known "
                          "capabilities and updated with what this run finds "
                          "(supports the iterative foothold->DA workflow).")
    run.add_argument("--no-status", action="store_true",
                     help="Disable the interactive 'press Enter for status' "
                          "feature (auto-disabled when stdin is not a TTY).")
    run.add_argument("--dry-run", action="store_true",
                     help="Show commands without executing them.")
    run.add_argument("-v", "--verbose", action="store_true",
                     help="Verbose logging of executed commands.")

    outg = parser.add_argument_group("output")
    outg.add_argument("-o", "--output",
                      help="Write a Markdown report to this file.")
    outg.add_argument("--json", dest="json_output",
                      help="Write a JSON report to this file.")
    outg.add_argument("--output-dir",
                      help="Directory for engagement artifacts. Each run creates a "
                           "timestamped subfolder with per-check evidence files "
                           "(command + raw output) suitable for report screenshots, "
                           "plus any reports written from the console.")
    outg.add_argument("--no-color", action="store_true",
                      help="Disable colored console output.")
    outg.add_argument("--include-raw", action="store_true",
                      help="Include raw tool output in the Markdown report.")

    interactive = parser.add_argument_group("interactive mode")
    interactive.add_argument("--console", action="store_true",
                             help="Launch interactive Metasploit-style console after scanning. "
                                  "Enables path selection, command execution, and privilege tracking.")

    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def resolve_credentials(args: argparse.Namespace) -> str | None:
    """Resolve password from args/prompt; returns the password or None."""
    password = args.password
    if args.username and not password and not args.nthash:
        if args.prompt_password or sys.stdin.isatty():
            try:
                password = getpass.getpass(f"Password for {args.username}: ")
            except (EOFError, KeyboardInterrupt):
                return None
    return password


def check_tooling(runner: ToolRunner) -> None:
    """Log which known tools are available so the operator knows the coverage."""
    for tool, hint in KNOWN_TOOLS.items():
        available = runner.is_available(tool)
        status = "found" if available else "MISSING"
        logger.info("tool %-14s: %s%s", tool, status,
                    "" if available else f"  (install: {hint})")


def build_tool_inventory(runner: ToolRunner) -> dict[str, str | None]:
    """Capture detected versions of the known tools for the report.

    Recording versions lets an operator correlate a parser miss with a
    tool-version change. Version discovery hits no target, so it is safe even
    under scope and dry-run.
    """
    inventory: dict[str, str | None] = {}
    for tool in KNOWN_TOOLS:
        inventory[tool] = runner.get_version(tool) if runner.is_available(tool) else None
    return inventory


def load_targets(args: argparse.Namespace) -> list[str]:
    """Collect target hosts from --target and/or --targets file."""
    hosts: list[str] = []
    if args.target:
        hosts.append(args.target)
    if args.targets:
        text = Path(args.targets).read_text(encoding="utf-8")
        for raw in text.splitlines():
            entry = raw.strip()
            if entry and not entry.startswith("#"):
                hosts.append(entry)
    # De-duplicate, preserve order.
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    return ordered


def discovered_capabilities(results: list[CheckResult]) -> set:
    """Union of all capabilities *granted* by path steps across results.

    Used to persist to the state file so a subsequent run knows what this run
    established (and to compute the next best action relative to progress).
    """
    caps = set()
    for r in results:
        for step in getattr(r, "path_steps", []) or []:
            caps.add(step.grants)
    return caps


def launch_console(
    runner: ToolRunner,
    targets: list[Target],
    state: State,
    state_path: str | None,
    all_results: list[CheckResult],
    attack_paths: list,
    start_caps: set,
    scope: Scope | None,
    evidence: EvidenceWriter | None = None,
) -> int:
    """Launch the interactive console with accumulated scan results.

    This creates a Session object from the current scan state and enters
    a Metasploit-style REPL for exploring and executing attack paths.
    """
    from .console import Console, Session

    # The first scanned target is the initial active target; the full list is
    # kept so the operator can switch targets and 'relay' can pick a victim.
    all_targets = list(targets) if targets else [Target(host="unknown")]
    primary_target = all_targets[0]

    # Create session with accumulated results.
    session = Session(
        runner=runner,
        target=primary_target,
        targets=all_targets,
        state=state,
        state_path=state_path,
        evidence=evidence,
    )
    session.add_results(all_results)
    session.capabilities = set(start_caps)
    session.attack_paths = attack_paths

    # Adjust runner for console mode (disable dry_run if set).
    runner.dry_run = False

    print("\n" + "=" * 60)
    print("Entering interactive console mode")
    print("=" * 60 + "\n")

    console = Console(session)
    return console.run()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s",
    )

    # Determine targets from --target and/or --targets.
    target_hosts = load_targets(args)
    if not target_hosts:
        print("error: provide --target and/or --targets", file=sys.stderr)
        return 2

    # Load scope first so we can fail fast before touching anything.
    scope: Scope | None = None
    if args.scope:
        try:
            scope = Scope.from_file(args.scope)
        except (OSError, ScopeError) as exc:
            print(f"error: could not load scope file: {exc}", file=sys.stderr)
            return 2
        logger.info("scope active: %s", scope.describe())
        # Every target and the dc-ip must be in scope; refuse the whole run
        # otherwise so we never partially touch an out-of-scope host.
        for host_arg in [*target_hosts, args.dc_ip]:
            if host_arg and not scope.contains(host_arg):
                print(
                    f"error: '{host_arg}' is not within the scope defined in "
                    f"{args.scope}. Refusing to run.",
                    file=sys.stderr,
                )
                return 2

    # Load resume state (empty if absent).
    state = State.load(args.state) if args.state else State()

    password = resolve_credentials(args)

    runner = ToolRunner(
        timeout=args.timeout,
        dry_run=args.dry_run,
        verbose=args.verbose,
        scope=scope,
    )

    if args.verbose:
        check_tooling(runner)
    tool_inventory = build_tool_inventory(runner)

    authed_any = bool(args.username and (password or args.nthash))
    targets = [
        Target(
            host=h,
            domain=args.domain,
            username=args.username,
            password=password,
            nthash=args.nthash,
            use_kerberos=args.kerberos,
            dc_ip=args.dc_ip,
        )
        for h in target_hosts
    ]

    opts = ScanOptions(
        timeout=args.timeout,
        skip_unauth=args.skip_unauth,
        skip_auth=args.skip_auth,
        skip_adcs=args.skip_adcs,
        skip_sccm=args.skip_sccm,
        userlist=args.userlist,
    )

    logger.info("scanning %d target(s)", len(targets))

    # Live status: a keypress on Enter prints progress. Disabled under
    # --dry-run (nothing meaningfully runs), --no-status, or a non-TTY stdin.
    tracker = ProgressTracker()
    tracker.set_total(count_units(targets, opts))
    status_enabled = not args.no_status and not args.dry_run
    with KeypressStatus(tracker, enabled=status_enabled):
        per_host = scan_targets(
            runner, targets, opts, max_workers=args.workers, tracker=tracker
        )
    if status_enabled and sys.stdin.isatty():
        print(tracker.format_final(), file=sys.stderr)

    # BloodHound collection/ingestion is domain-wide -> done once, not per host.
    bh_results: list[CheckResult] = []
    bh_data_path = args.bloodhound_data
    if args.bloodhound:
        logger.info("collecting BloodHound data")
        # Use the first authenticated target for collection.
        coll_target = next((t for t in targets if t.authenticated), targets[0])
        collect_result = bloodhound.collect(
            runner, coll_target, args.bloodhound_output, timeout=max(args.timeout, 600)
        )
        bh_results.append(collect_result)
        if not bh_data_path and not collect_result.skipped and not collect_result.error:
            bh_data_path = args.bloodhound_output
    if bh_data_path:
        logger.info("ingesting BloodHound data from %s", bh_data_path)
        bh_results.append(bloodhound.ingest(bh_data_path))

    # Aggregate all results (per-host + domain-wide BloodHound) for correlation.
    all_results: list[CheckResult] = []
    for host_results in per_host.values():
        all_results += host_results
    all_results += bh_results

    # Seed capabilities from starting posture + resume state.
    start_caps = paths_mod.starting_capabilities(
        authenticated=authed_any, is_low_priv=args.low_priv
    )
    start_caps |= state.seed_capabilities()

    attack_paths: list = []
    next_action = None
    if not args.no_paths:
        engine = paths_mod.build_engine(all_results)
        attack_paths = engine.find_paths(start_caps, max_depth=args.max_path_depth)
        next_action = paths_mod.next_best_action(attack_paths, start_caps)

    # Persist discovered capabilities to the state file for the next run.
    if args.state:
        state.record_discovered(discovered_capabilities(all_results))
        state.add_history(
            f"{len(targets)} target(s): " + ", ".join(t.host for t in targets)
        )
        try:
            state.save(args.state)
        except OSError as exc:
            logger.warning("could not write state file: %s", exc)

    target_label = (
        target_hosts[0] if len(target_hosts) == 1 else f"{len(target_hosts)} targets"
    ) + (f" ({args.domain})" if args.domain else "")

    report = Report(
        all_results,
        target=target_label,
        authenticated=authed_any,
        attack_paths=attack_paths,
        tool_inventory=tool_inventory,
        next_action=next_action,
    )

    print(report.console_summary(use_color=not args.no_color))

    if args.output:
        Path(args.output).write_text(
            report.to_markdown(include_raw=args.include_raw), encoding="utf-8"
        )
        print(f"\nMarkdown report written to {args.output}")
    if args.json_output:
        Path(args.json_output).write_text(report.to_json(), encoding="utf-8")
        print(f"JSON report written to {args.json_output}")

    # Evidence capture: per-check command + raw output files for screenshots.
    evidence: EvidenceWriter | None = None
    if args.output_dir:
        evidence = EvidenceWriter(args.output_dir)
        # Attribute each result to its host where we can (per-host results were
        # aggregated into all_results; use the single target label otherwise).
        host_label = target_hosts[0] if len(target_hosts) == 1 else ""
        try:
            written = evidence.write_results(all_results, target=host_label)
            # Also drop the reports into the run folder for a single bundle.
            evidence.write_text(
                "report.md", report.to_markdown(include_raw=args.include_raw)
            )
            evidence.write_text("report.json", report.to_json())
            print(
                f"\nEvidence for {len(written)} check(s) written to "
                f"{evidence.run_dir}"
            )
        except OSError as exc:
            logger.warning("could not write evidence: %s", exc)
            evidence = None

    # Launch interactive console if requested.
    if args.console:
        return launch_console(
            runner=runner,
            evidence=evidence,
            targets=targets,
            state=state,
            state_path=args.state,
            all_results=all_results,
            attack_paths=attack_paths,
            start_caps=start_caps,
            scope=scope,
        )

    # Exit code: 1 if a complete escalation path was found or any MEDIUM+
    # finding exists (useful for gating in automation), else 0.
    if attack_paths:
        return 1
    worst = max((f.severity for f in report.all_findings()), default=None)
    if worst is not None and int(worst) >= 2:  # MEDIUM or higher
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
