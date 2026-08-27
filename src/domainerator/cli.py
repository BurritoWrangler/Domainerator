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
from .checks import adcs, authenticated, unauthenticated
from .report import Report
from .runner import CheckResult, Scope, ScopeError, Target, ToolRunner

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
    tgt.add_argument("-t", "--target", required=True,
                     help="Target host/IP (typically a domain controller).")
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
    run.add_argument("--dry-run", action="store_true",
                     help="Show commands without executing them.")
    run.add_argument("-v", "--verbose", action="store_true",
                     help="Verbose logging of executed commands.")

    outg = parser.add_argument_group("output")
    outg.add_argument("-o", "--output",
                      help="Write a Markdown report to this file.")
    outg.add_argument("--json", dest="json_output",
                      help="Write a JSON report to this file.")
    outg.add_argument("--no-color", action="store_true",
                      help="Disable colored console output.")
    outg.add_argument("--include-raw", action="store_true",
                      help="Include raw tool output in the Markdown report.")

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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s",
    )

    # Load scope first so we can fail fast before touching anything.
    scope: Scope | None = None
    if args.scope:
        try:
            scope = Scope.from_file(args.scope)
        except (OSError, ScopeError) as exc:
            print(f"error: could not load scope file: {exc}", file=sys.stderr)
            return 2
        logger.info("scope active: %s", scope.describe())
        for host_arg, label in ((args.target, "target"), (args.dc_ip, "dc-ip")):
            if host_arg and not scope.contains(host_arg):
                print(
                    f"error: {label} '{host_arg}' is not within the scope "
                    f"defined in {args.scope}. Refusing to run.",
                    file=sys.stderr,
                )
                return 2

    password = resolve_credentials(args)

    target = Target(
        host=args.target,
        domain=args.domain,
        username=args.username,
        password=password,
        nthash=args.nthash,
        use_kerberos=args.kerberos,
        dc_ip=args.dc_ip,
    )

    runner = ToolRunner(
        timeout=args.timeout,
        dry_run=args.dry_run,
        verbose=args.verbose,
        scope=scope,
    )

    if args.verbose:
        check_tooling(runner)

    results: list[CheckResult] = []

    if not args.skip_unauth:
        logger.info("running unauthenticated checks")
        results += unauthenticated.run_all(
            runner, target, timeout=args.timeout, userlist=args.userlist
        )

    if target.authenticated:
        if not args.skip_auth:
            logger.info("running authenticated checks")
            results += authenticated.run_all(runner, target, timeout=args.timeout)
        if not args.skip_adcs:
            logger.info("running AD CS checks")
            results += adcs.run_all(runner, target, timeout=args.timeout)
    else:
        if not args.skip_auth or not args.skip_adcs:
            logger.info("no credentials supplied; skipping authenticated and AD CS checks")

    # BloodHound: optionally collect, then ingest whatever data we have.
    bh_data_path = args.bloodhound_data
    if args.bloodhound:
        logger.info("collecting BloodHound data")
        collect_result = bloodhound.collect(
            runner, target, args.bloodhound_output, timeout=max(args.timeout, 600)
        )
        results.append(collect_result)
        # If we just collected and the operator didn't point us elsewhere,
        # ingest from the collection output directory.
        if not bh_data_path and not collect_result.skipped and not collect_result.error:
            bh_data_path = args.bloodhound_output
    if bh_data_path:
        logger.info("ingesting BloodHound data from %s", bh_data_path)
        results.append(bloodhound.ingest(bh_data_path))

    # Correlate everything into ranked attack paths.
    attack_paths: list = []
    if not args.no_paths:
        engine = paths_mod.build_engine(results)
        start = paths_mod.starting_capabilities(
            authenticated=target.authenticated,
            is_low_priv=args.low_priv,
        )
        attack_paths = engine.find_paths(start, max_depth=args.max_path_depth)

    report = Report(
        results,
        target=f"{args.target}"
        + (f" ({args.domain})" if args.domain else ""),
        authenticated=target.authenticated,
        attack_paths=attack_paths,
    )

    # Console summary.
    print(report.console_summary(use_color=not args.no_color))

    # File outputs.
    if args.output:
        Path(args.output).write_text(
            report.to_markdown(include_raw=args.include_raw), encoding="utf-8"
        )
        print(f"\nMarkdown report written to {args.output}")
    if args.json_output:
        Path(args.json_output).write_text(report.to_json(), encoding="utf-8")
        print(f"JSON report written to {args.json_output}")

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
