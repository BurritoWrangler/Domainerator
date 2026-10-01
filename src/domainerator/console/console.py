"""Interactive console REPL for Domainerator."""

from __future__ import annotations

import readline  # noqa: F401 - enables history/editing
import shlex
from collections.abc import Callable

from ..paths import Capability
from ..runner import Severity
from . import outcomes
from .relay import CoercionMethod, RelayError, RelayMode, RelayOrchestrator
from .session import Session


class Console:
    """Metasploit-style interactive console for Domainerator.

    Provides a command-line interface for:
    - Viewing discovered attack paths
    - Selecting and executing exploitation steps
    - Tracking privilege escalation progress
    - Running additional checks
    - Managing session state

    Commands:
        help                    Show available commands
        show <type>             Show paths/findings/capabilities/targets
        use <id>                Select an attack path by ID
        info                    Show details of selected path
        run                     Execute/guide through current step
        exploit                 Alias for 'run'
        next                    Advance to next step in path
        back                    Deselect current path
        scan [check]            Run checks (all or specific)
        rescan                  Re-run all checks
        save [file]             Save session state
        status                  Show current session status
        exit, quit              Exit console
    """

    PROMPT_MAIN = "domainerator > "
    PROMPT_PATH = "domainerator (path) > "

    def __init__(self, session: Session) -> None:
        self.session = session
        self.running = True
        self.prompt = self.PROMPT_MAIN

        # Command registry
        self.commands: dict[str, Callable[[list[str]], None]] = {
            "help": self.cmd_help,
            "?": self.cmd_help,
            "show": self.cmd_show,
            "use": self.cmd_use,
            "info": self.cmd_info,
            "run": self.cmd_run,
            "exploit": self.cmd_run,
            "preview": self.cmd_preview,
            "next": self.cmd_next,
            "back": self.cmd_back,
            "set": self.cmd_set,
            "unset": self.cmd_unset,
            "options": self.cmd_options,
            "grant": self.cmd_grant,
            "targets": self.cmd_targets,
            "target": self.cmd_target,
            "relay": self.cmd_relay,
            "report": self.cmd_report,
            "scan": self.cmd_scan,
            "rescan": self.cmd_rescan,
            "save": self.cmd_save,
            "status": self.cmd_status,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
        }

        # Tab completion setup
        self._setup_completion()

    def _setup_completion(self) -> None:
        """Configure readline tab completion."""
        self.completions: list[str] = []

        def completer(text: str, state: int) -> str | None:
            if state == 0:
                # Generate completions based on current context
                line = readline.get_line_buffer()
                parts = line.strip().split()

                if len(parts) <= 1:
                    # Completing command
                    self.completions = [
                        cmd for cmd in self.commands if cmd.startswith(text)
                    ]
                elif parts[0] == "show":
                    self.completions = [
                        t for t in ["paths", "findings", "capabilities", "targets", "loot"]
                        if t.startswith(text)
                    ]
                elif parts[0] in ("set", "unset") and len(parts) <= 2:
                    from .variables import PLACEHOLDER_MAP
                    self.completions = [
                        v for v in PLACEHOLDER_MAP if v.startswith(text.upper())
                    ]
                elif parts[0] == "relay" and len(parts) == 2:
                    self.completions = [
                        m.value for m in RelayMode if m.value.startswith(text)
                    ]
                elif parts[0] == "relay" and len(parts) == 3:
                    self.completions = [
                        c.value for c in CoercionMethod if c.value.startswith(text)
                    ]
                elif parts[0] == "use" and text.isdigit():
                    # Complete with path IDs
                    self.completions = [
                        str(i) for i in range(len(self.session.attack_paths))
                    ]
                elif parts[0] == "target":
                    self.completions = [
                        str(i) for i in range(len(self.session.targets))
                        if str(i).startswith(text)
                    ]
                else:
                    self.completions = []

            if state < len(self.completions):
                return self.completions[state]
            return None

        readline.parse_and_bind("tab: complete")
        readline.set_completer(completer)

    def run(self) -> int:
        """Run the interactive console loop. Returns exit code."""
        self._print_banner()

        while self.running:
            try:
                line = input(self.prompt).strip()
                if not line:
                    continue

                # Parse command
                parts = self._parse_line(line)
                if not parts:
                    continue

                cmd = parts[0].lower()
                args = parts[1:]

                # Dispatch
                handler = self.commands.get(cmd)
                if handler:
                    handler(args)
                else:
                    print(f"Unknown command: {cmd}. Type 'help' for available commands.")

            except EOFError:
                # Ctrl-D
                print()
                self.cmd_exit([])
            except KeyboardInterrupt:
                # Ctrl-C - cancel current input
                print()
                continue

        # Auto-save on exit if modified
        if self.session.modified and self.session.state_path:
            print(f"Saving session state to {self.session.state_path}...")
            self.session.save()

        return 0

    def _parse_line(self, line: str) -> list[str]:
        """Parse a command line into tokens, handling quotes."""
        try:
            return shlex.split(line)
        except ValueError as e:
            print(f"Parse error: {e}")
            return []

    def _print_banner(self) -> None:
        """Display the console banner."""
        print()
        print("=" * 60)
        print("  Domainerator Interactive Console")
        print("  Active Directory Exploitation Framework")
        print("=" * 60)
        print()
        print(f"Target: {self.session.target.host}")
        if self.session.target.domain:
            print(f"Domain: {self.session.target.domain}")
        if self.session.target.authenticated:
            print(f"User: {self.session.target.username}")
        if len(self.session.targets) > 1:
            print(f"Scanned hosts: {len(self.session.targets)} "
                  "(use 'targets' to list, 'target <id>' to switch)")
        print()
        print(f"Capabilities: {len(self.session.capabilities)}")
        print(f"Attack paths: {len(self.session.attack_paths)}")
        print()
        print("Type 'help' for available commands, 'show paths' to see exploitation opportunities.")
        print()

    # --- Commands ------------------------------------------------------------

    def cmd_help(self, args: list[str]) -> None:
        """Show available commands."""
        print()
        print("Core Commands:")
        print("  help, ?              Show this help message")
        print("  show <type>          Show paths, findings, capabilities, targets, or loot")
        print("  use <id>             Select an attack path by ID")
        print("  info                 Show details of selected path")
        print("  preview              Show the current step's fully-substituted command")
        print("  run, exploit         Execute/guide through current step")
        print("  next                 Advance to next step in path")
        print("  back                 Deselect current path, return to main menu")
        print()
        print("Variables:")
        print("  set <NAME> <value>   Set a variable (e.g. set LHOST 10.0.0.5)")
        print("  unset <NAME>         Clear a variable")
        print("  options              Show all variables and the placeholders they fill")
        print()
        print("Capabilities:")
        print("  grant <capability>   Manually mark a capability as obtained")
        print()
        print("Targets:")
        print("  targets              List all scanned hosts and the active one")
        print("  target <id>          Switch the active target to a scanned host")
        print()
        print("Orchestration:")
        print("  relay [mode] [method]  Coordinate ntlmrelayx + coercion as one action")
        print("                         modes: ldap-rbcd, ldap-shadow, reflection, adcs-esc8")
        print("                         methods: coercer, petitpotam, printerbug, dfscoerce")
        print()
        print("Scanning:")
        print("  scan [check]         Run checks (all or specific check name)")
        print("  rescan               Re-run all checks with current capabilities")
        print()
        print("Session:")
        print("  status               Show current session status")
        print("  save [file]          Save session state to file")
        print("  report [dir]         Regenerate Markdown+JSON report from current state")
        print("  exit, quit           Exit console")
        print()

    def cmd_show(self, args: list[str]) -> None:
        """Show various session information."""
        if not args:
            print("Usage: show <paths|findings|capabilities|targets>")
            return

        what = args[0].lower()

        if what == "paths":
            self._show_paths()
        elif what == "findings":
            self._show_findings()
        elif what == "capabilities":
            self._show_capabilities()
        elif what == "targets":
            self._show_targets()
        elif what == "loot":
            self._show_loot()
        else:
            print(f"Unknown show type: {what}")
            print("Available: paths, findings, capabilities, targets, loot")

    def _show_paths(self) -> None:
        """Display discovered attack paths."""
        if not self.session.attack_paths:
            print("No attack paths discovered yet. Run 'scan' or 'rescan' to discover paths.")
            return

        print()
        print(f"{'ID':<4} {'Goal':<20} {'Steps':<6} {'Reliability':<12} {'Noise':<8}")
        print("-" * 60)

        for i, path in enumerate(self.session.attack_paths):
            marker = "*" if path == self.session.selected_path else " "
            print(
                f"{marker}{i:<3} {path.goal.value:<20} {path.length:<6} "
                f"{path.min_reliability.label:<12} {path.max_noise.label:<8}"
            )
            print(f"     {path.summary()}")

        print()
        print(f"Total: {len(self.session.attack_paths)} paths")
        if self.session.selected_path:
            print(f"Selected: path {self.session.attack_paths.index(self.session.selected_path)}")

    def _show_findings(self) -> None:
        """Display all findings from checks."""
        findings: list[tuple[str, Severity, str, str]] = []

        for result in self.session.check_results:
            for finding in result.findings:
                findings.append((
                    finding.title,
                    finding.severity,
                    finding.target or "N/A",
                    result.name,
                ))

        if not findings:
            print("No findings discovered yet.")
            return

        # Sort by severity (highest first)
        findings.sort(key=lambda f: f[1], reverse=True)

        print()
        print(f"{'Severity':<10} {'Title':<40} {'Target':<20} {'Check':<20}")
        print("-" * 100)

        for title, sev, target, check in findings:
            print(f"{sev.label:<10} {title[:40]:<40} {target[:20]:<20} {check[:20]:<20}")

        print()
        print(f"Total: {len(findings)} findings")

    def _show_capabilities(self) -> None:
        """Display current capabilities."""
        print()
        print(self.session.describe_capabilities())
        print()

    def _show_targets(self) -> None:
        """Display target information."""
        t = self.session.target
        print()
        print(f"Host: {t.host}")
        if t.domain:
            print(f"Domain: {t.domain}")
        if t.username:
            print(f"Username: {t.username}")
        print(f"Authenticated: {t.authenticated}")
        if t.dc_ip:
            print(f"DC IP: {t.dc_ip}")
        print()

    def cmd_use(self, args: list[str]) -> None:
        """Select an attack path."""
        if not args:
            print("Usage: use <path-id>")
            print("Use 'show paths' to see available paths.")
            return

        try:
            path_id = int(args[0])
        except ValueError:
            print(f"Invalid path ID: {args[0]}")
            return

        if self.session.select_path(path_id):
            path = self.session.selected_path
            assert path is not None
            print(f"Selected path {path_id}: {path.summary()}")
            print(f"Goal: {path.goal.value}")
            print(f"Steps: {path.length}")
            self.prompt = self.PROMPT_PATH
            self._show_step_info()
        else:
            print(f"Invalid path ID: {path_id}. Use 'show paths' to see available paths.")

    def cmd_info(self, args: list[str]) -> None:
        """Show details of selected path."""
        if not self.session.selected_path:
            print("No path selected. Use 'use <id>' to select a path.")
            return

        path = self.session.selected_path
        print()
        print(f"Goal: {path.goal.value}")
        print(f"Steps: {path.length}")
        print(f"Min reliability: {path.min_reliability.label}")
        print(f"Max noise: {path.max_noise.label}")
        print()
        print("Attack chain:")
        for i, step in enumerate(path.steps):
            marker = ">" if i == self.session.selected_step_index else " "
            print(f" {marker} {i+1}. [{step.technique}] {step.name}")
            if step.detail:
                print(f"      Detail: {step.detail}")
            if i == self.session.selected_step_index:
                cmd = self.session.variables.substitute(step.command)
                print(f"      Command: {cmd}")
        print()

    def _show_step_info(self) -> None:
        """Show info for current step."""
        step = self.session.current_step()
        if not step:
            print("No more steps in this path.")
            return

        cmd = self.session.variables.substitute(step.command)
        print()
        print(f"Step {self.session.selected_step_index + 1}/{len(self.session.selected_path.steps)}: {step.name}")
        print(f"Technique: {step.technique}")
        if step.detail:
            print(f"Detail: {step.detail}")
        print(f"Reliability: {step.reliability.label}")
        print(f"Noise: {step.noise.label}")
        print()
        print("Command:")
        print(f"  {cmd}")
        missing = self.session.variables.missing_placeholders(step.command)
        if missing:
            print()
            print(f"Unfilled variables: {', '.join(missing)} (use 'set <NAME> <value>')")
        print()

    def cmd_run(self, args: list[str]) -> None:
        """Execute/guide through current step."""
        step = self.session.current_step()
        if not step:
            if self.session.selected_path:
                print("No more steps in this path. Use 'back' to select another.")
            else:
                print("No path selected. Use 'use <id>' to select a path.")
            return

        cmd = self.session.variables.substitute(step.command)
        missing = self.session.variables.missing_placeholders(step.command)

        print()
        print("=" * 60)
        print(f"Step: {step.name}")
        print(f"Technique: {step.technique}")
        print("=" * 60)
        print()
        print("Description:")
        print(f"  {step.description}")
        print()
        if step.detail:
            print(f"Target/Context: {step.detail}")
            print()

        print("Command to execute:")
        print(f"  {cmd}")
        print()

        if missing:
            print(f"Unfilled variables: {', '.join(missing)} (use 'set <NAME> <value>')")
            print()

        # Check prerequisites
        missing_caps = [c for c in step.requires if c not in self.session.capabilities]
        if missing_caps:
            print("WARNING: Missing prerequisites:")
            for cap in missing_caps:
                print(f"  - {cap.value}")
            print()

        # Ask what to do
        print("Options:")
        print("  [r] Run this command now")
        print("  [c] Copy command to clipboard")
        print("  [s] Skip this step")
        print("  [m] Mark as completed (manually done)")
        print("  [q] Cancel")
        print()

        while True:
            try:
                choice = input("Choice [r/c/s/m/q]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                choice = "q"

            if choice == "r":
                self._execute_step(step, cmd, missing)
                break
            elif choice == "c":
                self._copy_command(cmd)
                break
            elif choice == "s":
                print("Step skipped.")
                break
            elif choice == "m":
                print(f"Marking {step.grants.value} as obtained.")
                self.session.grant_capability(step.grants)
                self.session.recompute_paths()
                self.session.next_step()
                break
            elif choice == "q":
                break
            else:
                print(f"Invalid choice: {choice}")

    def _execute_step(self, step, cmd: str, missing: list) -> None:
        """Execute a step's command through the ToolRunner (with confirmation).

        The substituted command string is parsed to an argv list and run via
        the session's ToolRunner so scope enforcement and password redaction
        apply. Output is inspected to auto-detect success and grant the step's
        capability, then paths are recomputed.
        """
        stripped = cmd.strip()

        # Steps expressed as comments are manual/multi-command guidance, not a
        # single runnable binary. Show and let the operator mark completion.
        if stripped.startswith("#"):
            print()
            print("This step is guidance (multiple commands or manual setup):")
            print(f"  {cmd}")
            print()
            print("Perform it manually, then use 'grant' or choose [m] to record progress.")
            return

        if missing:
            print()
            print(f"Refusing to run: unfilled variables {', '.join(missing)}.")
            print("Set them first with 'set <NAME> <value>'.")
            return

        # Parse to argv. Reject shell metacharacters we can't safely execute
        # (we run without a shell, so pipes/redirects wouldn't work anyway).
        try:
            argv = shlex.split(cmd, comments=True)
        except ValueError as exc:
            print(f"Could not parse command: {exc}")
            return
        if not argv:
            print("Nothing to run.")
            return

        shell_meta = {"|", ">", "<", ">>", "&&", ";", "&"}
        if any(tok in shell_meta for tok in argv):
            print()
            print("This command uses shell features (pipe/redirect) that the console")
            print("cannot execute safely. Copy it and run it in your shell instead:")
            print(f"  {cmd}")
            print()
            print("Then use 'grant' or [m] to record the resulting capability.")
            return

        print()
        print("WARNING: This will execute the command shown above.")
        print("         Ensure you have proper authorization and scope.")
        print()

        try:
            confirm = input("Proceed? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            confirm = "n"

        if confirm != "y":
            print("Cancelled.")
            return

        print()
        print("Executing...")
        print()

        out = self.session.runner.run(argv)

        if out.error:
            print(f"Execution error: {out.error}")
            return

        # Show output.
        if out.combined:
            print(out.combined)
            print()

        # Interpret the outcome.
        outcome = outcomes.interpret(step.technique, step.grants, out.combined)

        # Capture evidence for the report (command + raw output) if enabled.
        self._capture_execution(step.technique, out.command, out.combined, outcome.success)

        if outcome.loot:
            self.session.add_loot(outcome.loot)
            print(f"Captured {len(outcome.loot)} loot item(s) (see 'show loot').")

        if outcome.success and outcome.capability is not None:
            print(f"[+] Success: granting capability '{outcome.capability.value}'.")
            self.session.grant_capability(outcome.capability)
            self.session.recompute_paths()
            print("    Attack paths recomputed. Advancing to next step.")
            self.session.next_step()
        else:
            print(f"[!] {outcome.detail}")

    def _capture_execution(
        self, technique: str, command: str, output: str, success: bool | None
    ) -> None:
        """Write execution evidence to the output folder, if one is configured."""
        if self.session.evidence is None:
            return
        try:
            path = self.session.evidence.write_execution(
                technique=technique,
                command=command,
                output=output,
                target=self.session.target.host,
                success=success,
            )
            print(f"    Evidence saved: {path}")
        except OSError as exc:
            print(f"    (could not write evidence: {exc})")

    def _copy_command(self, command: str) -> None:
        """Copy command to clipboard."""
        try:
            import pyperclip
            pyperclip.copy(command)
            print("Command copied to clipboard.")
        except ImportError:
            print("pyperclip not installed. Command not copied.")
            print("Install with: pip install pyperclip")

    def cmd_next(self, args: list[str]) -> None:
        """Advance to next step."""
        if not self.session.selected_path:
            print("No path selected.")
            return

        step = self.session.next_step()
        if step:
            self._show_step_info()
        else:
            print("End of path reached!")
            print(f"You should now have: {self.session.selected_path.goal.value}")
            # Mark goal as obtained
            self.session.grant_capability(self.session.selected_path.goal)

    def cmd_back(self, args: list[str]) -> None:
        """Deselect current path."""
        self.session.clear_selection()
        self.prompt = self.PROMPT_MAIN
        print("Returned to main menu.")

    def cmd_preview(self, args: list[str]) -> None:
        """Show the current step's fully-substituted command without running."""
        step = self.session.current_step()
        if not step:
            print("No step selected. Use 'use <id>' to select a path.")
            return
        cmd = self.session.variables.substitute(step.command)
        missing = self.session.variables.missing_placeholders(step.command)
        print()
        print(f"[{step.technique}] {step.name}")
        print("Command:")
        print(f"  {cmd}")
        if missing:
            print()
            print(f"Unfilled variables: {', '.join(missing)}")
        print()

    def cmd_set(self, args: list[str]) -> None:
        """Set a session variable."""
        if len(args) < 2:
            print("Usage: set <NAME> <value>")
            print("Run 'options' to see available variables.")
            return
        name = args[0]
        value = " ".join(args[1:])
        self.session.variables.set(name, value)
        self.session.modified = True
        print(f"{name.upper()} => {value}")

    def cmd_unset(self, args: list[str]) -> None:
        """Clear a session variable."""
        if not args:
            print("Usage: unset <NAME>")
            return
        if self.session.variables.unset(args[0]):
            self.session.modified = True
            print(f"Unset {args[0].upper()}")
        else:
            print(f"{args[0].upper()} was not set")

    def cmd_options(self, args: list[str]) -> None:
        """Show all variables and the placeholders they fill."""
        rows = self.session.variables.as_rows()
        print()
        print(f"{'Name':<16} {'Value':<24} {'Fills placeholders'}")
        print("-" * 78)
        for name, value, tokens in rows:
            shown = value if value else "(unset)"
            print(f"{name:<16} {shown:<24} {tokens}")
        print()

    def cmd_grant(self, args: list[str]) -> None:
        """Manually mark a capability as obtained."""
        if not args:
            print("Usage: grant <capability>")
            print("Valid capabilities:")
            for cap in Capability:
                print(f"  {cap.value}")
            return
        name = args[0].lower()
        by_value = {c.value: c for c in Capability}
        cap = by_value.get(name)
        if cap is None:
            print(f"Unknown capability: {name}")
            print("Run 'grant' with no argument to list valid capabilities.")
            return
        self.session.grant_capability(cap)
        self.session.recompute_paths()
        print(f"Granted '{cap.value}'. Attack paths recomputed.")

    def cmd_targets(self, args: list[str]) -> None:
        """List all scanned hosts and mark the active one."""
        targets = self.session.targets
        if not targets:
            print("No targets in this session.")
            return
        print()
        print(f"{'ID':<4} {'Host':<28} {'Domain':<20} {'Auth'}")
        print("-" * 66)
        for i, t in enumerate(targets):
            marker = "*" if t is self.session.target else " "
            auth = "yes" if t.authenticated else "no"
            print(f"{marker}{i:<3} {t.host:<28} {(t.domain or '-'):<20} {auth}")
        print()
        print("* = active target. Use 'target <id>' to switch.")
        print()

    def cmd_target(self, args: list[str]) -> None:
        """Switch the active target to a scanned host by ID."""
        if not args:
            print("Usage: target <id>   (use 'targets' to list them)")
            return
        try:
            idx = int(args[0])
        except ValueError:
            print(f"Invalid target ID: {args[0]}")
            return
        if self.session.switch_target(idx):
            t = self.session.target
            print(f"Active target is now [{idx}] {t.host}"
                  + (f" ({t.domain})" if t.domain else ""))
            print("Command variables re-seeded from this target.")
        else:
            print(f"Invalid target ID: {idx}. Use 'targets' to list them.")

    def cmd_relay(self, args: list[str]) -> None:
        """Coordinate a background ntlmrelayx listener with a coercion trigger.

        Usage: relay [mode] [method]
          modes:   ldap-rbcd | ldap-shadow | reflection
          methods: coercer | petitpotam | printerbug | dfscoerce

        Values are drawn from session variables: LHOST (listener), DC_IP or DC
        (LDAP relay target), and USER/PASS/DOMAIN for the coercion credentials.
        The victim host to coerce is prompted for (or taken from RELAY_VICTIM).
        """
        mode = self._parse_relay_mode(args[0]) if len(args) >= 1 else None
        if mode is None:
            mode = self._prompt_relay_mode()
            if mode is None:
                return

        method = self._parse_coercion_method(args[1]) if len(args) >= 2 else None
        if method is None:
            method = self._prompt_coercion_method()
            if method is None:
                return

        v = self.session.variables
        listener_ip = v.get("LHOST")
        if not listener_ip:
            print("LHOST is not set. Use 'set LHOST <attacker-ip>' first.")
            return

        # Relay target depends on the mode:
        #   - LDAP modes: the DC (DC_IP/DC)
        #   - ESC8: the CA host/URL (CA), falling back to the DC if unset
        #   - reflection: the victim itself (resolved in build_plan)
        if mode is RelayMode.ADCS_ESC8:
            relay_target = v.get("CA") or v.get("DC_IP") or v.get("DC")
            if not v.get("CA"):
                print("Note: CA not set; defaulting the ESC8 relay target to the "
                      "DC. Use 'set CA <ca-host>' to target the CA explicitly.")
        else:
            relay_target = v.get("DC_IP") or v.get("DC")

        # For ESC8 the host we coerce is the DC (we relay its machine account);
        # offer that as the default victim.
        default_victim = v.get("RELAY_VICTIM")
        if not default_victim and mode is RelayMode.ADCS_ESC8:
            default_victim = v.get("DC_IP") or v.get("DC")
        victim = default_victim or self._prompt_relay_victim()
        if not victim:
            print("No victim host provided. Aborting.")
            return

        try:
            plan = self._orchestrator().build_plan(
                mode, method,
                listener_ip=listener_ip,
                relay_target=relay_target,
                victim=victim,
                domain=v.get("DOMAIN"),
                username=v.get("USER"),
                password=v.get("PASS"),
            )
        except RelayError as exc:
            print(f"Cannot build relay plan: {exc}")
            print("Set the missing variable(s) with 'set' and try again.")
            return

        # Show the plan and confirm.
        print()
        print("=" * 60)
        print("Relay orchestration plan")
        print("=" * 60)
        print(f"Mode:      {plan.mode.value} - {plan.mode.description}")
        print(f"Coercion:  {plan.coercion.value}")
        print(f"Listener:  {plan.listener_ip}")
        print(f"Relay to:  {plan.relay_target}")
        print(f"Victim:    {plan.victim}")
        print(f"Grants:    {plan.mode.grants.value} on success")
        print()
        print("Two coordinated commands will run:")
        print(f"  1. listener:  {plan.relay_display}")
        print(f"  2. coercion:  {plan.coercion_display}")
        print()
        print("WARNING: coercion is LOUD and touches the victim host. Ensure it")
        print("         is authorized and in scope.")
        print()

        try:
            confirm = input("Proceed? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            confirm = "n"
        if confirm != "y":
            print("Cancelled.")
            return

        print()
        result = self._orchestrator().run(plan, on_event=lambda m: print(f"  {m}"))
        print()

        # Capture relay evidence (listener + coercion output) for the report.
        relay_transcript = (
            f"# listener\n{plan.relay_display}\n\n"
            f"# coercion\n{plan.coercion_display}\n\n"
            f"--- relay output ---\n{result.relay_output}\n\n"
            f"--- coercion output ---\n{result.coercion_output}"
        )
        self._capture_execution(
            f"relay-{plan.mode.value}", plan.relay_display, relay_transcript, result.success
        )

        # Capture any loot from the relay output.
        loot = outcomes._extract_loot(result.relay_output)
        if loot:
            self.session.add_loot(loot)
            print(f"Captured {len(loot)} loot item(s) (see 'show loot').")

        if result.success and result.capability is not None:
            print(f"[+] {result.detail}")
            print(f"[+] Granting capability '{result.capability.value}'.")
            self.session.grant_capability(result.capability)
            self.session.recompute_paths()
            print("    Attack paths recomputed.")
        else:
            print(f"[!] Relay did not confirm success: {result.detail}")
            print("    Review the listener output above. If it actually worked,")
            print("    record it with 'grant <capability>'.")

    def _orchestrator(self) -> RelayOrchestrator:
        return RelayOrchestrator(runner=self.session.runner)

    def _parse_relay_mode(self, token: str):
        by_value = {m.value: m for m in RelayMode}
        mode = by_value.get(token.lower())
        if mode is None:
            print(f"Unknown relay mode: {token}")
            print("Modes: " + ", ".join(m.value for m in RelayMode))
        return mode

    def _parse_coercion_method(self, token: str):
        by_value = {c.value: c for c in CoercionMethod}
        method = by_value.get(token.lower())
        if method is None:
            print(f"Unknown coercion method: {token}")
            print("Methods: " + ", ".join(c.value for c in CoercionMethod))
        return method

    def _prompt_relay_mode(self):
        print("Select relay mode:")
        modes = list(RelayMode)
        for i, m in enumerate(modes):
            print(f"  [{i}] {m.value} - {m.description}")
        try:
            choice = input("Mode: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        # Accept index or name.
        if choice.isdigit() and 0 <= int(choice) < len(modes):
            return modes[int(choice)]
        return self._parse_relay_mode(choice)

    def _prompt_relay_victim(self) -> str:
        """Prompt for the victim host, offering the scanned hosts as choices.

        The operator can pick a scanned host by number or type any host/IP
        directly (useful when the victim wasn't a scan target). An entry is
        still subject to scope enforcement when the relay actually runs.
        """
        hosts = self.session.target_hosts()
        if hosts:
            print("Select victim host to coerce (or type a host/IP):")
            for i, h in enumerate(hosts):
                active = " (active)" if h == self.session.target.host else ""
                print(f"  [{i}] {h}{active}")
        try:
            choice = input("Victim: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""
        if not choice:
            return ""
        # A bare index selects from the scanned hosts; anything else is literal.
        if choice.isdigit() and hosts and 0 <= int(choice) < len(hosts):
            return hosts[int(choice)]
        return choice

    def _prompt_coercion_method(self):
        print("Select coercion method:")
        methods = list(CoercionMethod)
        for i, c in enumerate(methods):
            print(f"  [{i}] {c.value}")
        try:
            choice = input("Method: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if choice.isdigit() and 0 <= int(choice) < len(methods):
            return methods[int(choice)]
        return self._parse_coercion_method(choice)

    def _show_loot(self) -> None:
        """Display collected loot."""
        if not self.session.loot:
            print("No loot collected yet.")
            return
        print()
        print(f"Collected loot ({len(self.session.loot)} item(s)):")
        for i, item in enumerate(self.session.loot):
            # Truncate very long items for display.
            shown = item if len(item) <= 100 else item[:97] + "..."
            print(f"  [{i}] {shown}")
        print()

    # Check categories that can be run from the console.
    _SCAN_CATEGORIES = ("unauthenticated", "authenticated", "adcs", "sccm")

    def cmd_scan(self, args: list[str]) -> None:
        """Run checks against the active target.

        Usage:
          scan              Run all applicable checks (same as rescan)
          scan <category>   Run one category: unauthenticated | authenticated
                            | adcs | sccm

        Results are merged into the session (new capabilities unioned in) and
        the attack paths are recomputed, so paths that depend on freshly
        discovered capabilities (e.g. ESC8 needing a relay target + coercion)
        appear without leaving the console.
        """
        category = None
        if args:
            category = args[0].lower()
            if category not in self._SCAN_CATEGORIES:
                print(f"Unknown category: {category}")
                print("Categories: " + ", ".join(self._SCAN_CATEGORIES))
                return
        self._run_scan(category)

    def cmd_rescan(self, args: list[str]) -> None:
        """Re-run all applicable checks against the active target."""
        self._run_scan(None)

    def _run_scan(self, category: str | None) -> None:
        """Execute checks against the active target, merge, and recompute paths.

        ``category`` selects a single check module; None runs all applicable
        ones (gated by whether the target is authenticated, exactly as the CLI
        does). Prior results for the same checks are replaced so re-running does
        not pile up duplicates.
        """
        from ..scan import ScanOptions, scan_target

        target = self.session.target
        print()
        label = category or "all applicable"
        print(f"Running {label} checks against {target.host}...")
        if self.session.runner.scope is not None and self.session.runner.scope.active:
            # The runner enforces scope per-command, but warn early if the
            # active target itself is out of scope so the operator isn't
            # surprised by a wall of 'refused' results.
            if not self.session.runner.scope.contains(target.host):
                print(f"WARNING: {target.host} is outside the configured scope; "
                      "checks targeting it will be refused.")

        opts = ScanOptions(
            timeout=self.session.runner.timeout,
            skip_unauth=category not in (None, "unauthenticated"),
            skip_auth=category not in (None, "authenticated"),
            skip_adcs=category not in (None, "adcs"),
            skip_sccm=category not in (None, "sccm"),
        )

        try:
            results = scan_target(self.session.runner, target, opts)
        except Exception as exc:  # never let a scan crash the console
            print(f"Scan error: {exc}")
            return

        if not results:
            print("No checks ran (the selected category may not apply to this "
                  "target's auth state).")
            return

        # Merge: drop prior results for the same (name, category) on this host,
        # then add the fresh ones so capabilities reflect current reality.
        fresh_keys = {(r.name, r.category) for r in results}
        self.session.check_results = [
            r for r in self.session.check_results
            if (r.name, r.category) not in fresh_keys
        ]
        self.session.add_results(results)
        self.session.recompute_paths()

        # Summarize what happened.
        findings = sum(len(r.findings) for r in results)
        new_steps = sum(len(r.path_steps or []) for r in results)
        print(f"Ran {len(results)} check(s): {findings} finding(s), "
              f"{new_steps} path step(s).")
        print(f"Capabilities: {len(self.session.capabilities)}  "
              f"Attack paths: {len(self.session.attack_paths)}")
        if self.session.attack_paths:
            print("Use 'show paths' to view them.")
        else:
            print("No complete escalation path yet. 'show findings' and "
                  "'show capabilities' show what was discovered; some paths "
                  "need extra capabilities (e.g. ESC8 needs a relay target + "
                  "coercion) before they close.")

        # Capture evidence for the re-run checks if an output folder is set.
        if self.session.evidence is not None:
            try:
                self.session.evidence.write_results(results, target=target.host)
            except OSError as exc:
                print(f"(could not write evidence: {exc})")

    def cmd_save(self, args: list[str]) -> None:
        """Save session state."""
        path = args[0] if args else self.session.state_path
        if not path:
            print("Usage: save <file>")
            print("No default state file configured. Specify a path.")
            return

        self.session.save(path)
        print(f"Session state saved to {path}")

    def cmd_report(self, args: list[str]) -> None:
        """Regenerate a Markdown + JSON report from the current session state.

        The report reflects everything discovered/executed this session -
        updated capabilities, recomputed attack paths, and captured loot - so
        an operator can produce a fresh deliverable after interactive work.

        With an evidence folder configured (``--output-dir``) and no argument,
        the report lands in that run folder alongside the screenshots. A path
        argument overrides the destination directory.
        """
        from ..paths import next_best_action
        from ..report import Report

        # Build a report from the live session state.
        next_action = next_best_action(self.session.attack_paths, self.session.capabilities)
        report = Report(
            self.session.check_results,
            target=self.session.target.host
            + (f" ({self.session.target.domain})" if self.session.target.domain else ""),
            authenticated=self.session.target.authenticated,
            attack_paths=self.session.attack_paths,
            next_action=next_action,
        )

        md = report.to_markdown(include_raw=True)
        js = report.to_json()

        # Destination: explicit arg > evidence run folder > cwd.
        if args:
            from pathlib import Path
            dest = Path(args[0])
            dest.mkdir(parents=True, exist_ok=True)
            md_path = dest / "report.md"
            js_path = dest / "report.json"
            md_path.write_text(md, encoding="utf-8")
            js_path.write_text(js, encoding="utf-8")
        elif self.session.evidence is not None:
            md_path = self.session.evidence.write_text("report.md", md)
            js_path = self.session.evidence.write_text("report.json", js)
        else:
            from pathlib import Path
            md_path = Path("report.md")
            js_path = Path("report.json")
            md_path.write_text(md, encoding="utf-8")
            js_path.write_text(js, encoding="utf-8")

        print(f"Report written:\n  {md_path}\n  {js_path}")

    def cmd_status(self, args: list[str]) -> None:
        """Show session status."""
        print()
        print("Session Status:")
        print(f"  Target: {self.session.target.host}")
        print(f"  Checks run: {len(self.session.check_results)}")
        print(f"  Capabilities: {len(self.session.capabilities)}")
        print(f"  Attack paths: {len(self.session.attack_paths)}")
        if self.session.state_path:
            print(f"  State file: {self.session.state_path}")
        print(f"  Modified: {self.session.modified}")
        print()

    def cmd_exit(self, args: list[str]) -> None:
        """Exit the console."""
        self.running = False
        print("Exiting...")
