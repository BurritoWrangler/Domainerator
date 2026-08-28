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
  signing / channel-binding relay exposure, WebDAV/WebClient discovery, and AS-REP
  roasting (with a userlist).
- **Authenticated** — given a domain, username, and password (or NT hash), it adds
  password-policy review, local-admin detection, Kerberoasting, delegation
  enumeration, active **RBCD enumeration**, **coercion-surface detection**
  (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce), **noPac** (CVE-2021-42278/42287),
  MachineAccountQuota, a full AD CS template audit (**ESC1–ESC16**), and
  **BloodHound-based ACL path analysis** (GenericAll, WriteDacl, ForceChangePassword,
  AddMember, shadow credentials, RBCD, GPO abuse, DCSync, more).

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

## Detection and guidance only

Domainerator **does not exploit anything**. It enumerates, correlates, and reports
the routes to Domain/Enterprise Admin, printing the exact operator command for each
step so **you** decide what to run. It never sprays passwords, coerces authentication,
requests certificates, or performs DCSync on its own.

> Intended for authorized security testing only. Run it only against systems you have
> explicit written permission to assess.

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

### Multiple targets & concurrency

Scan a host list concurrently (respecting `--scope`), correlating findings from all
hosts plus domain-wide BloodHound data into one path analysis:

```bash
domainerator -T hosts.txt -d corp.local -u alice -p 'S3cret!' \
  --workers 8 --scope engagement.scope -o report.md
```

`hosts.txt` is one IP/host per line (`#` comments allowed). `--target` and `--targets`
can be combined. If any target (or `--dc-ip`) is outside `--scope`, the run aborts before
touching anything.

### Trustworthy results: inconclusive state & tool inventory

A check that runs but whose output shows a connection/auth failure — or whose expected
signal is absent — is reported as **inconclusive**, not clean. This prevents a parser
miss or an unreachable host from being read as "not vulnerable". The report also records
a **tool inventory** (detected versions of nxc/certipy/impacket/bloodhound-python) so a
parser miss can be correlated with a tool-version change.

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
| `-t, --target` | Target host/IP, usually a DC |
| `-T, --targets` | File of targets (one per line) to scan concurrently |
| `-d, --domain` | AD domain (FQDN) |
| `--dc-ip` | Domain controller IP (Kerberos/AD CS) |
| `-u, --username` | Domain username (enables authenticated checks) |
| `-p, --password` | Password (omit to be prompted) |
| `-H, --hash` | NT hash instead of a password |
| `-k, --kerberos` | Use Kerberos authentication |
| `--userlist` | User list file for unauthenticated AS-REP roasting |
| `--skip-unauth` / `--skip-auth` / `--skip-adcs` | Skip a check category |
| `--bloodhound` | Collect BloodHound data with `bloodhound-python` (needs creds) |
| `--bloodhound-output` | Directory for collection output (default `bloodhound-output`) |
| `--bloodhound-data` | Ingest existing `.zip` / `.json` / directory of `*.json` |
| `--no-paths` | Disable attack-path correlation |
| `--max-path-depth` | Max steps in a correlated path (default 8) |
| `--scope` | Scope file (one IP/CIDR per line); confines all testing |
| `--workers` | Concurrent workers when scanning multiple targets (default 5) |
| `--state` | JSON state file: seeds known capabilities, updated with findings |
| `--timeout` | Per-command timeout in seconds (default 300) |
| `--dry-run` | Show commands without executing |
| `-o, --output` | Write Markdown report to a file |
| `--json` | Write JSON report to a file |
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
│   ├── state.py            # resume/state file (cross-run capabilities)
│   ├── paths.py            # attack-graph model + best-first PathEngine
│   ├── bloodhound.py       # BloodHound-CE collection/ingestion -> PathSteps
│   ├── report.py           # JSON / Markdown / console rendering
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
