# Authorized Use Only

Domainerator is a tool for **authorized** security assessments of Active
Directory environments. It enumerates configuration weaknesses and maps
privilege-escalation paths so that defenders and authorized penetration testers
can understand and remediate them.

By using this software you agree that:

- You will only run it against systems you **own** or for which you have
  **explicit, written authorization** to test (e.g. a signed engagement scope,
  rules of engagement, or equivalent).
- You are solely responsible for complying with all applicable laws,
  regulations, and contractual obligations in your jurisdiction and the target
  environment's jurisdiction.
- Unauthorized access to computer systems is illegal in most jurisdictions
  (for example, the U.S. Computer Fraud and Abuse Act and similar laws
  elsewhere). Misuse of this tool may carry civil and criminal penalties.

The authors and contributors provide this software "as is", without warranty of
any kind, and accept **no liability** for misuse or for any damage arising from
its use. See `LICENSE` for the full terms.

## Design intent

Domainerator is a **detection and guidance** tool. It enumerates vulnerabilities
and maps attack paths, presenting commands for each exploitation step. The
interactive console can guide operators through execution with confirmation
prompts, but all exploitation actions require explicit operator approval. The
tool never automatically sprays passwords, coerces authentication, requests
certificates, or performs DCSync without user confirmation.

The console's `relay` command can orchestrate active exploitation — it starts a
relay listener and triggers authentication coercion against a victim host — but
only after the operator reviews the exact commands and explicitly confirms. This
is loud, intrusive activity: run it only with authorization that covers the
victim host, and only within your defined `--scope`. Domainerator ships no
exploit code of its own; `relay` and every other step invoke external tools
(ntlmrelayx, coercer, certipy, netexec, impacket, etc.) that you install
yourself.

The built-in `--scope` control is provided to help confine testing to an
authorized target range, but scoping is a safety aid and **not** a substitute
for proper authorization.

When `--output-dir` is used, Domainerator writes evidence files and reports that
can contain sensitive engagement data (recovered credentials, hashes, directory
information). Passwords passed on the command line are redacted from recorded
commands, but raw tool output may still contain secrets. Treat the output folder
as sensitive: store it securely, and handle and dispose of it per your rules of
engagement.
