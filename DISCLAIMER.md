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

Domainerator is a **detection and guidance** tool. It does not exploit
vulnerabilities on its own: it never sprays passwords, requests certificates,
coerces authentication, or performs DCSync. It reports the routes and the exact
operator commands so a human decides what to run. The built-in `--scope`
control is provided to help confine testing to an authorized target range, but
scoping is a safety aid and **not** a substitute for proper authorization.
