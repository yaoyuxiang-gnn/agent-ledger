# Security policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/yaoyuxiang-gnn/agent-ledger/security/advisories/new).
Please do not open a public issue for anything exploitable.

Include what you need to make it reproducible: the version, a minimal script or
ledger, and what an attacker gains. If you have a working exploit, say so — it
changes the priority.

There is no bug bounty. There is an acknowledgement in the advisory and in
`CHANGELOG.md` if you would like one.

## What is in scope

This library makes claims about accountability, so a defect in those claims is a
security issue even when nothing crashes. In scope, and taken seriously:

- **Falsifying a receipt or a ledger.** Editing a line and having `al verify`
  report success; deleting a line undetectably; replaying a receipt from one
  ledger into another; a forged receipt attributed to a third party.
- **Escaping policy.** Any way to place work, exceed a budget, exceed a chain
  ceiling, exceed the depth limit, or reach a denylisted publisher or agent when
  the policy says otherwise.
- **Corrupting the audit trail.** Input that makes `al verify` or `al audit`
  crash, hang, or report a healthier state than reality — including a truncated
  file, a hostile line, or a missing path.
- **Defeating a signature or a keyring.** Forging a signature; having a valid
  signature accepted under a principal the pinned keyring does not associate with
  that key; getting a revoked key accepted; a bundle that verifies when it should
  not.
- **Untrusted discovery input.** A malicious or merely broken ARD registry or
  manifest causing code execution, unbounded resource use, or a crash outside the
  contained discovery path.
- **Credential handling.** The library must never write a secret into a receipt,
  a ledger, a bundle, or a keyring. A path that does is a finding regardless of
  whether it is exploitable.

## What is already known, and therefore not a vulnerability

These are documented, not discovered. Reporting them is welcome as a
contribution, but they are not advisories:

| Known limitation | Where it is stated |
|---|---|
| Receipts are signed, but a signature names a **key**, not a person; the key-to-principal mapping is a pinned file an operator supplies | `README.md` → What it guarantees · `docs/DESIGN.md` → Limitations |
| **HMAC cannot be verified by a third party** — it is symmetric, so every verifier is a forger | `README.md` → What it guarantees · `agent_ledger/signing.py` |
| **Tail truncation** is undetectable from inside the file; `--expect-head` against a published head is the only fix | `README.md` → Something went wrong |
| A **full, consistent rewrite** by someone holding the file and the key verifies clean | `docs/DESIGN.md` → Limitations |
| A **bundle is a claim about a subset** of a ledger; completeness needs a trusted head | `README.md` → How it works · `bundle.py` |
| **Adapters are field mappings**, not integrations verified against live deployments | `README.md` → Status · `adapters.py` |
| The default matcher is **lexical**, a proxy for semantic similarity | `docs/DESIGN.md` → Limitations |
| Reputation is **not portable** between installations, by design | `docs/DESIGN.md` → Limitations |
| A2A **push notifications and the gRPC/REST bindings** are not implemented, and raise | `README.md` → Status · `a2a.py` |

A report that one of these is true will be closed with a pointer to the row
above. A report that one of them is **worse than described** — a concrete attack
the documentation does not anticipate — is a real finding and will be treated as
one.

## Design context worth knowing before you probe

Three decisions shape what is and is not a bug here:

- **The digest is not a signature, and a signature is not an identity.** A digest
  proves a line was not edited. A signature proves a key wrote it. Only a pinned
  keyring connects that key to a principal. Each layer is documented with what it
  does *not* prove, and claiming more than the table says is itself a bug.
- **Denials are data.** A refusal is a `PolicyDecision` carrying the rule that
  produced it, and it is written to the ledger. A refusal that leaves no trace is
  a bug; a refusal that is merely inconvenient is not.
- **The CLI never takes a secret as an argument.** `--sign-key-env` reads from
  the environment because an `argv` value is visible in `ps` and lands in shell
  history. A change that accepts a key on the command line would be rejected.
