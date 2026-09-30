# Design

Why the library is shaped the way it is, and where the shape is wrong.

## The layering

```
┌──────────────────────────────────────────────────────────────┐
│  Principal  (a person, or an agent acting for one)           │
└───────────────────────────┬──────────────────────────────────┘
                            │  Task(intent, capabilities, budget)
┌───────────────────────────▼──────────────────────────────────┐
│  agent-ledger                                         │
│                                                              │
│   match ──▶ decide ──▶ delegate ──▶ receipt ──▶ chain        │
│     │         │            │           │          │          │
│  reputation  policy     authority   digest    lineage        │
└───────────────────────────┬──────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌──────────────────┐                  ┌──────────────────┐
│  ARD             │                  │  A2A / MCP       │
│  discovery       │                  │  execution       │
│  (implemented,   │                  │  (behind the     │
│   not replaced)  │                  │   Executor proto)│
└──────────────────┘                  └──────────────────┘
```

The middle box is the project. The bottom two are standards that already exist
and that this deliberately does not compete with.

## Why ARD is implemented rather than reinvented

ARD v0.91 specifies how agentic resources are described, published and searched
across federated registries, with backing from Google, Microsoft, Hugging Face,
AWS, Cisco, GitHub, Nvidia, Salesforce and Snowflake, and with six production
reference registries already deployed.

Building a competing discovery layer would mean:

- forfeiting interoperability with every registry that adopts ARD
- maintaining a namespace system ARD already anchors to DNS (Appendix C)
- competing on a problem that is now a solved, standardised commodity

So `ard.py` implements the specification — static manifests, `POST /search`,
federation modes, publisher-authority binding — and stops exactly where ARD
stops.

## Where ARD stops, and why that is the whole point

This is not an interpretation. The specification says so:

| ARD text | What it leaves open |
|---|---|
| §3.6 "**Authentication is Delegated**… not the discovery layer" | identity and authority |
| §6 example ends "the orchestrator now has both capabilities and can proceed to invoke them" | task lifecycle, delegation semantics, result path |
| §5.3.5 "the request format… is **pending further definition**" | protocol wrappers |
| §5.3.2 "**out of scope for this draft**" (retrieve entry by identifier) | entry resolution |
| §5.3.2 score "MUST NOT be interpreted… as a trust, compliance, or safety rating; trust evaluation is **fully decoupled**" | trust evaluation |

Those five gaps are the product surface. Everything in this library exists to
close one of them.

## The receipt is the unit of accountability

A log line records that something happened. A receipt records *that it was
authorised, by whom, within what limits, and how it ended* — and it can be
checked.

```
Receipt
├─ delegation_id        which delegation this settles
├─ parent_receipt_id    ──▶ the previous hop  (this is what makes a chain)
├─ delegated_by         who authorised it
├─ delegate             who received it
├─ scope_digest         sha256 of the authority granted
├─ budget_usd / cost_usd
├─ outcome              pending | accepted | completed | failed | revoked
└─ digest               sha256 over the canonical form of all of the above
```

Three decisions matter here:

**One stable identity per delegation.** A delegation keeps the same
`receipt_id` for its whole life. Status transitions append new lines under that
id; the log keeps every transition and the view keeps the latest. This is what
lets a chain be reassembled *mid-flight* rather than only after everything has
settled. An earlier revision issued receipts only at settlement, and child
delegations surfaced as orphaned chains.

**Parent linkage by receipt id, resolved at issue time.** A delegation is
receipted the moment it is issued, so a child issued later always has a parent
to point at.

**Digest over a canonical form.** `canonical_json` sorts keys and uses tight
separators, so two processes on two machines agree on the bytes. Without that,
verification would depend on dictionary ordering.

## Reputation: the signal a registry cannot provide

An ARD registry can tell you an agent *claims* a capability. It cannot tell you
the agent blew its budget last Tuesday — and it should not, because a shared
reputation feed is a central point of failure and a censorship surface.

Instead, each installation's ledger seeds its own `ReputationIndex`. Three
consequences:

- The signal is **evidence, not gossip**. It reflects only delegations this
  installation actually issued.
- It is **self-correcting**. A rule does not have to be written for a badly
  behaving agent to lose work.
- It is **bounded**. Below `min_samples` an agent stays at the neutral prior of
  `0.5`, so one bad afternoon cannot permanently sideline it.

The score starts at neutral and moves with observation:

```
score = 0.5 + 0.5·success_rate − 0.5·failure_rate − 0.8·overrun_rate
```

clamped to `[0, 1]`. An overrun is penalised harder than a failure because a
failure is visible and an overrun is not: the work reports success while having
exceeded the authority granted. That is a governance breach, not bad luck.

## Policy counts commitments, not just spend

The naive budget check is `spent > cap`. It is wrong. Five concurrent
delegations that are each under the cap can collectively be far over it.

`committed_for_task` sums the outstanding budget of delegations in `pending` or
`accepted`, and `RuleContext.projected_spend` adds it to realised spend. The
check is on the projection.

## Cost is recorded per delegate, never rolled up

Each receipt carries what *that* delegate spent. A parent that sub-delegates
does not absorb its children's costs.

This was a bug before it was a principle: rolling costs up meant a three-hop
chain reported `$1.08` for work that cost `$0.49`, and every parent looked like
it had overrun. The chain total is the sum of the hops, and only the sum.

## Refusals are recorded

`Grid.delegate` writes a receipt for a refused delegation, against a synthetic
`urn:air:refused` delegate, carrying the rule that refused it.

"Why did nothing happen" is an audit question. A system that only records its
actions cannot answer it.

## Limitations

Stated plainly, because a design document that only lists strengths is
marketing. This is the honest state of it, and `SECURITY.md` keeps a matching
list of what is already known so the issue tracker does not fill with it.

1. **A keyring is pinned, not resolved.** A receipt carries a `signer` claim and a
   pinned `KeyRing` checks it, so a valid key presented under another principal's
   name is caught — that much is real. What is *not* answered is how the mapping
   got there: today it is a file an operator wrote. Obtaining it from a SPIFFE
   bundle endpoint, a DID document or an enterprise PKI is the next step, and the
   one place this project should adopt an existing standard rather than define
   anything. Until then, the trust anchor is a file, and its provenance is
   whatever process put it there.
2. **HMAC is not third-party verifiable, by construction.** It is symmetric, so
   every verifier is a forger: evidence *within* a trust domain, not *between*
   organisations. Ed25519 (the `[sign]` extra) is the only option where
   verification does not confer the ability to forge. The core ships HMAC anyway
   because it needs no dependency, and because a wrong claim about which of the
   two you hold is worse than either.
3. **Truncation of the tail is undetectable from inside the file.** A shortened
   prefix is a perfectly consistent chain. `--expect-head` checks against a value
   published earlier, and that publication *is* the fix — nothing in the file can
   substitute for it.
4. **Bundle exchange has a format but no transport.** A bundle verifies
   cryptographically and says honestly what it cannot prove; moving one between
   organisations is still a file someone emails.
5. **Shared storage is not a trust boundary.** `LedgerBackend` has in-process,
   JSONL and SQLite implementations, and SQLite enforces append-only with
   triggers. But nothing attributes a line to a writer except a signature, so a
   shared log whose writers are not all pinned is a forgeable shared log. That is
   why the cross-organisation answer is bundles, not a shared store.
6. **Adapters are field mappings, not integrations.** AGNTCY, ClawTeam and
   OpenClaw have their own evolving formats, none vendored here, so each adapter
   maps declared field names and reports an explicit `confidence`. Replacing a
   guessed name with an observed one is a one-line change in one place.
7. **The default matcher is lexical.** Stemmed token overlap is a proxy for
   semantic similarity, not a substitute. `Scorer` exists to swap it out.
8. **Reputation is not portable.** Each installation learns alone. That is
   deliberate — a shared feed would be a central point of failure and a censorship
   surface — but it means a new installation starts blind. Signed bundles make a
   middle path conceivable, and it deserves thought rather than a bolt-on.
9. **Depth limits are the only loop guard.** An agent that delegates sideways
   rather than downward is not caught by a depth check.
10. **A2A covers request/response, streaming and cancel; not push or gRPC.**
    `require_supported_binding` names an unimplemented binding before anything is
    invoked, so the gap is loud rather than silent.

## What would change the design

If ARD adds a delegation layer, most of this becomes an implementation of it —
which would be the right outcome, and the reason `ard.py` is kept separate from
`router.py`.
