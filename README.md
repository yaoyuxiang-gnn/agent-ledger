<h1 align="center">agent-ledger</h1>

<p align="center"><b>When an AI agent hands work to another AI agent, who authorised it — and who answers for the result?</b><br>
There is no shared record of what agents did, on whose authority. That is a ledger problem, so this is a ledger.</p>

<p align="center">
<code>pip install ai-agent-ledger-py</code> &nbsp;·&nbsp; zero dependencies &nbsp;·&nbsp; no API key needed &nbsp;·&nbsp; Python 3.10+<br>
<sub><a href="README.zh-CN.md">中文说明</a></sub>
</p>

```console
$ al demo

▎6. Settling up — receipts all the way down

program-coordinator    completed  $0.0200  rcpt_1790775390758_6314f873
   └─ legal-review           completed  $0.3500  rcpt_1790775390759_944db8e4
      └─ localization           completed  $0.1200  rcpt_1790775390760_38d127ec

  chain length      3 hops
  total cost        $0.4900
  violations        none
  answerable to     urn:principal:northwind.internal:dana
```

Three agents, two organisations, one question answered: **that work traces back to Dana.**

`al demo` runs the whole thing **offline** — no network, no API key, no account. Every
code path it exercises is the real one.

> **Jump to:** [The problem](#the-problem) · [See it work](#see-it-work) · [Install](#install) ·
> [Using it](#using-it) · [What it guarantees](#what-it-guarantees) · [Something went wrong?](#something-went-wrong) ·
> [How it works](#how-it-works) · [Design](docs/DESIGN.md) · [Security](SECURITY.md)

---

## The problem

Two standards already solved the easy halves.

**[ARD](https://github.com/ards-project/ard-spec)** (Agentic Resource Discovery, v0.91) is how
agents are described, published and searched across federated registries — backed by Google,
Microsoft, Hugging Face, AWS, Cisco, GitHub, Nvidia, Salesforce and Snowflake.
**[A2A](https://github.com/a2aproject/A2A)** is how they talk.

Then ARD's own integration example stops, deliberately, at this sentence:

> "The orchestrator now has both capabilities and can proceed to invoke them using their
> respective protocols."

That is where the spec hands off. And ARD says so itself: authentication is **delegated**, trust
evaluation is **fully decoupled** from its relevance score, and the protocol wrapper request
format is **"pending further definition"**.

So the ecosystem can *find* an agent and *call* it, but produces nothing that says:

- **which principal** authorised this work, and through which chain of hops
- **what scope** each hop was granted — capabilities, budget, deadline
- **whether any hop exceeded that scope**
- **who is answerable** when the result is wrong

`agent-ledger` is that missing layer. It implements ARD for discovery rather than
reinventing it, speaks A2A for execution, and owns the part both leave open — using the standards
rather than competing with them.

## See it work

Ranking that remembers. Nothing here is a rule someone wrote — the ledger changed the answer:

```console
▎8. Routing that remembers

  Before — nobody has a history yet:
    Localization Agent           ███████████████··· 0.845
    TranslatePro (partner)       ██████████████···· 0.768
    BargainLLM                   ████████████······ 0.658

  After — the localisation agent overran its budget twice:
    TranslatePro (partner)       ██████████████···· 0.768  ─   reputation=0.50
    Localization Agent           ██████████████···· 0.753  ▼-0.092   reputation=0.13
    BargainLLM                   ████████████······ 0.658  ─   reputation=0.50

  No rule was written. The ledger did the ranking.
```

An agent that **overran its budget** is penalised harder than one that plainly failed, because a
failure you can see and an overrun you cannot: the work reports success while having exceeded the
authority granted. That is a governance breach, not bad luck.

And refusals are recorded, not swallowed — "why did nothing happen" is an audit question too:

```console
$ al verify --ledger grid.jsonl
OK: 7 receipt lines verified; 7 signed

$ al verify --ledger grid.jsonl --sign-key-env AL_KEY --require-signature
FAILED: 1 tampered (line 3 (rcpt_1790775390758_6314f873))
  tampered: line 3 (rcpt_1790775390758_6314f873)
```

## Install

```bash
pip install ai-agent-ledger-py    # zero runtime dependencies, Python 3.10+
```

The console scripts are `al` and `agent-ledger`, so `al demo` runs the whole thing offline.
Without installing anything, `uvx --from ai-agent-ledger-py al demo` does the same.

> **One naming wrinkle, stated up front.** The *distribution* is
> `ai-agent-ledger-py`, because `agent-ledger` on PyPI belongs to an unrelated
> project. Nothing else moved: the import is still `agent_ledger`, the commands are
> still `al` and `agent-ledger`, and the repository is still
> [agent-ledger](https://github.com/yaoyuxiang-gnn/agent-ledger). Only the string
> you pass to `pip` differs.

### From source

```bash
git clone https://github.com/yaoyuxiang-gnn/agent-ledger
cd agent-ledger
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
al demo
```

Use a virtual environment, not the system interpreter. `pip install -e .` writes console scripts
into the interpreter's `Scripts`/`bin`, and on Windows a stock python.org install is
Administrator-owned and not writable — pip then fails with a confusing
`[WinError 2] The system cannot find the file specified: ...al.exe.deleteme`, which is
file-not-found rather than access-denied and reads like a build error. A venv avoids it entirely.

**Optional extras.** The core has **no runtime dependencies at all**. Signing with Ed25519 — the
only option a third party can verify without being able to forge — needs a library, so it is an
extra rather than a dependency:

```bash
pip install 'ai-agent-ledger-py[sign]'   # cryptography, for Ed25519 receipts
```

## Using it

### As a library

```python
from agent_ledger import Grid, Task

grid = Grid(
    registries=["https://registry.example.com/api/v1/search"],
    domains=["partner.example.com"],          # static /.well-known/ard.json
)

outcome = grid.dispatch(
    Task(
        intent="review the vendor data processing agreement",
        required_capabilities=["contract_review"],
        issued_by="urn:principal:acme.com:dana",
        budget_usd=0.50,
    )
)

if outcome.ok:
    print(outcome.delegation.delegate.display_name)
    print(outcome.receipt.digest())          # sha256 over the canonical receipt
else:
    print("refused:", outcome.reason)        # refusals are results, not exceptions
```

With no `executor` configured the delegation is placed and receipted as `pending` and nothing is
invoked — `outcome.receipt` is that issuance receipt. Pass an executor to carry the same call
through to settlement.

### As a command line

```bash
# Discover through ARD
al find "review a contract" --registry https://registry.example.com/api/v1/search

# Place work, with a budget ceiling and a governed ledger
al delegate "review the DPA" -c contract_review \
    --domain partner.example --budget 0.50 --ledger grid.jsonl

# Inspect the chain of custody
al audit --ledger grid.jsonl

# Re-check every digest, chain link and signature
al verify --ledger grid.jsonl
```

`registry.example.com` is a placeholder — point it at a real ARD registry, or at a domain serving
`/.well-known/ard.json` via `--domain`. `al demo` needs neither, which is why it is the place to
start.

**All eight commands:**

| Command | What it does |
|---|---|
| `al demo` | the whole project in 30 seconds, offline, no key |
| `al find` | discover agents through ARD |
| `al delegate` | place a task with the best eligible agent |
| `al audit` | show delegation chains from a ledger |
| `al verify` | re-check every digest, chain link and signature |
| `al policy` | show the built-in policy presets |
| `al bundle` | export or verify a signed receipt bundle |
| `al conform` | check a manifest, a publisher or a registry against ARD |

### Real A2A execution

An A2A executor ships. It fetches the Agent Card, drives `SendMessage` / `SendStreamingMessage` /
`GetTask` / `CancelTask`, and records what happened on the receipt:

```python
from agent_ledger import A2AExecutor, BearerCredential, Grid

grid = Grid(
    registries=[...],
    executor=A2AExecutor(
        credential=BearerCredential(token, reference="spiffe://acme.com/agents/grid")
    ),
)
outcome = grid.dispatch(task)
print(outcome.receipt.execution.task_ref)        # the agent's own id for the work
print(outcome.receipt.execution.state)           # TASK_STATE_COMPLETED, verbatim
print(outcome.receipt.execution.credential_ref)  # a reference, never the secret
```

**The mapping is the interesting part.** A2A has states this library has no equivalent for, because
a delegation is either outstanding or settled. Two of them —
`TASK_STATE_INPUT_REQUIRED` and `TASK_STATE_AUTH_REQUIRED` — map to `accepted` with `ok=True`,
deliberately: work waiting on the **principal** is not a failure of the delegate, and reporting it
as one would cost the agent reputation for a question nobody has answered while releasing a budget
commitment that is still outstanding. Unknown states fail rather than succeed.

### Policy that says no, and says why

```python
from agent_ledger import Policy

policy = Policy.ceilinged(budget=0.50, chain=2.00, depth=3)
policy = policy.with_(
    denied_publishers=frozenset({"cheapapi.io"}),
    allowed_publishers=frozenset({"acme.com", "partner.example"}),
)
grid = Grid(policy=policy, ledger=ledger)
```

Presets: `Policy.open_grid()`, `Policy.ceilinged()`, `Policy.zero_trust()`. Custom rules are plain
functions over `RuleContext` — no DSL to learn, no fork required.

Policy counts **commitments**, not just spend. The naive check is `spent > cap`, and it is wrong:
five concurrent delegations that are each under the cap can collectively be far over it.

### Handing evidence to another organisation

A shared mutable store is the wrong answer, and this project argues against one for the same reason
it argues against a shared reputation feed: it is a central operator and a censorship surface.
What two organisations actually need is to show each other evidence each can check without
trusting the other's storage.

```bash
al bundle export --ledger grid.jsonl --ledger-id acme-prod --out work.json
# Send work.json, and send its head over a channel you already trust.
al bundle verify work.json --keyring their-keys.json --expect-head sha256:...
```

A bundle is a ledger excerpt plus a manifest — the ledger was already the right serialisation, so
there is no second format to drift. Verification runs the *same* checks a local ledger gets.

### Checking ARD conformance

```bash
al conform manifest ./.well-known/ard.json
al conform publisher partner.example
al conform registry https://registry.example.com/api/v1
al conform --official manifest ard.json     # the spec's own CLI, when on PATH
```

### Seeing it as a trace

A receipt already carries a start time, a status, and — via `parent_receipt_id` — exactly the
parent-child relation a trace needs. So a delegation chain **is** a trace, and no instrumentation
is required to produce one:

```python
from agent_ledger import ledger_to_otlp, post_otlp

post_otlp(ledger_to_otlp(grid.ledger, service_name="agent-grid"), "http://localhost:4318/v1/traces")
```

## What it guarantees

Four layers, and each answers a different question. The table is the honest one, because a security
claim that overstates itself is worse than no claim:

| Layer | Proves | Does not prove |
|---|---|---|
| `digest` | a line was not **edited** | anything about a line that is gone |
| `prev` chain | a line was not **deleted, reordered or spliced in** | who wrote it |
| signature | a **specific key** wrote the line | that the key belongs to the principal named |
| **pinned keyring** | that key belongs to **that principal** | that the principal is who you think |

<details>
<summary><b>What that means in practice — and the three things it does not do</b></summary>

- **A signature names a key. A keyring names a person.** With a pinned keyring, a valid key
  presented under someone else's name is caught — the signature checks out and the *claim* beside
  it does not. Without one, nothing can catch it. That is not a defect; it is the reason the
  keyring exists, and `tests/test_keyring.py` asserts it rather than describing it.
- **HMAC cannot be checked by a third party.** It is symmetric, so every verifier is also a forger:
  evidence *within* one trust domain, not *between* organisations. The core ships it because it
  needs no dependency. For third-party verifiability use Ed25519 (`pip install
  'ai-agent-ledger-py[sign]'`), where a public key verifies and cannot forge.
- **Tail truncation is detectable only against a published head.** A shortened prefix is a perfectly
  consistent chain, so nothing inside the file can notice. `al verify` prints the head;
  `--expect-head` checks one you published earlier. The publication *is* the fix.
- **What a keyring does not answer** is how the key-to-principal mapping got there. Today it is a
  file an operator wrote. Obtaining it from a SPIFFE bundle endpoint, a DID document or an
  enterprise PKI is the next step, and the one place this project should adopt an existing standard
  rather than define anything.

</details>

Sign every receipt — the secret comes from the environment, never `argv`, because an `argv` value
is visible in `ps` and lands in shell history:

```bash
export AL_KEY=...                     # from your secret manager
al delegate "review the DPA" -c contract_review --domain partner.example \
    --ledger grid.jsonl --ledger-id acme-prod \
    --sign-key-env AL_KEY --key-id acme-2026 --signer urn:principal:acme.com:grid

al verify --ledger grid.jsonl --ledger-id acme-prod \
    --sign-key-env AL_KEY --keyring trust.json --require-signature
al verify --ledger grid.jsonl --json | jq -r .chain_head   # publish this
al verify --ledger grid.jsonl --expect-head sha256:...     # and check it later
```

## Something went wrong?

**`pip install -e .` failed with `[WinError 2] ... al.exe.deleteme` on Windows.**
You installed into the system interpreter. `C:\PythonXX\Scripts` is Administrator-owned and not
writable by a normal user, so pip cannot create the console script — and the error it reports is
file-not-found rather than access-denied, which is why it reads like a build error. Create a venv
(see [Install](#install)) and retry. If `import agent_ledger` works but `al` does not exist,
that is the same problem: the package landed in `site-packages` and the script did not.

**`al find` says `no entries found`.**
The default examples point at `registry.example.com`, which is a placeholder and does not resolve.
Pass a real registry with `--registry`, or a domain serving `/.well-known/ard.json` with `--domain`.
`al demo` needs neither.

**`al verify` says `no such ledger file`.**
A typo'd path used to report `OK: 0 receipt lines verified` and exit 0 — the one failure an operator
is least likely to double-check. It now fails, deliberately.

**`al verify` says `checked against ledger identity 'agent-ledger/default-ledger'`.**
The ledger identity is **not stored in the file**, on purpose: recording it would let a forger
supply their own, and binding it is what stops a receipt being replayed into another ledger. So a
verifier that was not told the identity checks against the wrong thing and sees a broken chain *and*
a bad signature at once — which reads as corruption rather than as a missing input. Pass
`--ledger-id` with the identity the ledger was written under.

**`al verify` reports `bad signatures` on a ledger I know is signed.**
Same cause. Also check you are passing the right `--sign-key-env`, and that `--key-id` matches the
one used at write time.

**`al verify` passes, but I deleted a line from the ledger.**
If the deleted line was at the **end**, and you did not publish the head, nothing can notice — a
shortened prefix is a perfectly consistent chain. This is a documented limit, not a bug. Publish
`chain_head` and use `--expect-head`.

**`al bundle verify` says a line is signed by an untrusted key.**
A bundle is evidence offered by someone else, so `--require-signature` is the default and nothing
verifies without `--keyring`. If you mean to accept an unsigned bundle, `--allow-unsigned` — but it
then proves nothing about who wrote it.

**Signing refuses to write a keyring with `cannot be distributed`.**
You are trying to persist an HMAC verifier. An HMAC "public key" *is* the secret, so writing one
would turn a verification artefact into a signing capability every reader shares. Use Ed25519 for
anything a third party verifies, or keep HMAC verification in the process that holds the secret.

**My registry's search results crash `al find`.**
They should not, and if they do it is a bug worth reporting — ARD §5.3.2 allows a result to omit
`url`, and that case is covered by `TestLeanSearchResults`. Include your registry's response shape.

**Still stuck?** Open an [issue](https://github.com/yaoyuxiang-gnn/agent-ledger/issues) with
the output of `al demo`, your Python version and your OS. If it is about routing, include the
candidate list from `grid.candidates(task)` — the signals are there precisely so routing bugs can be
diagnosed without guesswork.

## How it works

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

The middle box is the project. The bottom two are standards that already exist and that this
deliberately does not compete with.

**The receipt is the unit of accountability.** A log line records that something happened. A
receipt records *that it was authorised, by whom, within what limits, and how it ended* — and it can
be checked:

```
Receipt
├─ delegation_id        which delegation this settles
├─ parent_receipt_id    ──▶ the previous hop  (this is what makes a chain)
├─ delegated_by         who authorised it
├─ delegate             who received it
├─ scope_digest         sha256 of the authority granted
├─ budget_usd / cost_usd
├─ outcome              pending | accepted | completed | failed | revoked
├─ execution            remote task id, remote state, credential reference
├─ signature / key_id   who wrote this line
└─ digest               sha256 over the canonical form of all of the above
```

Three decisions worth knowing:

- **One stable identity per delegation.** A delegation keeps the same `receipt_id` for its whole
  life; status transitions append new lines under that id. That is what lets a chain be reassembled
  *mid-flight* rather than only after everything settles.
- **Sign the digest; never digest the signature.** The signature lives beside the digest in the
  stored envelope, never inside the digested body — otherwise every ledger ever written would start
  failing verification, and there is no version marker to explain why.
- **Cost is recorded per delegate, never rolled up.** A parent that sub-delegates does not absorb
  its children's costs. Rolling up once made a three-hop chain report `$1.08` for work that cost
  `$0.49`, and every parent looked like it had overrun.

Want the reasoning behind all of it, including where the design is wrong?
→ **[docs/DESIGN.md](docs/DESIGN.md)**.

## Status

Alpha, and honest about it. **578 tests**, `ruff` clean, and `al demo` runs offline on every
commit.

**What works:** discovery (ARD), matching, policy, delegation, receipts, chains, verification,
signing, bundle exchange, A2A execution over JSON-RPC (including streaming and cancellation),
adapters, OTLP export, ARD conformance checking.

**What does not, and is loud about it:**

- **Keyring resolution.** A pinned keyring binds a key to a principal. *Obtaining* that mapping
  from a SPIFFE bundle endpoint, a DID document or an enterprise PKI is not built — today it is a
  file an operator writes.
- **Adapters are documented mappings, not verified integrations.** AGNTCY, ClawTeam and OpenClaw
  each have their own evolving formats, and none of their specifications is vendored here. Each
  adapter maps declared field names, reports an explicit confidence, and says so in its own
  `summary`. Replacing a guessed name with an observed one is a one-line change in one place.
- **A2A push notifications** and the **gRPC / `HTTP+JSON` bindings**. `require_supported_binding`
  names the gap before anything is invoked rather than sending a request in the wrong protocol.
- **Bundle exchange has a format but no transport.** A bundle verifies cryptographically; moving
  one between organisations is still a file someone emails.
- **No public ARD registry is bundled.** `al demo` runs against a simulated federation.

**Not a claim we make:** that this replaces ARD or A2A, that a signature alone proves authorship,
or that a ledger proves more than the table in [What it guarantees](#what-it-guarantees) says.

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)**. The one command to run before you push:

```bash
python -m pytest && python -m agent_ledger.cli demo --no-color
```

Tests need no install step — `tests/conftest.py` puts `src` on `sys.path`, so a fresh clone runs
them immediately:

```bash
git clone https://github.com/yaoyuxiang-gnn/agent-ledger
cd agent-ledger
python -m pytest
```

Three promises CI enforces: **no runtime dependencies** (the `dependencies` list must stay empty),
**tests never touch the network** (everything goes through the `Transport` protocol), and **the demo
stays offline and key-free**.

**[SECURITY.md](SECURITY.md)** is worth reading before probing anything: a defect in the
accountability claims *is* a security issue even when nothing crashes, and it lists what is already
documented so the tracker does not fill with reports the limitations already anticipate.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

<sub>**Keywords:** accountable AI agents · agent delegation · agent handoff · agent discovery · ARD ·
Agentic Resource Discovery · A2A · Agent2Agent · capability matching · intent routing · multi-agent
provenance · task routing · agent registry · MCP · AI agent governance · audit trail · SCITT</sub>
