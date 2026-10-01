# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.2.1] — 2026-10-01

**The first published release, under a different distribution name.**

`agent-ledger` on PyPI is an unrelated project — an idempotency ledger for tool
calls, owned by somebody else — and PyPI has no mechanism for two projects to
share a name. The 0.2.0 rename therefore could not be completed as intended: the
*project* is still agent-ledger, but the *distribution* is
`ai-agent-ledger-py`.

Nothing a user writes changed:

| | Before | After |
|---|---|---|
| `pip install` | not possible | `ai-agent-ledger-py` |
| Import | `agent_ledger` | `agent_ledger` |
| CLI | `al`, `agent-ledger` | `al`, `agent-ledger` |
| Repository | `yaoyuxiang-gnn/agent-ledger` | unchanged |

The one cost is a string that does not match the repository name, which is
recorded in the README rather than hidden, because a reader who runs
`pip install agent-ledger` and lands on a foreign project deserves to know why
before they file the bug.

### Added — a release path that does not involve a laptop

- **`.github/workflows/release.yml`**, publishing on a published GitHub release
  through PyPI Trusted Publishing (OIDC). No API token is stored anywhere: the
  upload authenticates with a short-lived credential minted for this workflow, in
  this repository, in the `pypi` environment. The job refuses to publish when the
  release tag and the version in `pyproject.toml` disagree — the one mistake that
  cannot be undone, because a version number on PyPI can be yanked but never
  reused.

- **`tools/audit_dist.py`**, the artefact audit that CI's build job used to run
  inline. It now asserts the two things this rename could silently break: that the
  version in the wheel matches `pyproject.toml` *and* `_identity.py` — otherwise
  the `User-Agent` and `--version` advertise a release that does not exist — and
  that `al` and `agent-ledger` are still declared as console scripts. CI and the
  release workflow call the same file, because a release that checks less than CI
  is a release nobody checked.

### Fixed

- **`tools/check_readme.py` could not run from a fresh clone.** It handed the demo
  subprocess a hand-built environment of `NO_COLOR` and `SYSTEMROOT`, which reads
  as harmless isolation but also strips `PYTHONPATH` — the only thing making
  `agent_ledger` importable when the package is not installed. The result was
  `al demo exited 1`, a message that named neither the cause nor the cure. The
  child now inherits this process's environment, and the error quotes the child's
  last line of stderr.
- **`uvx --from` tripped the flag check.** The README's run-it-without-installing
  example was reported as documenting a flag `al` does not accept, because the
  checker cannot tell another tool's flag from a fictional one of ours. The
  exemption is now an explicit list rather than a pattern to decode.

## [0.2.0] — 2026-09-30

**Renamed from `agent-delegate-grid` to `agent-ledger`.** The old name described
one thing the project does; the new one describes what it actually is. The
ledger — append-only, signed, chain-linked, exchangeable — is the product, and
discovery, matching, policy and execution exist to feed it.

This is a breaking release. Every identifier changed:

| | Was | Now |
|---|---|---|
| Distribution | `agent-delegate-grid` | `agent-ledger` |
| Import | `agent_delegate_grid` | `agent_ledger` |
| CLI | `adg` | `al` (and `agent-ledger`) |
| Env var in the docs | `ADG_KEY` | `AL_KEY` |

**The signing format changed with it, deliberately.** The domain separator is
part of the signed payload, so `b"adg-receipt-v1\0"` became
`b"al-receipt-v1\0"` — which means **receipts signed before this release will not
verify**. That is only acceptable because `0.1.0` was never published and no
ledger existed outside a development machine, and it is the last time it can be
done cheaply. After this release the separator is frozen and the project will
need a real migration path, not a rename.

Two smaller improvements made in the same pass:

- **The `User-Agent` is now defined once.** It had been copy-pasted into five
  modules with the version hard-coded as `0.1`, so a release bump would have left
  most of them advertising the old one. It comes from `_identity.py`, which exists
  because putting it in `__init__.py` creates a circular import the moment a
  submodule needs it — and that failure reads as "cannot import name X from a
  partially initialized module", pointing at the importer rather than the cycle.
- **The package description and keywords now say what the project is**: an
  append-only, signed ledger for agent delegations, with `receipts`,
  `transparency-log` and `audit-trail` among the keywords rather than only
  routing terms.

### Changed — the README, rewritten and translated

- **`README.md` is restructured around what a reader wants to know, in the order
  they want it.** It used to open with the gap in the specification; it now opens
  with the question the project answers, shows the demo output that answers it,
  and only reaches architecture after installation and troubleshooting. The
  reasoning lives in `docs/DESIGN.md`, which the README links to rather than
  duplicating.
- **`README.zh-CN.md`**, a full Chinese translation. Technical tokens — ARD, A2A,
  `receipt`, `ledger`, `keyring`, `bundle` — stay in English because they are the
  API names and the strings a reader greps for; translating them would make the
  document harder to use, not easier. Both files link to each other and have the
  same section structure.
- The **"Something went wrong?"** section now answers the real failures this
  project produces, including the Windows `pip install -e .` trap, the
  `no such ledger file` and ledger-identity confusions, "I deleted a line and
  `verify` passed" (a documented limit, with the fix), and why a keyring refuses
  to persist an HMAC key. A README that documents only the happy path is the one
  place a reader cannot check you.
- **`tools/check_readme.py`**, wired into CI. It checks the claims that *can* be
  checked: every `al` command and flag named in either README exists, the quoted
  test count is real, the demo transcript's numbers still appear in real output,
  the zero-dependency promise still holds, and the translation has not fallen
  behind. Documentation drifts in one direction — it describes the version
  someone was proud of — and this is the cheapest guard against that.

### Added — a pinned keyring, so a signature names *who*

- **`KeyRing` now binds a key to a principal, and enforces it.** Signing alone
  answers the wrong question: it establishes a *key*. Accountability needs a
  *who*, and the only bridge is a mapping somebody decided in advance — which is
  why it cannot be derived from the ledger and why an attacker who controls the
  ledger cannot supply it. A receipt now carries a `signer` claim, and a pinned
  keyring checks it. `LedgerIntegrity` gains `principal_mismatch` and `revoked`.
- **Revocation that keeps history attributable.** `KeyRing.revoke` retains the
  pin rather than deleting it. Deleting would turn every historical signature
  into `unknown_key`, which is indistinguishable from a forgery by a key nobody
  has ever seen — and it erases the one thing an investigation needs, which is
  who held the signing key.
- **`PinnedKey.to_json` refuses to serialise a symmetric key.** An HMAC "public
  key" *is* the secret, so writing one would quietly turn a verification artefact
  into a signing capability shared by everyone holding the file. The refusal
  happens at the write, where the mistake is visible, rather than at load time
  where it would look like a problem with the ledger.
- `Ed25519Signer.public_hex`, `from_public_hex`, and a `principal` argument
  throughout, so a trust store is 64 hex characters per key and a verifier holds
  only the public half.
- CLI: `--keyring FILE` on `verify` and `bundle verify`, and `--signer PRINCIPAL`
  on `delegate`.

### Added — A2A beyond request/response

- **`SendStreamingMessage` over SSE**, reduced to its final state rather than
  exposed as a generator: this library needs the terminal state to receipt and
  the accumulated artifact text to hash, and a generator would push the burden of
  knowing when the stream ended onto every caller — the one caller that matters
  being a delegation that must be receipted exactly once. `StreamingTransport` is
  a **separate** protocol from `JsonRpcTransport`, so a transport that cannot
  stream is not forced to stub a method that only raises.
- `cancel_task` / `A2AExecutor.cancel`, returning the state the agent reports
  rather than a bare success — a cancellation is a *request*, and the returned
  state is the only honest answer to "did it stop". Kept separate from `execute`,
  because cancelling is a decision the principal makes and folding it in would
  let a policy change silently cancel remote work.
- `fetch_extended_agent_card`, and `require_supported_binding`, which **names**
  the binding this library does not implement rather than sending a request in
  the wrong protocol. `BINDING_SUPPORT` records which is which; gRPC and
  `HTTP+JSON` raise `UnsupportedBindingError` before anything is invoked.
- The receipt records the binding actually used, so it cannot claim one that was
  never spoken.

### Added — signed receipt bundles

- **`export_bundle` / `verify_bundle`**, which is what "a shared ledger backend"
  should have meant. Two organisations do not need to write to one mutable store;
  they need to show each other evidence each can check without trusting the
  other's storage. A bundle is a ledger excerpt plus a manifest — the ledger was
  already the right serialisation, so no second format exists to drift.
- Verification reuses the local checks by materialising the lines into a
  throwaway ledger. A bundle-specific verifier would be a second home for the
  same class of bug.
- `require_signature` defaults to **True** here and only here. A local ledger may
  legitimately predate signing, so demanding signatures there would declare
  existing users' data corrupt; a bundle is evidence offered *to someone else*,
  so an unsigned one proves nothing and accepting it by default would make the
  exchange decorative.
- **`complete` on the manifest**, because chain linkage makes every line commit
  to its predecessor and a selected subset therefore cannot chain from genesis.
  Re-signing to fix that would need the private key and would destroy the
  evidence. The manifest declares which kind it is, so a receiver can tell "this
  is a subset" from "this bundle's linkage is broken".
- CLI: `al bundle export` and `al bundle verify --keyring --expect-head`.

### Added — adapters and OpenTelemetry

- **`adapters.py`** — best-effort mappings for AGNTCY, ClawTeam and OpenClaw.
  Honest about their status in the code itself: these are documented field
  mappings with an explicit `confidence`, **not** integrations verified against a
  live deployment, and `Adapter.summary` says so for each. An adapter that cannot
  find a publisher domain returns no entry rather than inventing one, because a
  fabricated domain would pass ARD's shape check and then defeat the §4.5.1
  authority binding.
- **`otlp.py`** — receipts as OTLP spans, with no dependency. A receipt already
  carries a start time, a status and attributes, and `parent_receipt_id` is
  exactly the parent-child relation a trace needs, so a delegation chain *is* a
  trace and no instrumentation is required to produce one. Emits OTLP **JSON**
  (not protobuf, not gRPC), which the module says plainly.

### Added — ARD conformance, checkable in one command

- **`al conform manifest|publisher|registry`**, implementing the specification's
  checks locally. Not a reimplementation for its own sake: a conformance command
  that needs the network before it can say anything is one nobody runs in CI, and
  one requiring a separately installed script is one nobody starts. Every finding
  cites the section it comes from, and `--official` drives the specification's
  own CLI when it is on `PATH` for a second opinion.
- The **error/warning split is preserved all the way to the exit code**: ARD
  §D.2 makes `representativeQueries` a warning so existing tooling still
  validates, and a checker that fails conformant input is worse than no checker.
- Optional endpoints are treated as optional. A 501 from `POST /explore` or a 404
  from `GET /agents` is **conformance**, not failure — reporting them as errors is
  the most common way a conformance tool wastes a reader's afternoon.
- `tests/test_conform.py` includes a cross-check that our own demo agents are
  conformant, because a project shipping a conformance checker that fails its own
  material is the shortest possible route to an embarrassing issue report.

### Fixed

- `_duplicates` compared `outcome` as a `DelegationStatus` against the string
  that came back from JSON, so a ledger read from disk reported every legitimate
  state transition as a forged duplicate. Normalised to the stored form.
- The signature members joined the duplicate check's mutable set. Every
  transition of one delegation carries a *different* signature, so including them
  made each identity unique and produced the same false positive a third time —
  after `result_digest` and `issued_at`. A check that reports correct input as
  forged is worse than no check, because it teaches the operator to ignore it.
- `to_spans` keyed spans by receipt id alone, silently collapsing several
  transitions of one delegation into a single span and losing the rest.
- The publisher-authority binding check in `conform.py` was gated on a condition
  that never held, disabling it entirely.

### Added — signed receipts

- **`HmacSigner`** (standard library, no extra) and **`Ed25519Signer`** (behind
  the new `[sign]` extra). The standard library has **no asymmetric signature
  primitive** in any version this project supports — `hashlib` and `hmac` are
  symmetric, `ssl` exposes no signing API, and 3.13 removed `crypt` without
  adding anything — so third-party-verifiable receipts necessarily need a
  library, and it is an extra rather than a dependency so that
  `pip install agent-ledger` still pulls in nothing.
- The differences are documented rather than glossed. **HMAC proves the holder
  of the secret wrote the bytes; it does not prove who.** It is symmetric, so
  every verifier is also a forger, which makes it evidence *within* one trust
  domain and not *between* organisations — and a key leak is unrecoverable,
  because historically valid tags cannot be told from forged ones. Ed25519 is the
  only option where a third party can verify without being able to forge.
  `TestHmacProvesTheHolderNotTheAuthor` asserts the limitation instead of
  describing it, so no future docstring can quietly imply otherwise.
- **`signing_payload`**, domain-separated and audience-bound:
  `b"al-receipt-v1\\0" || ledger_id || prev || digest`. Signing a bare
  `sha256:<hex>` invites replay as a signature over something else that hashes
  the same way; omitting `ledger_id` lets a receipt from one ledger verify in
  another; omitting `prev` lets a signed line move *within* a ledger. A
  per-receipt signature without linkage would have *laundered* replay and
  splicing by lending them cryptographic authority.
- `KeyRing`, deliberately **pinned**: every key is supplied by the caller from a
  channel they already trust. A keyring that fetched keys from wherever a receipt
  said they were would be worse than useless, because an attacker rewriting the
  ledger would simply also rewrite the key reference.
- `LedgerIntegrity` gains `bad_signature`, `unknown_key`, `unknown_alg` and a
  `signed` count. A line that *is* signed but cannot be checked reports
  `unknown_key`, not success.
- CLI: `--sign-key-env VAR` on `delegate`, and `--sign-key-env`,
  `--require-signature` on `verify`. **The secret is read from the environment
  and never from argv** — an argv value is visible in `ps` and lands in shell
  history, and a signing key in a process listing is a finding waiting to be
  filed.

### Added — head witnessing

- **`--expect-head DIGEST`** on `al verify`, and `chain_head` in `--json` and in
  the human-readable output. This is what makes **tail truncation** detectable:
  a shortened prefix is a perfectly consistent chain, so nothing inside the file
  can notice, and publishing the head out of band — a commit, a peer, a release
  artefact — is the only mechanism that can. The CLI prints the head with a line
  telling the operator to do exactly that.
- `--ledger-id` on `delegate` and `verify`, and `ledger_id` in
  `LedgerIntegrity`. The ledger identity is deliberately **not** stored in the
  file — recording it would let a forger supply their own — so a verifier that
  was not told it checks against the wrong thing and sees a broken chain *and* a
  bad signature, which reads as corruption rather than as a missing input.
  `verify` now names the identity it used and says to pass the original. The
  binding is not weakened; the failure is made diagnosable.

### Added — SQLite backend

- **`SqliteBackend`**, standard library, satisfying the same `LedgerBackend`
  protocol. Row inserts are atomic, so the torn-tail corruption class cannot
  happen at all; and append-only stops being a convention and becomes something
  the database enforces, with `BEFORE UPDATE`/`BEFORE DELETE` triggers that
  `RAISE(ABORT)`. It stores the receipt as **one canonical-JSON text column, never
  per-field columns** — field columns would round-trip `1` as `1.0` and `None` as
  `NULL`, and every one of those changes the digest the whole design rests on. It
  is an option and not the default because it trades away the property the module
  opens by defending: JSONL can be read, diffed and grepped by anything.

### Added — real A2A execution

- **`A2AExecutor`**, driving A2A v1.0 over JSON-RPC: Agent Card discovery,
  `SendMessage`, `GetTask`, a v0.3 method-name fallback (`message/send`), and
  bounded polling. It satisfies the existing `Executor` protocol, so it drops
  into `Grid(executor=...)` with no change to policy, matching or the ledger.
- **`a2a.map_task_state`**, the A2A-task-state to delegation-state mapping, with
  the whole table tested row by row. The two *interrupted* states —
  `TASK_STATE_INPUT_REQUIRED` and `TASK_STATE_AUTH_REQUIRED` — map to `accepted`
  with `ok=True`, deliberately. A2A has states this library has no equivalent
  for, because a delegation is either outstanding or settled, and reporting
  work that is waiting on the **principal** as a failure would cost the delegate
  reputation for a question nobody has answered while releasing a budget
  commitment that is still outstanding. `Grid.dispatch` therefore leaves such a
  delegation open rather than settling it. Unknown states fail rather than
  succeed: a state this library does not model might mean anything, and
  reporting success for it would receipt work that never happened.
- **`ExecutionRecord`** on the receipt: the remote task id, the remote state
  verbatim, and a *reference* to the credential presented. Three questions an
  audit asks that "it was invoked" cannot answer.
- `Credential` protocol with `StaticCredential` and `BearerCredential`. The
  reference is a separate, required field, because "we forgot to name it" is
  exactly how a token ends up in an audit log.
- `JsonRpcTransport` protocol with a `UrllibJsonRpcTransport` implementation, so
  the whole A2A surface — including its error handling and state mapping — is
  testable with no sockets. `A2AClient`, `AgentCard`, `SendMessageResult`,
  `GetTaskResult`, `A2AError`.
- `tests/test_a2a.py`, 49 tests.

### Changed — the receipt body

- `Receipt.body()` includes `execution` **only when present**. That is what keeps
  this backward compatible: a receipt without one — every receipt written before
  this release, and every receipt from a local executor — digests to exactly the
  bytes it always did. An unconditional field would have changed every
  historical digest, and with no version marker in the body there would be no
  way to tell those receipts from corrupt ones. The trade is deliberate: a
  receipt that *does* carry an execution record has a digest older verifiers
  cannot reproduce, which is correct, because it is the new receipts that need
  the new field protected.
- `Ledger._duplicates` treats `execution` as transition-mutable, alongside
  `result_digest`. It only appears at completion, so without this every real A2A
  delegation was reported as a forged duplicate — the same false-positive class
  the `result_digest` and `issued_at` fixes addressed.

### Fixed — discovery and packaging

- **`ArdClient.search()` crashed on every real ARD registry response.**
  `ard.py` rebuilt an entry via `ArdEntry(**{**entry.__dict__, ...})`, but
  `ArdEntry` is `slots=True` and has no `__dict__`, so any search result that
  omitted `url` raised `AttributeError`. ARD §5.3.2 says a result "is therefore
  not necessarily a complete ARD entry", so omitting `url` is normal, not
  malformed. The test fixture gave every registry entry a `url`, which is why
  176 green tests did not notice. Fixed, and the lean shape is now covered by
  `TestLeanSearchResults`.
- A search result with no target is no longer given a fabricated `data` payload
  to satisfy `is_valid`. `ArdEntry` gains `has_target` and `is_searchable`, so
  "discoverable" and "invocable" are distinguishable; `is_valid` keeps its
  original meaning of *complete ARD entry*.
- `Grid.discover()` caught only `ArdError`, so a parsing bug on an unexpected
  remote response escaped as a raw traceback and aborted the delegation. Any
  failure is now contained, and recorded on `Grid._last_discovery_error` rather
  than swallowed.
- `Grid.dispatch()` could return `outcome.ok is True` with
  `outcome.receipt is None` when no executor was configured — the exact call the
  README quick-start makes, which raised `AttributeError` on `.digest()`. The
  issuance receipt already existed in the ledger; it is now returned.
- `Grid.dispatch()` invoked a delegate with no target, letting the executor fail
  on `None`. It now refuses with a reason naming the partial result, and receipts
  the refusal.
- The CLI no longer prints a traceback for an unexpected error. It names the
  exception, points at the issue tracker, and exits non-zero.
- **Packaging: the sdist shipped the entire working directory.**
  `.gitignore` listed `.venv/`, which does not match `.venv-test/`, and
  hatchling honours `.gitignore` — so a 16 MB sdist was produced containing 1,944
  virtualenv files including `python.exe`. The sdist now uses an explicit
  `include` allowlist in `pyproject.toml`; the result is 105 KB.
- `Typing :: Typed` was declared without shipping `py.typed`, making the
  classifier false. The marker is now present in both wheel and sdist.

### Fixed — receipt and ledger integrity

Every one of these had the same shape: `verify()` reporting success for work
it had not done.

- **A line with its `digest` key removed verified clean.** `verify()` read
  `if stored and stored != ...`, so a missing or empty digest meant "nothing to
  check" — while the line still counted as verified. An attacker could forge a
  receipt's contents, delete the digest, and `al verify` printed
  ``N receipt lines verified, chain intact`` and exited 0 with the forged value
  in place.
- **Deleting a line was undetectable.** Per-line digests cannot catch a
  whole-line deletion: nothing is left to disagree with. Every line now carries
  `prev`, the link of the line before it, so deletion, reordering, insertion and
  cross-ledger splicing are all reported. Verified against the seven attacks
  enumerated in the audit.
- **A receipt spliced from another ledger verified as a legitimate root.** The
  genesis link now mixes in a `ledger_id`, so line 1 of one ledger is not line 1
  of another. This matters because a chain root is precisely the line that names
  the accountable principal.
- **The digest was not stable across a write/read cycle.** `Receipt.from_json`
  coerced numeric fields with `float()` while the constructor did not, so
  `Receipt(cost_usd=1)` and its reloaded counterpart disagreed and `verify()`
  reported an **untouched** file as tampered. Numeric fields are now normalised
  in `__post_init__`, so both paths agree. A signature layered on the old digest
  would have failed on the library's own output.
- **`content_digest` was not reproducible across processes.** It used
  `json.dumps(..., default=str)`, and `str()` of a `set` follows hash
  randomisation — four `PYTHONHASHSEED` values produced four digests for
  identical content. Sets are now handled structurally, integral floats are
  normalised so `1` and `1.0` agree, and anything genuinely unserialisable
  raises the new `DigestError` instead of silently hashing a `repr()` that only
  verifies on the machine that wrote it.
- **`verify()` and `al audit` traced back on hostile input.** `from_json` was
  called unguarded inside `verify()`, so a line as ordinary as
  `{"receipt_id": "evil", "digest": "..."}` raised `KeyError` and `[1, 2, 3]`
  raised `AttributeError`. One appended line could disable the integrity tool.
  Unparseable and schema-invalid lines are now reported by line number, and the
  good lines around them are still checked.
- **`al verify --ledger typo.jsonl` printed `OK: 0 receipt lines verified,
  chain intact` and exited 0.** A missing file is now a reported failure,
  distinct from a legitimately empty ledger.
- **A duplicate `receipt_id` silently rewrote the audit view.** `_index`
  overwrote unconditionally, so a second line under an existing id changed the
  reported cost and outcome with a valid digest and no complaint. A repeated id
  is legitimate — one delegation keeps one id across its state transitions — so
  the rule distinguishes a transition from a forgery rather than flagging both.
- **`describe()` claimed "chain intact" without checking any chain property.**
  It now reports what it actually verified, and says how many lines it could
  not check.
- **`from_json` was not a pure function of its input.** A line lacking
  `receipt_id` or `issued_at` was given a fresh random id and the current time,
  so two parses of the same bytes produced different digests. Both are now
  required.
- **A receipt's `issued_at` changed every time its status advanced.** Each
  transition regenerated the timestamp, so a field that "when was this
  authorised" depends on mutated as the work progressed. `issued_at` is now the
  delegation's creation time, shared by all of its transitions. Found because it
  made every real delegation look like a forged duplicate to the new
  duplicate-id check — a check that fails on correct input is worse than no
  check, since it teaches the operator to ignore it.

### Fixed — ledger mechanics

- **`record()` advanced the in-memory view before writing.** A failed append
  still mutated the ledger, so a store that could not be written reported
  delegations it did not hold. Write-then-index now.
- **Two `Ledger` instances on one path silently diverged.** There was no way to
  observe lines written by another process, so a stale instance could append a
  transition that un-settled a delegation the first had completed — re-opening
  its budget and erasing its spend while every digest verified. Read entry points
  now refresh first. This is a read-model defect; file locking does not fix it.
- **`current()` was O(n²)**, re-scanning an accumulating list per line, on the
  hot path: reputation seeding plus a scan per policy candidate meant ~11 full
  scans per `delegate()`. Measured at 20k lines: **1247 ms → 116 ms**.
- **`__bool__` returned false for an empty ledger**, so `ledger or Ledger()`
  silently substituted a different object. This shipped a real bug once. An
  empty ledger is now truthy; `len()` still reports delegations.
- **A torn final line had no remedy.** It was tolerated on load but failed
  `verify()` forever, and a later append moved it mid-file where it could no
  longer be attributed to the crash that caused it. `Ledger.repair_tail()`
  removes the trailing run. It refuses to touch a malformed line that has valid
  lines after it, because that is not a torn write.

### Added

- **`LedgerBackend`**, a four-operation storage protocol (`append`, `scan`,
  `refresh`, `close`), with `MemoryBackend` and `JsonlBackend` implementations.
  `Ledger(path=...)` behaves exactly as before; `Ledger(backend=...)` is the new
  seam. `scan()` yields raw lines rather than parsed receipts on purpose —
  verification is about what is *stored*, including lines that do not parse, and
  a backend that parsed for the caller would discard the evidence an audit needs.
- `LedgerIntegrity` now distinguishes `tampered`, `malformed`, `broken_chain`,
  `orphaned`, `duplicated`, `no_digest`, `missing` and `unchained`, because "the
  ledger is bad" is not an actionable statement. `chain_head` exposes the last
  link so truncation can be detected by publishing it out of band.
- `Ledger.verify(strict_chain=True)` for a deployment that has committed to
  linkage everywhere. Off by default, so upgrading does not retroactively
  declare existing ledgers corrupt.
- `DigestError`, raised when a value cannot be canonicalised reproducibly.
- `tests/test_ledger_integrity.py` (79 tests) and `tests/test_ledger_backend.py`
  (25 tests). Both are predominantly *negative* tests, because the defects they
  guard against were all invisible to happy-path testing.
- `docs/DESIGN.md` — the design reasoning, including an honest limitations
  list, kept in step with `SECURITY.md` so the two never contradict each other.
- `.gitattributes` — LF normalisation, so committed ledger fixtures hash
  identically on every platform.
- `SECURITY.md`. Unusually, its scope section is substantive: a defect in the
  accountability claims *is* a security issue even when nothing crashes. It also
  lists what is already documented, so the tracker does not fill with reports
  the limitations list already anticipates.
- `.github/ISSUE_TEMPLATE/` (bug report, feature request, config) and
  `.github/PULL_REQUEST_TEMPLATE.md`. An empty tracker reads as abandoned, so
  these are part of shipping rather than polish.
- README: a "from source" install section documenting the virtualenv
  requirement, an explicit statement of what `al verify` does and does not
  prove, and a notice that the package is not yet on PyPI — the README's first
  command fails until it is. The comparison table no longer claims `via A2A`
  for a transport that does not ship.

### Fixed

- **Every repository URL pointed at a repository that does not exist.**
  `github.com/agent-ledger/agent-ledger` returned 404 for all
  twelve references across the README, `pyproject.toml`, `CONTRIBUTING.md` and
  `CHANGELOG.md` — including the issue link
  the CLI prints when it hits an unexpected error, and the `compare`/`releases`
  links at the foot of this file. Repointed at the repository that actually
  exists. `ard.py`'s `User-Agent` was malformed in the same way: it advertised an
  organisation URL rather than the project.
- A GitHub "About" box description once read "Implements ARD discovery + A2A
  execution", contradicting the README's own comparison table. Corrected, with a
  note on why the two must not disagree.

### Changed

- `Grid.dispatch()` without an executor now returns the `pending` issuance
  receipt instead of `None`. One test asserted the old behaviour and was updated
  deliberately; see `test_dispatch_without_executor_only_places`.
- Three further tests asserted behaviour this release deliberately changes — the
  empty ledger being falsy, a missing ledger verifying clean, and a tamper label
  being the bare receipt id. Each was rewritten to pin the new contract with the
  reasoning, rather than deleted.

## [0.1.0] — 2026-09-30

First release. The layer ARD and A2A deliberately leave open: task publication,
capability matching, delegated authority, receipts and a verifiable chain of
custody.

### Added

**Discovery**
- `ArdClient` implementing ARD v0.91 — static discovery via
  `/.well-known/ard.json` (with the `ai-catalog.json` predecessor path as a
  courtesy fallback), dynamic discovery via `POST /search`, and federation with
  `auto` / `referrals` / `none` semantics.
- ARD §4.5.1 publisher-authority binding, on by default, so an entry claiming
  `urn:air:google.com:...` is rejected unless its trust identity agrees.
- `StaticTransport` for offline tests, demos and air-gapped rehearsals.
- Referral loops terminate; one unreachable registry cannot sink a federated
  query.

**Matching**
- Multi-signal ranking with every signal kept visible: capability coverage,
  query relevance, registry score, trust, reputation.
- `ReputationIndex` derived from the ledger's own receipts — routing that
  remembers. A budget overrun is penalised harder than a plain failure, because
  an overrun still reports success.
- Pluggable `Scorer` so lexical matching can be swapped for embeddings.

**Policy**
- `Policy` with ordered, named rules: budget ceilings, chain ceilings counting
  commitments as well as spend, delegation depth, publisher and agent
  allow/deny lists, trust requirements, deadlines.
- Presets: `open_grid()`, `ceilinged()`, `zero_trust()`.
- Custom rules are plain functions over `RuleContext` — no DSL, no fork.
- Denials are first-class results carrying the rule that produced them, and
  refusals are written to the ledger.

**Delegation and receipts**
- `Grid` with `discover`, `candidates`, `delegate`, `dispatch`, `accept`,
  `complete`, `fail`, `revoke`, `audit`.
- `Delegation` records the authority actually granted: capabilities, budget,
  deadline, parent, depth.
- `Receipt` with a `sha256` over its own canonical form, a stable identity per
  delegation, and append-only state transitions.
- `DelegationChain` reconstructs a lineage root-principal-first and reports
  every violation rather than only the first.
- `Ledger` — append-only JSONL with a derived current-state view, tamper
  detection via `verify()`, and commitment-aware budget accounting.

**Interfaces**
- `al` CLI: `demo`, `find`, `delegate`, `audit`, `verify`, `policy`.
- `al demo` — a complete three-hop, two-organisation scenario that runs
  offline with no API key.
- Zero runtime dependencies. Python 3.10+.

### Notes

This is alpha. Known gaps, stated plainly:

- Receipts are content-addressed but **not signed**. A third party can verify
  that a ledger was not edited; they cannot yet verify who wrote it.
- The ledger is local JSONL. There is no shared or remote backend.
- A2A task-lifecycle binding is not implemented. Execution sits behind an
  `Executor` protocol so a real client can be dropped in, but none ships.
- The default matcher is lexical. It is honest about being a proxy.

[Unreleased]: https://github.com/yaoyuxiang-gnn/agent-ledger/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yaoyuxiang-gnn/agent-ledger/releases/tag/v0.2.0
[0.1.0]: https://github.com/yaoyuxiang-gnn/agent-ledger/releases/tag/v0.1.0
