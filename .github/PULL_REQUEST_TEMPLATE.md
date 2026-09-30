## What this changes

<!-- One or two sentences. If it fixes an issue, link it. -->

## Why

<!-- The problem, not the patch. What goes wrong today? -->

## Breaking changes

<!--
Receipt digests are deterministic on purpose. If you changed `Receipt.body()` or
the canonicalisation, existing ledgers will report as tampered. Say so here, and
add it to CHANGELOG.md under Unreleased.
-->

- [ ] No breaking change
- [ ] Breaking change, described above and in `CHANGELOG.md`

## Checklist

- [ ] `python -m pytest` passes (no install needed — `tests/conftest.py` shims `src` onto `sys.path`)
- [ ] `python -m agent_ledger.cli demo --no-color` still runs — the demo is the README's front door
- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] A test fails without this change
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`

## Constraints this project keeps

- [ ] **No runtime dependency added.** `dependencies` stays empty; a CI job fails the build if it does not. Anything needing a library ships as an opt-in extra (`[sign]` is the expected shape).
- [ ] **No network in tests.** Everything goes through the `Transport` protocol; use `StaticTransport`.
- [ ] **The demo stays offline and key-free.**
- [ ] **Denials stay data.** A refusal is a `PolicyDecision`, not an exception.
- [ ] If this touches `verify()`, `content_digest()` or `Receipt`, I added a **negative** test — tampered digest, wrong key, missing field, hostile line — not only the happy path.

## How it was verified

<!--
Commands you ran and what they printed. If you changed the CLI, the demo
transcript, or anything the README quotes, say whether the README needed
updating — a README that describes the old behaviour is a bug.
-->
