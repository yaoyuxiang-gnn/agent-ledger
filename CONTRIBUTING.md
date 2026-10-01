# Contributing

Thanks for looking. This project is small on purpose, and the fastest way to
get a change merged is to keep it that way.

## Getting set up

No install step is needed to run the tests — `tests/conftest.py` puts `src` on
`sys.path`:

```bash
git clone https://github.com/yaoyuxiang-gnn/agent-ledger
cd agent-ledger
python -m pytest          # 192 tests, under a second, no network
```

That shim is why a fresh clone works with no install. It also means the suite
never exercises the *installed* package or the console scripts, which is what the
`build` job in CI is for.

For linting and the full experience, install into a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
ruff check src tests
ruff format src tests
```

**Do not install into the system interpreter.** `pip install -e .` writes
console scripts into the interpreter's `Scripts`/`bin` directory. On Windows a
stock python.org install (`C:\PythonXX\Scripts`) is owned by `BUILTIN\Administrators`
and grants `BUILTIN\Users` only `ReadAndExecute`, so pip cannot create `al.exe`.
The failure it reports is misleading:

```text
WARNING: Failed to write executable - trying to use .deleteme logic
ERROR: Could not install packages due to an OSError: [WinError 2] The system
cannot find the file specified: '...\Scripts\al.exe' -> '...\Scripts\al.exe.deleteme'
```

`WinError 2` is *file not found*, not access denied, because pip's vendored
`distlib` falls back to renaming a file that was never created — so it looks like
a build error when it is a permissions one. It also leaves a half-installed
package behind: the `.pth` and `.dist-info` land in `site-packages` and `import
agent_ledger` works, while the `al` command does not exist. A venv avoids
all of it.

## The one command to run before you push

```bash
python -m pytest && python -m agent_ledger.cli demo --no-color
```

The demo is the project's front door. If it breaks, the README breaks.

If you changed the CLI, the test count or the demo output, also run:

```bash
python tools/check_readme.py
```

It checks that both READMEs still describe this software — every `al` command and
flag they name exists, the quoted test count is real, the demo transcript's numbers
still appear in real output, and the Chinese translation has not fallen behind. It
runs in CI.

If you changed the demo, also regenerate the social preview card:

```bash
python tools/make_social_preview.py
```

`tools/make_social_preview.py` captures the real `al demo` output and renders
`.github/social-preview.png` from it, then you upload that file under
**Settings → General → Social preview** (GitHub has no API for that field). It is
generated rather than drawn so the card cannot advertise output the software no
longer prints — and it is not checked in CI, so regenerating it is on you.

### Keeping the two READMEs in step

`README.md` and `README.zh-CN.md` are the same document in two languages, with the
same section structure and the same facts. Change one, change the other, in the
same pull request. `tools/check_readme.py` fails if the translation loses a section.

Technical tokens — ARD, A2A, `receipt`, `ledger`, `keyring`, `bundle`, `digest` —
stay in English in the Chinese file on purpose: they are the API names and the
strings a reader greps for. Translating them would make the document harder to use,
not easier.

### Releasing

A release is a GitHub release, not a terminal command. Publishing runs in
`.github/workflows/release.yml`, authenticated by PyPI Trusted Publishing — there
is no API token on anyone's laptop and none in the repository's secrets.

1. Update `version` in `pyproject.toml` **and** `VERSION` in
   `src/agent_ledger/_identity.py`, and add a `CHANGELOG.md` entry. The release
   job fails if the tag and `pyproject.toml` disagree, because a version number on
   PyPI can be yanked but never reused.
2. `python -m build && python tools/audit_dist.py && python -m twine check --strict dist/*`
   locally. `audit_dist.py` is the same check CI runs; running it here is how you
   find out before a release exists rather than after.
3. Draft a GitHub release with tag `v<version>`, and publish it. The workflow
   builds, audits, installs the wheel into a clean interpreter, then uploads.

To rehearse without spending a version number, run the workflow manually
(`workflow_dispatch`) with `target: testpypi`.

## Non-negotiables

These are load-bearing promises, and CI enforces them:

1. **No runtime dependencies.** The `dependencies` list in `pyproject.toml`
   must stay empty. A CI job fails the build if it does not. Standard library
   only, including HTTP (`urllib.request`).
2. **Tests must not touch the network.** Everything goes through the
   `Transport` protocol; use `StaticTransport`.
3. **The demo must stay offline and key-free.** `al demo` runs with no API
   key, no account and no sockets. It is how people decide whether to care.
4. **Denials stay data.** A refusal is a `PolicyDecision`, not an exception.
5. **Receipt digests stay deterministic.** If you add a field to
   `Receipt.body()`, existing ledgers will report as tampered. Treat it as a
   breaking change and say so in the changelog.

## What would help most

The core is built. What is genuinely open, in rough order of usefulness:

- **A keyring that resolves rather than pins.** A pinned `KeyRing` binds a key to
  a principal; how that mapping is *obtained* — from a SPIFFE bundle endpoint, a
  DID document, an enterprise PKI — is not built. This is the one place the
  project should adopt an existing standard rather than define anything, and it
  is the highest-value remaining work.
- **A transport for bundle exchange.** The format exists and verifies; moving one
  between organisations is still a file someone emails.
- **Adapters verified against live deployments.** AGNTCY, ClawTeam and OpenClaw
  adapters map declared field names with an explicit confidence, because none of
  their specifications is vendored here. Replacing a guessed name with an
  observed one is a one-line change in one place.
- **A2A push notifications, and the gRPC / `HTTP+JSON` bindings.** Both are
  currently named and refused rather than half-implemented.
- **Documentation of failure modes.** Where does this design break? A good
  "limitations" section is worth more than another feature.

`docs/DESIGN.md` has the honest limitations list. If you find a limitation that
is not on it, that is itself a contribution.

## Style

- Type annotations on public functions. The package ships `Typing :: Typed`.
- Docstrings explain *why*, not *what*. The code already says what.
- Comments should earn their place. If a line needs a comment to be
  understandable, prefer rewriting the line.
- Tests are named for the behaviour they protect, not the method they call.
  `test_a_budget_overrun_changes_the_next_ranking` beats `test_score`.

## Pull requests

- One logical change per PR.
- Add a test that fails without your change.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- If you change behaviour, say what breaks.

## Reporting bugs

Include the output of `al demo` (or a minimal reproduction), your Python
version, and your OS. If it is about routing, include the candidate list from
`grid.candidates(task)` — the signals are there precisely so routing bugs can
be diagnosed without guesswork.

## Code of conduct

Be decent. Assume competence and good faith. Technical disagreements are
welcome and should stay technical. The full text is in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Contributions are accepted under Apache-2.0. See [LICENSE](LICENSE).
