"""Check that the READMEs still describe the software that exists.

Documentation drifts in one direction: it describes the version someone was proud
of. This is the cheapest possible guard against that — it does not judge the
prose, it checks the *claims that can be checked*:

* every ``al`` command and flag named in a README exists
* the test count in both READMEs matches reality
* the demo transcript's numbers still appear in real ``al demo`` output
* the zero-dependency promise is still true
* the two READMEs still have the same section structure, so the translation has
  not fallen behind the original
* no file that is meant to stay local has been committed

Run it after changing the CLI, the test count, or the demo:

    python tools/check_readme.py
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

READMES = ("README.md", "README.zh-CN.md")

#: Paths that must never appear in a public commit. Kept in step with
#: ``.gitignore``; this list is the *point* of that file, so it is asserted
#: rather than trusted.
MUST_NOT_SHIP = (
    ".internal/",
    "RELEASE.md",
    "AUDIT-",
    "THREAT-MODEL",
)


def _all_subparsers(parser):
    """Every subparser reachable from *parser*, at any depth.

    Yields subparsers rather than ``(name, subparser)`` pairs, and that is
    deliberate: ``bundle verify`` and top-level ``verify`` share a name, so
    collecting into a dict silently drops one of them — which made this checker
    report ``--require-signature`` as fictional because the *nested* ``verify``
    had overwritten the real one.
    """
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            for sub in choices.values():
                yield sub
                yield from _all_subparsers(sub)


def _command_names(parser) -> set[str]:
    group = getattr(parser, "_subparsers", None)
    if group is None:
        return set()
    return {name for action in group._group_actions for name in (action.choices or {})}


def main() -> int:
    from agent_ledger.cli import build_parser

    problems: list[str] = []
    texts = {name: (ROOT / name).read_text(encoding="utf-8") for name in READMES}

    parser = build_parser()
    all_subparsers = list(_all_subparsers(parser))
    commands = _command_names(parser)
    nested = {n for sub in all_subparsers for n in _command_names(sub)}

    # 1. Commands named in a README must exist, at the top level or nested.
    known = commands | nested
    for name, text in texts.items():
        for match in sorted(set(re.findall(r"\badg ([a-z][a-z-]*)", text))):
            if match not in known:
                problems.append(f"{name}: documents `al {match}`, which does not exist")

    # 2. Flags named in a README must exist somewhere in the command tree.
    #
    # `--from` is uv's, not ours: `uvx --from <distribution> al demo` is how the
    # README tells a reader to run this without installing it, and the checker
    # cannot tell another tool's flag from a fictional one of ours. Listed rather
    # than regexed around, so that the exemption is a decision rather than a
    # pattern somebody has to decode.
    FOREIGN_FLAGS = {"--from"}
    every_flag = {
        option
        for sub in all_subparsers
        for action in sub._actions
        for option in action.option_strings
    }
    for name, text in texts.items():
        for flag in sorted(set(re.findall(r"(?<![\w-])(--[a-z][a-z-]{2,})", text))):
            if flag not in every_flag and flag not in FOREIGN_FLAGS:
                problems.append(f"{name}: documents {flag}, which no command accepts")

    # 3. The test count must match reality in both files.
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    total = re.search(r"(\d+) tests? collected", collected.stdout)
    count = (
        int(total.group(1))
        if total
        else sum(int(n) for n in re.findall(r"^tests[/\\]\S+:\s+(\d+)\s*$", collected.stdout, re.M))
    )
    if count:
        for name, text in texts.items():
            claimed = re.findall(r"\*\*(\d+) tests?\*\*", text)
            if claimed and str(count) not in claimed:
                problems.append(f"{name}: claims {claimed} tests, but {count} are collected")

    # 4. The demo numbers quoted in the READMEs must appear in real output.
    #
    # The child gets a *copy* of this process's environment, plus NO_COLOR. It
    # deliberately does not get a hand-built `{"NO_COLOR": ..., "SYSTEMROOT": ...}`
    # one: that reads as harmless isolation, but it also strips `PYTHONPATH`, which
    # is the only thing making `agent_ledger` importable for a contributor running
    # this from a fresh clone without installing. The failure it produced — "al demo
    # exited 1" — said nothing about the cause.
    env = {**os.environ, "NO_COLOR": "1"}
    demo = subprocess.run(
        [sys.executable, "-m", "agent_ledger.cli", "demo", "--no-color"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if demo.returncode != 0:
        problems.append(
            f"al demo exited {demo.returncode}, so the transcript cannot be trusted"
            + (f": {demo.stderr.strip().splitlines()[-1]}" if demo.stderr.strip() else "")
        )
    else:
        for needle in ("$0.4900", "3 hops", "reputation=0.13", "No rule was written"):
            if needle in texts["README.md"] and needle not in demo.stdout:
                problems.append(f"README.md quotes {needle!r}, which al demo no longer prints")

    # 5. Zero dependencies is a headline promise.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", pyproject, re.S | re.M)
    if deps is None or deps.group(1).strip():
        problems.append(
            "pyproject.toml declares runtime dependencies, so the README's claim is false"
        )

    # 6. The translation must not fall behind the original.
    english = re.findall(r"^##+ (.+)$", texts["README.md"], re.M)
    chinese = re.findall(r"^##+ (.+)$", texts["README.zh-CN.md"], re.M)
    if len(chinese) < len(english):
        problems.append(
            f"README.zh-CN.md has {len(chinese)} sections against {len(english)} in "
            "README.md: the translation has fallen behind"
        )

    # 7. Nothing that is meant to stay local may be in the tree at all.
    #
    # This is the check that would have caught a release plan being published.
    # It looks at the working tree rather than at git, because the mistake is
    # made when the file is created, not when it is committed. `.internal/` is
    # the one sanctioned home for local material, so it is skipped rather than
    # flagged.
    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".internal", "node_modules"}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if skip_dirs & set(path.relative_to(ROOT).parts):
            continue
        relative = path.relative_to(ROOT).as_posix()
        for forbidden in MUST_NOT_SHIP:
            if forbidden in relative:
                problems.append(
                    f"{relative} looks like local-only material ({forbidden!r}); it "
                    "belongs in .internal/, or should be deleted"
                )
                break

    if problems:
        print("README drift detected:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(f"READMEs agree with the code: {len(commands)} commands, {count} tests, demo verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
