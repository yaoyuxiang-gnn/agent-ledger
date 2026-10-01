"""Audit the built artefacts before they are uploaded.

This is the local twin of the `build` job in CI. It exists because the two
mistakes it catches are both invisible from the outside and both permanent once
uploaded: a version number that disagrees with what you think you are releasing,
and a file in the sdist that was never meant to leave the machine. A missing
`.gitignore` pattern once produced a 16 MB sdist containing an entire virtualenv.

Run it after `python -m build`:

    python tools/audit_dist.py
"""

from __future__ import annotations

import glob
import pathlib
import re
import tarfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Anything matching one of these must not be in the sdist at all.
FORBIDDEN = (".venv", "venv/", "node_modules", "__pycache__", ".pyc", ".git/")

#: The sdist is the source of truth for anyone who cannot use a wheel, so these
#: have to be in it even though a wheel would never carry them.
REQUIRED = ("pyproject.toml", "README.md", "README.zh-CN.md", "LICENSE", "CHANGELOG.md")


def main() -> int:
    problems: list[str] = []

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    name = re.search(r'^name\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
    version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)

    identity = (ROOT / "src" / "agent_ledger" / "_identity.py").read_text(encoding="utf-8")
    identity_version = re.search(r'^VERSION\s*=\s*"([^"]+)"', identity, re.M).group(1)
    if identity_version != version:
        problems.append(
            f"_identity.py says {identity_version}, pyproject.toml says {version}: "
            "the User-Agent and --version would advertise the wrong release"
        )

    sdists = glob.glob(str(ROOT / "dist" / "*.tar.gz"))
    wheels = glob.glob(str(ROOT / "dist" / "*.whl"))
    if not sdists or not wheels:
        problems.append("dist/ does not contain both an sdist and a wheel; run python -m build")
        print_problems(problems)
        return 1

    sdist = sdists[0]
    names = [n for n in tarfile.open(sdist).getnames() if not n.endswith("/")]
    print(f"{pathlib.Path(sdist).name}: {len(names)} files")

    leaked = [n for n in names if any(f in n for f in FORBIDDEN)]
    if leaked:
        problems.append("artefact leak in the sdist:\n    " + "\n    ".join(leaked[:20]))

    missing = [r for r in REQUIRED if not any(n.endswith(r) for n in names)]
    if missing:
        problems.append(f"the sdist is missing: {missing}")

    wheel = wheels[0]
    wnames = zipfile.ZipFile(wheel).namelist()
    print(f"{pathlib.Path(wheel).name}: {len(wnames)} entries")

    if not any(n.endswith("agent_ledger/py.typed") for n in wnames):
        problems.append("the wheel is missing py.typed, so `Typing :: Typed` would be a lie")

    bytecode = [n for n in wnames if "__pycache__" in n or n.endswith(".pyc")]
    if bytecode:
        problems.append(f"the wheel contains bytecode caches: {bytecode[:5]}")

    # The import name must survive the distribution rename. It is the one string
    # users type that this project deliberately did *not* change, so it is worth
    # asserting rather than assuming.
    if not any(n.startswith("agent_ledger/") for n in wnames):
        problems.append("the wheel does not contain an agent_ledger/ package")

    metadata = next((n for n in wnames if n.endswith(".dist-info/METADATA")), None)
    if metadata is None:
        problems.append("the wheel has no METADATA")
    else:
        text = zipfile.ZipFile(wheel).read(metadata).decode("utf-8")
        declared = re.search(r"^Name: (.+)$", text, re.M).group(1).strip()
        wheel_version = re.search(r"^Version: (.+)$", text, re.M).group(1).strip()
        if declared != name:
            problems.append(f"the wheel calls itself {declared!r}, pyproject says {name!r}")
        if wheel_version != version:
            problems.append(
                f"the wheel is version {wheel_version}, pyproject says {version}: PyPI "
                "rejects a re-upload, so this is the one error that cannot be undone"
            )

    # Console scripts live in entry_points.txt, not METADATA. `al` and
    # `agent-ledger` are what a user types after installing; the distribution
    # rename must not have taken them with it.
    entry_points = next((n for n in wnames if n.endswith(".dist-info/entry_points.txt")), None)
    if entry_points is None:
        problems.append("the wheel declares no console scripts")
    else:
        scripts = re.findall(
            r"^([\w-]+)\s*=\s*agent_ledger\.cli:main$",
            zipfile.ZipFile(wheel).read(entry_points).decode("utf-8"),
            re.M,
        )
        print(f"  name={declared} version={wheel_version} console scripts={scripts}")
        if set(scripts) != {"al", "agent-ledger"}:
            problems.append(f"console scripts are {scripts}, expected ['al', 'agent-ledger']")
    if problems:
        print_problems(problems)
        return 1

    print(f"artefacts ok: {name} {version}")
    return 0


def print_problems(problems: list[str]) -> None:
    print("artefact audit failed:")
    for problem in problems:
        print(f"  - {problem}")


if __name__ == "__main__":
    raise SystemExit(main())
