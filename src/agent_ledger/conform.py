"""ARD conformance — making "implements ARD" checkable in one command.

The specification ships an official conformance CLI, and the honest first
sentence is that this module is **not** it. This is the same checks implemented
locally, and the reason is not NIH: a conformance command that needs the network
before it can tell you anything is a command nobody runs in CI, and one that
shells out to a script the reader has to install first is a command nobody
starts. So the checks live here, dependency-free, and :func:`run_official` will
drive the real tool when it is available for a second opinion.

Every rule below cites the section it comes from, because a conformance report
that cannot be argued with is a conformance report nobody trusts. Where the
specification is explicit that something is a *warning* rather than an error —
``representativeQueries`` is the main one — it is reported as a warning, and the
distinction is preserved all the way out to the exit code.

What this checks, and what it deliberately does not:

* **Manifest validation** (§4.2, §4.3, §4.5.1, §D.2): required terms, the
  value-or-reference rule, URN shape, ``representativeQueries`` presence and
  size, publisher-authority binding, and media-type sanity.
* **Publisher resolution** (§5.1): the normative well-known path, with the
  predecessor path as a courtesy and a warning, because a publisher reachable
  only at the old path may not be discovered at all.
* **Registry probing** (§5.3.2, §5.3.3, §5.3.4): ``POST /search`` is mandated and
  is probed as a hard requirement; ``POST /explore`` and ``GET /agents`` are
  optional, and a 404 or 501 from either is conformance, not failure.

It does **not** verify cryptographic trust manifests (§4.5.2 delegates that to
whatever framework the manifest declares), and it does not validate against the
JSON Schema, which needs ``jsonschema`` — :func:`run_official` and the optional
schema check in the CLI are where those belong.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ._identity import USER_AGENT
from .ard import PREDECESSOR_PATH, WELL_KNOWN_PATH
from .models import parse_ard_urn

__all__ = [
    "ConformanceReport",
    "Finding",
    "check_manifest",
    "check_registry",
    "resolve_publisher",
    "run_official",
]

#: The URN grammar of Appendix C: `urn:air:<publisher>:<namespace>:<agent-name>`,
#: where `<publisher>` is a fully qualified domain name. The domain shape is
#: checked rather than merely the segment count, because the whole point of the
#: form is that the publisher is resolvable through DNS.
_FQDN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

#: ARD §3.3 says `type` is an IANA media type. This is deliberately loose — the
#: type space is open by design, and rejecting an extension type would defeat the
#: extension mechanism — so it checks *shape*, not membership.
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")


@dataclass(frozen=True, slots=True)
class Finding:
    """One conformance observation, with the section that produced it."""

    level: str  # "error" | "warning" | "info"
    code: str
    detail: str
    where: str = ""
    section: str = ""

    @property
    def is_error(self) -> bool:
        return self.level == "error"

    def describe(self) -> str:
        location = f" [{self.where}]" if self.where else ""
        citation = f" (ARD {self.section})" if self.section else ""
        return f"{self.level}: {self.detail}{location}{citation}"


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    """Everything one run found, errors and warnings kept apart.

    ``ok`` is about errors only. Conflating the two would make
    ``representativeQueries`` — which the specification explicitly flags as a
    warning, so that output from existing tooling still validates — into a hard
    failure, and a checker that rejects conformant input is worse than no checker.
    """

    subject: str
    findings: tuple[Finding, ...] = ()
    checked: int = 0
    mode: str = "manifest"

    @property
    def errors(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.level == "error")

    @property
    def warnings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.level == "warning")

    @property
    def ok(self) -> bool:
        return not self.errors

    def describe(self) -> str:
        bits = [f"{self.checked} checked"]
        if self.errors:
            bits.append(f"{len(self.errors)} error(s)")
        if self.warnings:
            bits.append(f"{len(self.warnings)} warning(s)")
        if self.ok and not self.warnings:
            bits.append("conformant")
        return f"{self.subject}: " + ", ".join(bits)

    def to_json(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "mode": self.mode,
            "ok": self.ok,
            "checked": self.checked,
            "errors": [f.describe() for f in self.errors],
            "warnings": [f.describe() for f in self.warnings],
            "findings": [
                {
                    "level": f.level,
                    "code": f.code,
                    "detail": f.detail,
                    "where": f.where,
                    "section": f.section,
                }
                for f in self.findings
            ],
        }


# --------------------------------------------------------------------------- #
# Entry rules
# --------------------------------------------------------------------------- #


def _check_entry(raw: Mapping[str, Any], where: str) -> list[Finding]:
    """Every structural rule an ARD entry must satisfy (§4.2, §4.3, §4.5.1)."""
    out: list[Finding] = []

    for term in ("identifier", "displayName", "type"):
        if not raw.get(term):
            out.append(Finding("error", "entry.missing_term", f"{term} is required", where, "§4.2"))

    identifier = raw.get("identifier")
    if isinstance(identifier, str) and identifier:
        parsed = parse_ard_urn(identifier)
        if parsed is None:
            out.append(
                Finding(
                    "error",
                    "entry.urn_shape",
                    f"{identifier!r} is not urn:air:<publisher>:<namespace>:<name>",
                    where,
                    "Appendix C",
                )
            )
        else:
            publisher, _, name = parsed
            if not _FQDN.match(publisher.lower()):
                out.append(
                    Finding(
                        "error",
                        "entry.publisher_not_fqdn",
                        f"publisher {publisher!r} is not a fully qualified domain name; the "
                        "authority anchor is what makes the identifier verifiable",
                        where,
                        "Appendix C",
                    )
                )
            if not name:
                out.append(
                    Finding("error", "entry.empty_name", "agent name is empty", where, "Appendix C")
                )

    # §4.3: exactly one of url or data.
    has_url = raw.get("url") is not None
    has_data = raw.get("data") is not None
    if has_url and has_data:
        out.append(
            Finding(
                "error",
                "entry.url_and_data",
                "an entry MUST NOT carry both url and data",
                where,
                "§4.3",
            )
        )
    elif not has_url and not has_data:
        out.append(
            Finding(
                "error",
                "entry.no_target",
                "an entry MUST carry exactly one of url or data",
                where,
                "§4.3",
            )
        )

    media_type = raw.get("type")
    if isinstance(media_type, str) and media_type and not _MEDIA_TYPE.match(media_type):
        out.append(
            Finding(
                "warning",
                "entry.media_type",
                f"{media_type!r} is not shaped like an IANA media type",
                where,
                "§3.3",
            )
        )

    # §4.2 / §D.2: representativeQueries is a SHOULD, 2-5 examples, and the
    # specification is explicit that a shortfall is a warning rather than a
    # validation failure — existing tooling must still validate.
    queries = raw.get("representativeQueries")
    if queries is None:
        out.append(
            Finding(
                "warning",
                "entry.no_queries",
                "no representativeQueries: the registry's semantic index is built from "
                "them, so this is a valid catalog entry but not a discoverable ARD entry",
                where,
                "§4.2",
            )
        )
    elif isinstance(queries, Sequence) and not isinstance(queries, (str, bytes)):
        if not 2 <= len(queries) <= 5:
            out.append(
                Finding(
                    "warning",
                    "entry.query_count",
                    f"{len(queries)} representativeQueries; the specification expects 2-5",
                    where,
                    "§D.2",
                )
            )
    else:
        out.append(
            Finding(
                "error", "entry.query_type", "representativeQueries must be an array", where, "§4.2"
            )
        )

    if raw.get("capabilities") is not None and not isinstance(raw.get("capabilities"), Sequence):
        out.append(
            Finding(
                "error", "entry.capabilities_type", "capabilities must be an array", where, "§4.2"
            )
        )

    # §4.5.1 publisher-authority binding. The manifest cannot be *verified* here
    # — ARD §4.5.2 delegates that to the declared trust framework — but an
    # obvious contradiction is checkable, and it is the specification's stated
    # defence against namespace squatting.
    manifest = raw.get("trustManifest")
    if isinstance(manifest, Mapping) and isinstance(identifier, str):
        identity = manifest.get("identity")
        parsed = parse_ard_urn(identifier)
        if identity and parsed and parsed[0] not in str(identity):
            out.append(
                Finding(
                    "error",
                    "entry.publisher_binding",
                    f"identifier claims {parsed[0]!r} but trustManifest.identity is "
                    f"{identity!r}; a verifying registry rejects this",
                    where,
                    "§4.5.1",
                )
            )
    return out


def check_manifest(document: Any, *, subject: str = "manifest") -> ConformanceReport:
    """Validate an ARD manifest — a ``/.well-known/ard.json`` document (§5.1).

    Accepts either the document object or a bare list of entries, because
    publishers in the wild do both and the specification's ``ardManifest``
    definition wraps the common case in ``entries``.
    """
    findings: list[Finding] = []

    if isinstance(document, list):
        entries: Sequence[Any] = document
    elif isinstance(document, Mapping):
        raw_entries = document.get("entries")
        if raw_entries is None:
            findings.append(
                Finding(
                    "error",
                    "manifest.no_entries",
                    "a manifest MUST have an 'entries' array",
                    subject,
                    "§5.1",
                )
            )
            entries = []
        elif not isinstance(raw_entries, Sequence) or isinstance(raw_entries, (str, bytes)):
            findings.append(
                Finding(
                    "error", "manifest.entries_type", "'entries' must be an array", subject, "§5.1"
                )
            )
            entries = []
        else:
            entries = raw_entries
        # §D.2: a 'collections' root member was removed under ADR-0003. ARD
        # ignores unrecognised top-level members, so this is informational.
        if "collections" in document:
            findings.append(
                Finding(
                    "warning",
                    "manifest.legacy_collections",
                    "'collections' was removed under ADR-0003 and is ignored",
                    subject,
                    "ADR-0003",
                )
            )
    else:
        return ConformanceReport(
            subject=subject,
            mode="manifest",
            findings=(
                Finding(
                    "error",
                    "manifest.not_an_object",
                    f"expected a JSON object or array, got {type(document).__name__}",
                    subject,
                    "§5.1",
                ),
            ),
        )

    checked = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            findings.append(
                Finding(
                    "error",
                    "entry.not_an_object",
                    f"entry {index} is a {type(entry).__name__}, not an object",
                    f"entries[{index}]",
                    "§4",
                )
            )
            continue
        checked += 1
        findings.extend(_check_entry(entry, _entry_label(entry, index)))

    if not entries:
        findings.append(
            Finding(
                "warning",
                "manifest.empty",
                "the manifest declares no entries, so this domain publishes nothing discoverable",
                subject,
                "§5.1",
            )
        )

    return ConformanceReport(
        subject=subject, findings=tuple(findings), checked=checked, mode="manifest"
    )


def _entry_label(entry: Mapping[str, Any], index: int) -> str:
    identifier = entry.get("identifier")
    return str(identifier) if identifier else f"entries[{index}]"


# --------------------------------------------------------------------------- #
# Publisher resolution (§5.1)
# --------------------------------------------------------------------------- #


def _get_json(url: str, timeout: float) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def resolve_publisher(domain: str, *, timeout: float = 15.0) -> ConformanceReport:
    """Resolve a domain the way a conformant consumer does (§5.1).

    Fetches the normative path, falls back to the predecessor path, and warns
    when only the old one answers — because consulting it is *optional* for
    consumers, so a publisher reachable only there may not be found at all. That
    warning is the single most useful thing this mode produces: it is the
    difference between "your manifest is valid" and "your manifest is valid and
    nobody will see it".
    """
    host = domain.strip().rstrip("/")
    if "://" in host:
        host = host.split("://", 1)[1].split("/", 1)[0]

    findings: list[Finding] = []
    primary = f"https://{host}{WELL_KNOWN_PATH}"
    try:
        document = _get_json(primary, timeout)
    except urllib.error.HTTPError as exc:
        findings.append(
            Finding(
                "info",
                "publisher.normative_path_absent",
                f"HTTP {exc.code} from {primary}",
                primary,
                "§5.1",
            )
        )
        document = None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return ConformanceReport(
            subject=host,
            mode="publisher",
            findings=(
                Finding(
                    "error",
                    "publisher.unreachable",
                    f"cannot reach {primary}: {exc}",
                    primary,
                    "§5.1",
                ),
            ),
        )

    if document is None:
        fallback = f"https://{host}{PREDECESSOR_PATH}"
        try:
            document = _get_json(fallback, timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
            return ConformanceReport(
                subject=host,
                mode="publisher",
                findings=(
                    *findings,
                    Finding(
                        "error",
                        "publisher.nothing_published",
                        f"no manifest at {primary} or {fallback}: {exc}",
                        host,
                        "§5.1",
                    ),
                ),
            )
        findings.append(
            Finding(
                "warning",
                "publisher.predecessor_path_only",
                f"resolved from {fallback}. Consulting that path is OPTIONAL for "
                "consumers, so this publisher may not be discovered at all — serve "
                f"{WELL_KNOWN_PATH} instead",
                host,
                "§5.1",
            )
        )
    else:
        findings.append(
            Finding("info", "publisher.resolved", f"resolved from {primary}", primary, "§5.1")
        )

    manifest = check_manifest(document, subject=host)
    return ConformanceReport(
        subject=host,
        mode="publisher",
        findings=(*findings, *manifest.findings),
        checked=manifest.checked,
    )


# --------------------------------------------------------------------------- #
# Registry probing (§5.3)
# --------------------------------------------------------------------------- #


def _post_json(url: str, payload: Mapping[str, Any], timeout: float) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ConnectionError(str(exc)) from exc


def check_registry(base_url: str, *, timeout: float = 15.0) -> ConformanceReport:
    """Probe a registry's REST API (§5.3.2, §5.3.3, §5.3.4).

    Only ``POST /search`` is mandated. ``POST /explore`` and ``GET /agents`` are
    optional, and a 404 or 501 from either is **conformance**, not failure —
    reporting an optional endpoint's absence as an error is the most common way
    a conformance tool is wrong, and it wastes the reader's afternoon.
    """
    base = base_url.rstrip("/")
    findings: list[Finding] = []
    checked = 0

    # --- POST /search: required (§5.3.2) ------------------------------------ #
    search_url = f"{base}/search"
    try:
        status, document = _post_json(search_url, {"query": {"text": "conformance probe"}}, timeout)
    except ConnectionError as exc:
        return ConformanceReport(
            subject=base,
            mode="registry",
            findings=(
                Finding(
                    "error",
                    "registry.unreachable",
                    f"cannot reach {search_url}: {exc}",
                    search_url,
                    "§5.3.2",
                ),
            ),
        )

    if status != 200:
        findings.append(
            Finding(
                "error",
                "registry.search_status",
                f"POST /search returned {status}; a registry MUST expose it",
                search_url,
                "§5.3.2",
            )
        )
    elif not isinstance(document, Mapping) or not isinstance(document.get("results"), list):
        findings.append(
            Finding(
                "error",
                "registry.search_shape",
                "POST /search must return an object with a 'results' array",
                search_url,
                "§5.3.2",
            )
        )
    else:
        checked += 1
        findings.append(
            Finding(
                "info",
                "registry.search_ok",
                f"POST /search returned {len(document['results'])} result(s)",
                search_url,
                "§5.3.2",
            )
        )
        for index, result in enumerate(document["results"]):
            if not isinstance(result, Mapping):
                findings.append(
                    Finding(
                        "error",
                        "registry.result_shape",
                        f"result {index} is not an object",
                        search_url,
                        "§5.3.2",
                    )
                )
                continue
            # §5.3.2: `identifier` is the ONE term a result must carry. Every
            # other term is the registry's discretion, and flagging a missing
            # `url` as an error would reject the shape the specification says is
            # normal.
            if not result.get("identifier"):
                findings.append(
                    Finding(
                        "error",
                        "registry.result_no_identifier",
                        f"result {index} carries no identifier, which is the one term "
                        "a search result MUST have",
                        search_url,
                        "§5.3.2",
                    )
                )
            score = result.get("score")
            if score is not None and not isinstance(score, (int, float)):
                findings.append(
                    Finding(
                        "warning",
                        "registry.score_type",
                        f"result {index} has a non-numeric score",
                        search_url,
                        "§5.3.2",
                    )
                )

    # --- POST /explore: optional (§5.3.3) ----------------------------------- #
    explore_url = f"{base}/explore"
    try:
        status, document = _post_json(
            explore_url,
            {"query": {}, "resultType": {"facets": [{"field": "type"}]}},
            timeout,
        )
    except ConnectionError as exc:
        findings.append(
            Finding("info", "registry.explore_unreachable", str(exc), explore_url, "§5.3.3")
        )
    else:
        if status in (404, 501):
            findings.append(
                Finding(
                    "info",
                    "registry.explore_absent",
                    f"{status}: explore is optional, so this is conformant",
                    explore_url,
                    "§5.3.3",
                )
            )
        elif status == 200:
            checked += 1
            if not isinstance(document, Mapping) or not isinstance(document.get("facets"), Mapping):
                findings.append(
                    Finding(
                        "error",
                        "registry.explore_shape",
                        "explore must return a 'facets' object",
                        explore_url,
                        "§5.3.3",
                    )
                )
        else:
            findings.append(
                Finding(
                    "warning",
                    "registry.explore_status",
                    f"explore returned {status}; 404 or 501 is the conformant way to decline",
                    explore_url,
                    "§5.3.3",
                )
            )

    # --- GET /agents: optional (§5.3.4) ------------------------------------- #
    agents_url = f"{base}/agents"
    try:
        request = urllib.request.Request(
            agents_url,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            status = response.status
            document = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status, document = exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        status, document = 0, None
        findings.append(
            Finding("info", "registry.agents_unreachable", str(exc), agents_url, "§5.3.4")
        )

    if status in (404, 501):
        findings.append(
            Finding(
                "info",
                "registry.agents_absent",
                f"{status}: deterministic listing is optional, so this is conformant",
                agents_url,
                "§5.3.4",
            )
        )
    elif status == 200:
        checked += 1
        if not isinstance(document, Mapping) or not isinstance(document.get("items"), list):
            findings.append(
                Finding(
                    "warning",
                    "registry.agents_shape",
                    "GET /agents should return a paginated 'items' array",
                    agents_url,
                    "§5.3.4",
                )
            )

    return ConformanceReport(
        subject=base, mode="registry", findings=tuple(findings), checked=checked
    )


# --------------------------------------------------------------------------- #
# The official tool, as a second opinion
# --------------------------------------------------------------------------- #


def run_official(*args: str, tool: str = "conformance-test") -> tuple[int, str]:
    """Run the specification's own conformance CLI, if it is on ``PATH``.

    Offered rather than required. The tool is the authority, so a reader who
    wants the final word should have it — but making it a prerequisite would mean
    this command cannot run in a fresh container, which is exactly where a
    conformance check is most useful.

    Returns ``(exit_code, output)``. An absent tool is reported as exit code 127,
    the shell's own convention for "command not found", so a caller can
    distinguish it from a conformance failure without parsing prose.
    """
    import shutil
    import subprocess

    resolved = shutil.which(tool)
    if resolved is None:
        return 127, (
            f"{tool} is not on PATH. It ships with the specification at "
            "https://github.com/ards-project/ard-spec (conformance/bin/). "
            "The built-in checks run without it."
        )
    completed = subprocess.run(  # noqa: S603
        [resolved, *args], capture_output=True, text=True, check=False
    )
    return completed.returncode, (completed.stdout + completed.stderr).strip()
