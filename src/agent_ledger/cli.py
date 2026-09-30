"""Command line interface.

    al demo                      # the whole project in 30 seconds, offline
    al find "review a contract" --registry URL
    al delegate "review the DPA" -c contract_review --registry URL --budget 0.5
    al audit  --ledger grid.jsonl
    al verify --ledger grid.jsonl

Everything the CLI does is available as a library call. The CLI exists so that
``uvx agent-ledger demo`` works with no setup at all.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .ard import ArdClient, ArdError, HttpTransport
from .ledger import Ledger
from .models import DelegationStatus, Task
from .policy import Policy
from .render import BOLD, DIM, GREEN, RED, YELLOW, c, g, header, kv, rule, tree
from .router import Grid, GridConfig
from .signing import HmacSigner, KeyRing

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_REFUSED = 2


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    if args.json:
        import io
        import os
        from contextlib import redirect_stdout

        os.environ["NO_COLOR"] = "1"
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            result = run_demo(colour=False)
        payload = {
            "chain_length": result.chain_length,
            "total_cost_usd": result.total_cost_usd,
            "delegations": result.delegations,
            "refusals": result.refusals,
            "integrity_ok": result.integrity_ok,
            "ranking_before": result.ranking_before,
            "ranking_after": result.ranking_after,
            "transcript": buffer.getvalue().splitlines(),
        }
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    result = run_demo(colour=not args.no_color)
    return EXIT_OK if result.integrity_ok else EXIT_FAILURE


def _cmd_find(args: argparse.Namespace) -> int:
    client = ArdClient(HttpTransport(), verify_publisher_binding=not args.no_verify)
    entries = client.discover(
        domains=args.domain or (),
        registries=args.registry or (),
        text=args.query,
        filter={"capabilities": args.capability} if args.capability else None,
    )

    if args.json:
        print(json.dumps([e.to_ard() | {"source": e.source} for e in entries], indent=2))
        return EXIT_OK if entries else EXIT_FAILURE

    if not entries:
        print(c("no entries found", YELLOW))
        return EXIT_FAILURE

    print(rule(f"ARD discovery · {len(entries)} entries"))
    for entry in entries:
        if entry.is_trusted:
            trust = c(f" {g('check')}trust", GREEN)
        else:
            trust = c(f" {g('cross')}untrusted", RED)
        print(f"\n  {c(entry.display_name, BOLD)}{trust}")
        print(c(f"    {entry.identifier}", DIM))
        if entry.description:
            print(f"    {entry.description}")
        if entry.capabilities:
            print(c(f"    capabilities: {', '.join(entry.capabilities)}", DIM))
        if entry.source:
            print(c(f"    source: {entry.source}", DIM))
    return EXIT_OK


def _cmd_delegate(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger) if args.ledger else None
    signer = _signer_from_env(args)
    if signer is not None and ledger_path is None:
        # Signing into an in-memory ledger signs nothing anyone can check, which
        # is worse than not signing: it looks like evidence.
        print(
            c(
                "--sign-key-env requires --ledger: signed receipts are only useful "
                "where they are stored.",
                RED,
            ),
            file=sys.stderr,
        )
        return EXIT_FAILURE
    ledger = Ledger(ledger_path, ledger_id=args.ledger_id, signer=signer)
    policy = (
        Policy.ceilinged(budget=args.budget, chain=args.chain_budget, depth=args.max_depth)
        if args.budget is not None
        else Policy.open_grid()
    )
    if args.deny_publisher:
        policy = policy.with_(denied_publishers=frozenset(args.deny_publisher))
    if args.require_trust:
        policy = policy.with_(require_trust=True)

    grid = Grid(
        client=ArdClient(HttpTransport()),
        policy=policy,
        ledger=ledger,
        registries=args.registry or (),
        domains=args.domain or (),
        config=GridConfig(record_refusals=not args.no_record_refusals),
    )

    task = Task(
        intent=args.intent,
        required_capabilities=tuple(args.capability or ()),
        issued_by=args.principal,
        budget_usd=args.budget,
    )

    print(rule("delegation"))
    print(kv("intent", task.intent))
    print(kv("requires", ", ".join(task.required_capabilities) or c("(any)", DIM)))
    budget_label = f"${task.budget_usd:.2f}" if task.budget_usd is not None else c("uncapped", DIM)
    print(kv("budget", budget_label))
    print(kv("policy", c(policy.name, YELLOW)))

    outcome = grid.delegate(task)

    print()
    for line in outcome.explain():
        print("  " + line)

    if not outcome.ok:
        print()
        print(c(f"  refused: {outcome.reason}", RED))
        if ledger_path:
            print(c(f"  refusal recorded in {ledger_path}", DIM))
        return EXIT_REFUSED

    assert outcome.delegation is not None
    if args.dry_run:
        print()
        print(c("  dry run — nothing executed", YELLOW))
        return EXIT_OK

    if args.execute:
        result = grid.dispatch(task)
        assert result.receipt is not None
        print()
        print(kv("outcome", result.receipt.outcome.value))
        print(kv("cost", f"${result.receipt.cost_usd:.4f}"))
        print(kv("receipt", c(result.receipt.receipt_id, DIM)))
    else:
        grid.accept(outcome.delegation)
        print()
        print(c("  accepted — settle with grid.complete(...) or al audit", DIM))

    if ledger_path:
        print(kv("ledger", str(ledger_path)))
    return EXIT_OK


def _cmd_audit(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger)
    if not len(ledger):
        print(c(f"no receipts in {args.ledger}", YELLOW))
        return EXIT_FAILURE

    chains = [ledger.chain(r) for r in [args.receipt]] if args.receipt else ledger.chains()

    if args.json:
        print(json.dumps([ch.to_json() for ch in chains], indent=2))
        return EXIT_OK

    stats = ledger.stats()
    print(rule("ledger"))
    print(kv("stats", stats.describe()))
    print(kv("integrity", ledger.verify().describe()))

    for index, chain in enumerate(chains, start=1):
        print(header(index, f"chain · {len(chain)} hops · ${chain.total_cost:.4f}"))
        lines = []
        for receipt in chain:
            colour = {
                DelegationStatus.COMPLETED: GREEN,
                DelegationStatus.FAILED: RED,
                DelegationStatus.REVOKED: YELLOW,
            }.get(receipt.outcome, DIM)
            lines.append(
                (
                    receipt.depth,
                    f"{receipt.delegate.rsplit(':', 1)[-1]:<26}"
                    + c(receipt.outcome.value, colour)
                    + c(f"  ${receipt.cost_usd:.4f}", DIM),
                )
            )
            lines.append(
                (
                    receipt.depth,
                    c(f"{receipt.receipt_id}  {receipt.note or '—'}", DIM),
                )
            )
        print(tree(lines))
        if not chain.is_clean:
            for problem in chain.violations():
                print(c(f"  ! {problem}", RED))
    return EXIT_OK


def _signer_from_env(args: argparse.Namespace) -> HmacSigner | None:
    """Build a signer from the environment, or ``None`` if none was requested.

    The secret is read from an environment variable and **never** taken as a
    command-line argument. An argv value is visible in ``ps`` output and lands in
    shell history, and a signing key in a process listing is a finding waiting to
    be filed. This is the one place in the CLI where ergonomics loses to
    security on purpose.
    """
    variable = getattr(args, "sign_key_env", None)
    if not variable:
        return None
    secret = os.environ.get(variable)
    if not secret:
        raise SystemExit(f"--sign-key-env {variable} was given but ${variable} is empty or unset")
    return HmacSigner(
        secret=secret.encode("utf-8"),
        key_id=getattr(args, "key_id", "cli"),
        # The principal the signature claims. On its own that is a *claim*; it
        # becomes evidence only when a pinned keyring agrees, which is why
        # --keyring exists.
        principal=getattr(args, "signer", None),
    )


def _keyring_from_args(args: argparse.Namespace) -> KeyRing | None:
    path = getattr(args, "keyring", None)
    if not path:
        return None
    try:
        return KeyRing.load(path)
    except (OSError, ValueError, KeyError) as exc:
        # A trust store that cannot be read is not a reason to verify without
        # one. Silently dropping it would report every signed line as unknown,
        # which looks like a ledger problem and sends the operator to the wrong
        # artefact.
        raise SystemExit(f"cannot load keyring {path}: {exc}") from exc


def _cmd_verify(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger, ledger_id=args.ledger_id, keyring=_keyring_from_args(args))
    signer = _signer_from_env(args)
    integrity = ledger.verify(
        require_signature=args.require_signature,
        verifier=signer,
    )

    # An expected head is what turns tail truncation from undetectable into
    # detected: a shortened prefix is a perfectly consistent chain, so the only
    # way to notice is to know what the end should have been.
    head_mismatch = False
    if args.expect_head:
        head_mismatch = integrity.chain_head != args.expect_head

    ok = integrity.ok and not head_mismatch
    if args.json:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "checked": integrity.checked,
                    "signed": integrity.signed,
                    "chain_head": integrity.chain_head,
                    "expected_head": args.expect_head,
                    "head_matches": not head_mismatch if args.expect_head else None,
                    "tampered": list(integrity.tampered),
                    "malformed": list(integrity.malformed),
                    "no_digest": list(integrity.no_digest),
                    "broken_chain": list(integrity.broken_chain),
                    "orphaned": list(integrity.orphaned),
                    "duplicated": list(integrity.duplicated),
                    "bad_signature": list(integrity.bad_signature),
                    "unknown_key": list(integrity.unknown_key),
                    "unknown_alg": list(integrity.unknown_alg),
                    "unchained": integrity.unchained,
                },
                indent=2,
            )
        )
        return EXIT_OK if ok else EXIT_FAILURE

    print(c(f"{'OK' if ok else 'FAILED'}: {integrity.describe()}", GREEN if ok else RED))
    if not ok and (integrity.broken_chain or integrity.bad_signature):
        # The most likely cause of both at once, and the least guessable. The
        # ledger identity is deliberately *not* stored in the file — binding it is
        # what stops a receipt being replayed into another ledger — so a verifier
        # that was not told which identity to use checks against the wrong thing
        # and sees corruption where there is none.
        print(
            c(
                f"  checked against ledger identity {integrity.ledger_id!r}. If this "
                "ledger was written under a different identity, every link and every "
                "signature will look wrong; set the original identity and retry.",
                YELLOW,
            )
        )
    if head_mismatch:
        print(
            c(
                f"  head mismatch: the ledger ends at {integrity.chain_head}, "
                f"expected {args.expect_head}",
                RED,
            )
        )
        print(
            c(
                "  A shortened prefix is a consistent chain, so this is the only way to detect it.",
                DIM,
            )
        )
    for label, findings in (
        ("tampered", integrity.tampered),
        ("no digest", integrity.no_digest),
        ("broken chain", integrity.broken_chain),
        ("bad signature", integrity.bad_signature),
        ("unknown key", integrity.unknown_key),
        ("unknown algorithm", integrity.unknown_alg),
        ("orphaned parent", integrity.orphaned),
        ("duplicated id", integrity.duplicated),
    ):
        for finding in findings:
            print(c(f"  {label}: {finding}", RED))

    if integrity.chain_head:
        print(c(f"  head: {integrity.chain_head}", DIM))
        print(
            c(
                "  Publish this out of band (a commit, a peer, a release artifact) and "
                "pass it to --expect-head next time.",
                DIM,
            )
        )
    return EXIT_OK if ok else EXIT_FAILURE


def _cmd_bundle_export(args: argparse.Namespace) -> int:
    """Package receipts for another organisation."""
    from .bundle import export_bundle, write_bundle

    ledger = Ledger(args.ledger, ledger_id=args.ledger_id)
    bundle = export_bundle(
        ledger,
        note=args.note or "",
        receipt_ids=args.receipt or None,
        metadata={"generator": f"agent-ledger/{__version__}"},
    )
    write_bundle(bundle, args.out)

    if args.json:
        print(
            json.dumps(
                {
                    "out": str(args.out),
                    "ledger_id": bundle.ledger_id,
                    "head": bundle.head,
                    "lines": len(bundle.lines),
                },
                indent=2,
            )
        )
        return EXIT_OK

    print(rule("bundle exported"))
    print(kv("file", str(args.out)))
    print(kv("ledger", bundle.ledger_id))
    print(kv("lines", str(len(bundle.lines))))
    if bundle.head:
        print(kv("head", c(bundle.head, DIM)))
    print(
        c(
            "\n  Send the head over a channel you already trust. A bundle can be\n"
            "  shortened and still verify — a truncated prefix is a consistent\n"
            "  chain — so `bundle verify --expect-head` is what catches it.",
            DIM,
        )
    )
    return EXIT_OK


def _cmd_bundle_verify(args: argparse.Namespace) -> int:
    """Check a bundle from another organisation, trusting only pinned keys."""
    from .bundle import read_bundle, verify_bundle

    try:
        bundle = read_bundle(args.bundle)
    except (OSError, ValueError) as exc:
        print(c(f"cannot read bundle: {exc}", RED), file=sys.stderr)
        return EXIT_FAILURE

    keyring = _keyring_from_args(args)
    if args.require_signature and keyring is None:
        # Without keys there is nothing to check, and reporting "OK" for a bundle
        # nobody verified is exactly the failure this whole exchange exists to
        # prevent.
        print(
            c(
                "--require-signature needs --keyring: a bundle is evidence offered "
                "by someone else, and without their keys there is nothing to check.",
                RED,
            ),
            file=sys.stderr,
        )
        return EXIT_FAILURE

    result = verify_bundle(
        bundle,
        keyring=keyring,
        expected_head=args.expect_head,
        require_signature=args.require_signature,
    )

    if args.json:
        print(json.dumps(result.to_json(), indent=2))
        return EXIT_OK if result.ok else EXIT_FAILURE

    print(
        c(f"{'OK' if result.ok else 'REJECTED'}: {result.describe()}", GREEN if result.ok else RED)
    )
    for problem in result.problems:
        print(c(f"  {problem}", RED))
    if result.ok and args.expect_head is None:
        print(
            c(
                "  No --expect-head was given, so completeness was not checked: this\n"
                "  bundle may be a truthful excerpt of a longer ledger.",
                YELLOW,
            )
        )
    return EXIT_OK if result.ok else EXIT_FAILURE


def _emit_conformance(report, *, as_json: bool) -> int:
    """Print a conformance report and return the exit code.

    The exit code follows the error/warning split the specification draws. A
    warning is not a failure: ARD §D.2 explicitly makes ``representativeQueries``
    a warning so that output from existing tooling still validates, and a checker
    that fails conformant input is worse than no checker.
    """
    if as_json:
        print(json.dumps(report.to_json(), indent=2))
        return EXIT_OK if report.ok else EXIT_FAILURE

    print(c(f"{'PASS' if report.ok else 'FAIL'}: {report.describe()}", GREEN if report.ok else RED))
    for finding in report.errors:
        print(c(f"  {finding.describe()}", RED))
    for finding in report.warnings:
        print(c(f"  {finding.describe()}", YELLOW))
    for finding in report.findings:
        if finding.level == "info":
            print(c(f"  {finding.describe()}", DIM))
    return EXIT_OK if report.ok else EXIT_FAILURE


def _cmd_conform(args: argparse.Namespace) -> int:
    """Check a manifest, a publisher domain, or a registry against ARD."""
    from .conform import check_manifest, check_registry, resolve_publisher, run_official

    if args.official:
        code, output = run_official(*args.official_args)
        if output:
            print(output)
        if code != 127:
            return EXIT_OK if code == 0 else EXIT_FAILURE
        print(c("  the official tool is absent; using the built-in checks", YELLOW))

    target = args.target

    if args.what == "manifest":
        # A local path or a URL. Fetching a live manifest is the common case, and
        # the specification's own tool accepts both.
        if target.startswith(("http://", "https://")):
            import urllib.error
            import urllib.request

            try:
                with urllib.request.urlopen(target, timeout=args.timeout) as response:  # noqa: S310
                    document = json.loads(response.read().decode("utf-8"))
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                print(c(f"cannot fetch {target}: {exc}", RED), file=sys.stderr)
                return EXIT_FAILURE
        else:
            path = Path(target)
            if not path.is_file():
                print(c(f"no such file: {path}", RED), file=sys.stderr)
                return EXIT_FAILURE
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                print(c(f"{path} is not valid JSON: {exc}", RED), file=sys.stderr)
                return EXIT_FAILURE
        report = check_manifest(document, subject=target)
    elif args.what == "publisher":
        report = resolve_publisher(target, timeout=args.timeout)
    else:
        report = check_registry(target, timeout=args.timeout)

    return _emit_conformance(report, as_json=args.json)


def _cmd_policy(args: argparse.Namespace) -> int:
    presets = {
        "open-grid": Policy.open_grid(),
        "ceilinged": Policy.ceilinged(),
        "zero-trust": Policy.zero_trust(),
    }
    payload: dict[str, Any] = {
        name: {
            "max_budget_usd": p.max_budget_usd,
            "max_total_cost_usd": p.max_total_cost_usd,
            "max_depth": p.max_depth,
            "require_trust": p.require_trust,
        }
        for name, p in presets.items()
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(rule("policy presets"))
        for name, spec in payload.items():
            print(c(f"\n  {name}", BOLD))
            for key, value in spec.items():
                print(kv(key, c(str(value), DIM), key_width=22, indent=4))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="al",
        description=(
            "Accountable delegation for AI agents. ARD finds agents, A2A talks to "
            "them; this owns capability matching, delegated authority and receipts."
        ),
        epilog="Run 'al demo' for a complete offline walkthrough.",
    )
    parser.add_argument("--version", action="version", version=f"agent-ledger {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the full offline demonstration")
    demo.add_argument("--json", action="store_true", help="emit machine-readable output")
    demo.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    demo.set_defaults(func=_cmd_demo)

    find = sub.add_parser("find", help="discover agents through ARD")
    find.add_argument("query", help="natural-language description of the need")
    find.add_argument("--registry", action="append", help="registry search endpoint (repeatable)")
    find.add_argument("--domain", action="append", help="domain publishing /.well-known/ard.json")
    find.add_argument("-c", "--capability", action="append", help="required capability token")
    find.add_argument("--no-verify", action="store_true", help="skip ARD publisher binding check")
    find.add_argument("--json", action="store_true")
    find.set_defaults(func=_cmd_find)

    delegate = sub.add_parser("delegate", help="place a task with the best eligible agent")
    delegate.add_argument("intent", help="what needs doing")
    delegate.add_argument(
        "--registry", action="append", help="registry search endpoint (repeatable)"
    )
    delegate.add_argument(
        "--domain", action="append", help="domain publishing /.well-known/ard.json"
    )
    delegate.add_argument("-c", "--capability", action="append", help="required capability token")
    delegate.add_argument(
        "--principal", default="urn:principal:cli", help="who is authorising this"
    )
    delegate.add_argument("--budget", type=float, help="per-delegation budget in USD")
    delegate.add_argument("--chain-budget", type=float, default=10.0, help="total chain ceiling")
    delegate.add_argument("--max-depth", type=int, default=3, help="maximum delegation depth")
    delegate.add_argument("--deny-publisher", action="append", help="publisher domain to refuse")
    delegate.add_argument("--require-trust", action="store_true", help="demand a trustManifest")
    delegate.add_argument("--ledger", help="JSONL ledger path (records the receipt)")
    delegate.add_argument(
        "--ledger-id",
        help="identity to bind chain links and signatures to; set it explicitly if "
        "more than one ledger exists, so receipts cannot be replayed between them",
    )
    delegate.add_argument(
        "--sign-key-env",
        metavar="VAR",
        help="sign every receipt with the HMAC secret in environment variable VAR",
    )
    delegate.add_argument("--key-id", default="cli", help="key identifier recorded on signed lines")
    delegate.add_argument(
        "--signer",
        metavar="PRINCIPAL",
        help="the principal each signature claims, e.g. urn:principal:acme.com:grid",
    )
    delegate.add_argument("--execute", action="store_true", help="run the delegate after placing")
    delegate.add_argument("--dry-run", action="store_true", help="decide but do not accept")
    delegate.add_argument("--no-record-refusals", action="store_true")
    delegate.set_defaults(func=_cmd_delegate)

    audit = sub.add_parser("audit", help="show delegation chains from a ledger")
    audit.add_argument("--ledger", required=True, help="JSONL ledger path")
    audit.add_argument("--receipt", help="trace one chain from this receipt id")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=_cmd_audit)

    verify = sub.add_parser(
        "verify", help="re-check every receipt digest, chain link and signature"
    )
    verify.add_argument("--ledger", required=True, help="JSONL ledger path")
    verify.add_argument(
        "--ledger-id",
        help="the identity this ledger was written under; chain links and signatures bind to it",
    )
    verify.add_argument(
        "--sign-key-env",
        metavar="VAR",
        help="check HMAC signatures using the secret in environment variable VAR",
    )
    verify.add_argument(
        "--require-signature",
        action="store_true",
        help="fail on any unsigned line, for a ledger that is meant to be signed",
    )
    verify.add_argument(
        "--keyring",
        metavar="FILE",
        help=(
            "pinned trust store; binds each key to a principal, so a signature "
            "names who rather than merely which key"
        ),
    )
    verify.add_argument(
        "--expect-head",
        metavar="DIGEST",
        help="fail unless the ledger ends at this chain head (detects tail truncation)",
    )
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=_cmd_verify)

    policy = sub.add_parser("policy", help="show the built-in policy presets")
    policy.add_argument("--json", action="store_true")
    policy.set_defaults(func=_cmd_policy)

    # Bundle exchange — the cross-organisation path.
    bundle = sub.add_parser("bundle", help="export or verify a signed receipt bundle")
    bundle_sub = bundle.add_subparsers(dest="bundle_command", required=True)

    bundle_export = bundle_sub.add_parser(
        "export", help="package receipts for another organisation"
    )
    bundle_export.add_argument("--ledger", required=True, help="JSONL ledger path")
    bundle_export.add_argument("--ledger-id", help="the identity this ledger was written under")
    bundle_export.add_argument("--out", required=True, help="bundle file to write")
    bundle_export.add_argument(
        "--receipt",
        action="append",
        help="export one delegation by receipt id (repeatable); default is the whole ledger",
    )
    bundle_export.add_argument("--note", help="free text for the recipient")
    bundle_export.add_argument("--json", action="store_true")
    bundle_export.set_defaults(func=_cmd_bundle_export)

    bundle_verify = bundle_sub.add_parser(
        "verify", help="check a bundle, trusting only pinned keys"
    )
    bundle_verify.add_argument("bundle", help="bundle file to verify")
    bundle_verify.add_argument(
        "--keyring",
        metavar="FILE",
        help="pinned trust store for the sender's keys; required with --require-signature",
    )
    bundle_verify.add_argument(
        "--expect-head",
        metavar="DIGEST",
        help="the head obtained over a trusted channel; without it, completeness is unchecked",
    )
    bundle_verify.add_argument(
        "--allow-unsigned",
        dest="require_signature",
        action="store_false",
        help="accept an unsigned bundle (it then proves nothing about authorship)",
    )
    bundle_verify.add_argument("--json", action="store_true")
    bundle_verify.set_defaults(func=_cmd_bundle_verify, require_signature=True)

    # ARD conformance — the claim, made checkable.
    conform = sub.add_parser(
        "conform", help="check a manifest, a publisher domain, or a registry against ARD"
    )
    conform.add_argument(
        "what",
        choices=("manifest", "publisher", "registry"),
        help="manifest: a file or URL · publisher: resolve /.well-known/ard.json · "
        "registry: probe the REST API",
    )
    conform.add_argument("target", help="path, URL or domain depending on the mode")
    conform.add_argument("--timeout", type=float, default=15.0, help="per-request timeout")
    conform.add_argument(
        "--official",
        action="store_true",
        help="run the specification's own conformance CLI instead, if it is on PATH",
    )
    conform.add_argument(
        "official_args",
        nargs="*",
        help="arguments passed through to the official tool with --official",
    )
    conform.add_argument("--json", action="store_true")
    conform.set_defaults(func=_cmd_conform)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ArdError as exc:
        print(c(f"discovery failed: {exc}", RED), file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:  # pragma: no cover
        print(c("\ninterrupted", YELLOW), file=sys.stderr)
        return 130
    except BrokenPipeError:  # pragma: no cover
        return EXIT_OK
    except Exception as exc:  # noqa: BLE001 - a CLI reports, it does not traceback
        # A traceback is a bug report, not a user interface. Anything that
        # escapes a command is unexpected by definition, so name it, point at
        # the report path, and exit non-zero — while keeping the type and
        # message, which is what makes the bug report actionable.
        print(c(f"unexpected error: {type(exc).__name__}: {exc}", RED), file=sys.stderr)
        print(
            c(
                "This is a bug. Report it with the command you ran:\n"
                "  https://github.com/yaoyuxiang-gnn/agent-ledger/issues",
                DIM,
            ),
            file=sys.stderr,
        )
        return EXIT_FAILURE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
