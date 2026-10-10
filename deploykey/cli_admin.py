"""``deploykey`` — inventory sync, health check, launchd audit and key reconcile."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ._common import (
    EXIT_OK,
    EXIT_PROBLEMS,
    EXIT_REFUSED,
    EXIT_USAGE,
    RefusedError,
    helper_sha,
    runtime_path,
)
from .check import Report
from .inventory import Inventory

EPILOG = """\
exit codes: 0 ok, 1 red findings (check/audit), 2 usage, 3 refused/unreadable input

examples:
  deploykey sync -i deploy-keys.toml       # validate + install ~/.ssh/deploy/deploy-keys.json
  deploykey sync -i deploy-keys.toml -n            # validate only
  deploykey check -d -i deploy-keys.toml   # offline: keys, modes, fingerprints, drift, evidence
  deploykey check -j                               # full (probes, stuck commits, policy) as JSON
  deploykey audit -i deploy-keys.toml      # launchd jobs vs audit/launchd-git-calls.json
  deploykey reconcile -i deploy-keys.toml -k github-books-lists-read -n
  deploykey reconcile -i deploy-keys.toml -P -e evidence/891 \
      -k github-runai-cluster-automation-write
  deploykey -V                                     # the installed helper sha
"""


def build_parser() -> argparse.ArgumentParser:
    """The ``deploykey`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="deploykey",
        description="Manage the Mac's repo-scoped deploy keys: inventory, checks, provisioning.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="store_true", help="print the helper sha")
    sub = parser.add_subparsers(dest="cmd")

    sync = sub.add_parser("sync", help="validate the TOML and install the runtime JSON")
    sync.add_argument("-i", "--inventory", required=True, help="source TOML inventory")
    sync.add_argument(
        "-o",
        "--output",
        help="runtime JSON path (default ~/.ssh/deploy/deploy-keys.json)",
    )
    sync.add_argument("-n", "--dry-run", action="store_true", help="validate only, write nothing")

    check = sub.add_parser("check", help="health rules of every row (see module docs)")
    check.add_argument("-i", "--inventory", help="source TOML; also flags runtime-JSON drift")
    check.add_argument(
        "-c",
        "--config",
        help="runtime JSON (default $DEPLOYKEY_CONFIG or the installed one)",
    )
    check.add_argument(
        "-d",
        "--offline",
        action="store_true",
        help="no network: skip probes, stuck, policy",
    )
    check.add_argument("-j", "--json", action="store_true", help="machine-readable output")

    audit = sub.add_parser("audit", help="launchd jobs vs the reviewed network-git audit")
    audit.add_argument("-i", "--inventory", help="source TOML (default audit file sits next to it)")
    audit.add_argument("-c", "--config", help="runtime JSON instead of the TOML")
    audit.add_argument(
        "-a",
        "--audit-file",
        help="audit JSON (default <toml dir>/audit/launchd-git-calls.json)",
    )
    audit.add_argument(
        "-L",
        "--plist-dir",
        action="append",
        help="plist directory (repeatable; default the 3 launchd dirs)",
    )
    audit.add_argument("-j", "--json", action="store_true", help="machine-readable output")

    rec = sub.add_parser("reconcile", help="create-if-absent / verify / refuse one key")
    rec.add_argument("-i", "--inventory", required=True, help="source TOML inventory")
    rec.add_argument("-k", "--key", required=True, help="key name")
    rec.add_argument("-n", "--dry-run", action="store_true", help="change nothing, print the plan")
    rec.add_argument(
        "-P",
        "--policy",
        action="store_true",
        help="also verify/create the append-only rule",
    )
    rec.add_argument(
        "-e", "--evidence-dir", help="snapshot directory (default <toml dir>/evidence)"
    )
    return parser


def _print_report(report: Report, as_json: bool, what: str) -> int:
    if as_json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        for f in report.findings:
            mark = "❌" if f.level == "problem" else "·"
            print(f"{mark} {f.row} [{f.cls}] {f.text}")
        print(
            f"{'✅' if report.ok else '❌'} deploykey {what}: "
            f"{sum(f.level == 'problem' for f in report.findings)} problem(s)"
        )
    return EXIT_OK if report.ok else EXIT_PROBLEMS


def _cmd_sync(args: argparse.Namespace) -> int:
    from .source import sync  # pylint: disable=import-outside-toplevel

    out = sync(Path(args.inventory), args.output, dry_run=args.dry_run)
    verb = "validated" if args.dry_run else f"installed {out}"
    print(f"✅ deploykey sync: {args.inventory} {verb}")
    return EXIT_OK


def _cmd_check(args: argparse.Namespace) -> int:
    from .check import Finding, run_check  # pylint: disable=import-outside-toplevel
    from .inventory import load_runtime  # pylint: disable=import-outside-toplevel

    source = None
    if args.inventory:
        from .source import normalized_source  # pylint: disable=import-outside-toplevel

        source = normalized_source(Path(args.inventory))
    try:
        inv = load_runtime(runtime_path(args.config))
    except RefusedError as exc:
        report = Report([Finding("inventory", "key-config", "problem", str(exc))])
        return _print_report(report, args.json, "check")
    report = run_check(inv, helper=helper_sha(), source_json=source, offline=args.offline)
    return _print_report(report, args.json, "check")


def _load_any(args: argparse.Namespace) -> Inventory:
    from .inventory import (  # pylint: disable=import-outside-toplevel
        build,
        load_runtime,
    )

    if args.inventory:
        from .source import load_toml  # pylint: disable=import-outside-toplevel

        return build(load_toml(Path(args.inventory)))
    return load_runtime(runtime_path(args.config))


def _cmd_audit(args: argparse.Namespace) -> int:
    from .audit import (  # pylint: disable=import-outside-toplevel
        DEFAULT_PLIST_DIRS,
        installed_jobs,
        load_audit,
        run_audit,
    )

    inv = _load_any(args)
    if args.audit_file:
        audit_path = Path(args.audit_file)
    elif args.inventory:
        audit_path = Path(args.inventory).resolve().parent / "audit" / "launchd-git-calls.json"
    else:
        raise RefusedError("give -a/--audit-file (or -i, whose directory holds audit/)")
    jobs = installed_jobs(args.plist_dir or DEFAULT_PLIST_DIRS)
    report = run_audit(inv, load_audit(audit_path), jobs)
    return _print_report(report, args.json, "audit")


def _cmd_reconcile(args: argparse.Namespace) -> int:
    from .inventory import build  # pylint: disable=import-outside-toplevel
    from .reconcile import Reconciler  # pylint: disable=import-outside-toplevel
    from .source import load_toml  # pylint: disable=import-outside-toplevel
    from .tools import ApiError  # pylint: disable=import-outside-toplevel

    toml = Path(args.inventory)
    inv = build(load_toml(toml))
    evidence_dir = (
        Path(args.evidence_dir) if args.evidence_dir else toml.resolve().parent / "evidence"
    )
    try:
        result = Reconciler(
            inv,
            args.key,
            dry_run=args.dry_run,
            policy=args.policy,
            evidence_dir=evidence_dir,
        ).run()
    except ApiError as exc:
        print(
            f"❌ deploykey reconcile: API refused, stopping (never bypass via the UI): {exc}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    print("record in the inventory:")
    for name, value in result.items():
        print(f"  {name} = {json.dumps(value)}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the exit code."""
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.version:
        print(helper_sha())
        return EXIT_OK
    handlers = {
        "sync": _cmd_sync,
        "check": _cmd_check,
        "audit": _cmd_audit,
        "reconcile": _cmd_reconcile,
    }
    if args.cmd not in handlers:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        return handlers[args.cmd](args)
    except RefusedError as exc:
        print(f"❌ deploykey {args.cmd}: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
