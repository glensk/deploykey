"""``deploy-git`` — the only way an unattended job reaches a git remote (stdlib, 3.9+).

There is no free argv for network operations: the remote, the refspec and the
key all come from the installed runtime inventory, looked up by consumer label.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import ops
from ._common import EXIT_REFUSED, EXIT_USAGE, RefusedError, helper_sha, runtime_path
from .inventory import load_runtime

EPILOG = """\
exit codes: 0 ok, 2 usage, 3 refused (no network call was made),
            4 network/remote/local-command failure (commits stay local; retry next cycle)

examples:
  deploy-git push sdsc-runai                       # push the row's refspec (HEAD:refs/heads/main)
  deploy-git push tp-autopilot:tp -W /abs/worktree # from a worktree of the same repository
  deploy-git pull books-lists-pull                 # fetch + merge --ff-only, read key
  deploy-git run cscs-triage -- ai.py push -m "msg" f.pdf  # commit locally, then push
  deploy-git -c /tmp/inv.json push x               # another runtime inventory (tests)
  deploy-git -V                                    # the installed helper sha
"""


def build_parser() -> argparse.ArgumentParser:
    """The ``deploy-git`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="deploy-git",
        description="Push or fetch exactly what the deploy-key inventory allows, with that "
        "consumer's repo-scoped key (ssh -F /dev/null, no agent).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="store_true", help="print the helper sha")
    parser.add_argument(
        "-c",
        "--config",
        help="runtime inventory JSON (default $DEPLOYKEY_CONFIG or ~/.ssh/deploy/deploy-keys.json)",
    )
    sub = parser.add_subparsers(dest="cmd")
    for name, text in (
        ("push", "push the consumer's inventory refspec"),
        ("pull", "fast-forward the consumer's checkout from its remote branch"),
        ("run", "run a local commit command under the repo lock, then push"),
    ):
        cmd = sub.add_parser(name, help=text, description=text)
        cmd.add_argument("consumer", help="consumer label from the inventory")
        cmd.add_argument(
            "-t",
            "--lock-timeout",
            type=float,
            help="seconds to wait for the repository lock",
        )
        if name == "push":
            cmd.add_argument(
                "-W",
                "--worktree",
                help="absolute path of a worktree of the same repository to push from",
            )
        if name == "run":
            cmd.add_argument(
                "-T",
                "--command-timeout",
                type=float,
                help="seconds the commit command may run",
            )
            cmd.add_argument("argv", nargs=argparse.REMAINDER, help="-- <command> [args…]")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the exit code."""
    parser = build_parser()
    args, extra = parser.parse_known_args(list(sys.argv[1:] if argv is None else argv))
    if args.version:
        print(helper_sha())
        return 0
    if args.cmd is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    if extra:
        print(
            f"❌ refused: deploy-git takes no git options or refs ({' '.join(extra)}); "
            "the refspec comes from the inventory",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    try:
        inv = load_runtime(runtime_path(args.config))
        inv.consumer(args.consumer)
    except RefusedError as exc:
        print(f"❌ refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    if args.cmd == "push":
        outcome = ops.push(
            inv, args.consumer, worktree=args.worktree, lock_timeout=args.lock_timeout
        )
    elif args.cmd == "pull":
        outcome = ops.pull(inv, args.consumer, lock_timeout=args.lock_timeout)
    else:
        command = list(args.argv)
        if command[:1] == ["--"]:
            command = command[1:]
        outcome = ops.run(
            inv,
            args.consumer,
            command,
            lock_timeout=args.lock_timeout,
            command_timeout=args.command_timeout,
        )
    mark = "✅" if outcome.ok else "❌"
    print(
        f"{mark} deploy-git {args.cmd} {args.consumer}: {outcome.message}",
        file=sys.stderr,
    )
    return outcome.rc


if __name__ == "__main__":
    sys.exit(main())
