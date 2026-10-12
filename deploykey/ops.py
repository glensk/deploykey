"""The three network operations: push, pull, run (commit+push) (stdlib only, 3.9+).

Every operation validates everything it can before the first network call and
raises :class:`RefusedError` on any doubt (exit 3). A network or remote failure —
including a non-fast-forward rejection — returns ``rc`` 4 and leaves the local
commits where they are: there is no automatic rebase, the next cycle retries.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess  # nosec B404 - fixed argv, never a shell
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import evidence
from ._common import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_REFUSED,
    DeployKeyError,
    RefusedError,
    helper_sha,
)
from .gitenv import git, git_common_dir, git_env, local_env, resolve_remote
from .inventory import Consumer, Inventory, validate_refspec
from .lock import LockBusyError, repo_lock

_NFF_RE = re.compile(r"non-fast-forward|fetch first|\(rejected\)|stale info", re.IGNORECASE)


@dataclass(frozen=True)
class Outcome:
    """Result of one attempt; ``rc`` uses the CLI exit codes (0, 3, 4)."""

    rc: int
    message: str
    pushed_sha: str | None = None
    remote_oid: str | None = None

    @property
    def ok(self) -> bool:
        """True when the attempt succeeded."""
        return self.rc == EXIT_OK


def _require_usable(inv: Inventory, consumer: Consumer, direction: str) -> None:
    if consumer.status == "planned":
        raise RefusedError(f"consumer {consumer.label!r} is planned, not provisioned yet")
    if consumer.status == "legacy":
        raise RefusedError(
            f"consumer {consumer.label!r} is legacy: it is still published by its in-repo "
            "helper copy, not by deploykey"
        )
    key = inv.key_of(consumer)
    if key.direction != direction:
        raise RefusedError(
            f"consumer {consumer.label!r} uses the {key.direction} key {key.name!r}; "
            f"this operation needs a {direction} key"
        )
    if not os.path.isfile(consumer.git) or not os.access(consumer.git, os.X_OK):
        raise RefusedError(f"git {consumer.git} is not an executable file")
    if not os.path.isdir(consumer.checkout):
        raise RefusedError(f"checkout {consumer.checkout} does not exist")


def _same_repo(consumer: Consumer, worktree: str | None) -> str | None:
    """*worktree* (``-W``) must share the row checkout's git-common-dir."""
    if worktree is None:
        return None
    if not os.path.isabs(worktree):
        raise RefusedError(f"worktree {worktree!r} must be an absolute path")
    if git_common_dir(consumer, worktree) != git_common_dir(consumer):
        raise RefusedError(f"worktree {worktree} is not a worktree of {consumer.checkout}")
    return worktree


def _push_locked(
    inv: Inventory, consumer: Consumer, base: Mapping[str, str], worktree: str | None
) -> Outcome:
    """Validate, then push exactly the inventory refspec. Caller holds the lock."""
    key = inv.key_of(consumer)
    src, dst = validate_refspec(consumer.refspec, key.direction)
    env = git_env(inv, consumer, base)
    remote = resolve_remote(consumer, push=True, cwd=worktree)
    rev = git(consumer, "rev-parse", "--verify", "--quiet", f"{src}^{{commit}}", cwd=worktree)
    if rev.returncode != 0:
        raise RefusedError(f"{src} does not name a commit in {worktree or consumer.checkout}")
    sha = rev.stdout.strip()
    try:
        proc = git(
            consumer,
            "push",
            "--porcelain",
            "--no-follow-tags",
            remote,
            f"{sha}:{dst}",
            env=env,
            timeout=inv.settings.net_timeout_s or None,
            cwd=worktree,
        )
    except subprocess.TimeoutExpired:
        return Outcome(EXIT_FAILED, f"push timed out after {inv.settings.net_timeout_s}s")
    text = f"{proc.stdout}\n{proc.stderr}".strip()
    if proc.returncode == 0:
        return Outcome(
            EXIT_OK,
            f"pushed {sha[:12]} to {consumer.remote} {dst}",
            sha,
            sha,
        )
    if _NFF_RE.search(text):
        return Outcome(
            EXIT_FAILED,
            f"non-fast-forward: {dst} on {consumer.remote} moved; commit {sha[:12]} kept "
            f"locally, no rebase — retry next cycle. {_tail(text)}",
        )
    return Outcome(EXIT_FAILED, f"push failed (git rc={proc.returncode}): {_tail(text)}")


def _tail(text: str, lines: int = 6) -> str:
    return " | ".join(text.splitlines()[-lines:])


def _attempt(consumer: Consumer, operation: str, body: Callable[[], Outcome]) -> Outcome:
    """Run *body*, turn refusals and a busy lock into outcomes, write the evidence record."""
    try:
        outcome = body()
    except LockBusyError as exc:
        outcome = Outcome(EXIT_FAILED, str(exc))
    except RefusedError as exc:
        outcome = Outcome(EXIT_REFUSED, f"refused: {exc}")
    except OSError as exc:
        outcome = Outcome(EXIT_FAILED, f"{operation} failed: {exc}")
    evidence.record(
        consumer.evidence,
        consumer=consumer.label,
        operation=operation,
        rc=outcome.rc,
        message=outcome.message,
        helper=helper_sha(),
        pushed_sha=outcome.pushed_sha,
        remote_oid=outcome.remote_oid,
    )
    return outcome


def push(
    inv: Inventory,
    label: str,
    base: Mapping[str, str] | None = None,
    *,
    worktree: str | None = None,
    lock_timeout: float | None = None,
) -> Outcome:
    """``deploy-git push``: take the repository lock and push the inventory refspec."""
    consumer = inv.consumer(label)
    env = dict(os.environ if base is None else base)

    def body() -> Outcome:
        _require_usable(inv, consumer, "write")
        wt = _same_repo(consumer, worktree)
        timeout = inv.settings.lock_timeout_s if lock_timeout is None else lock_timeout
        with repo_lock(git_common_dir(consumer), timeout):
            return _push_locked(inv, consumer, env, wt)

    return _attempt(consumer, "push", body)


def pull_ref(branch: str) -> str:
    """The deploykey-owned local ref ``deploy-git pull`` fetches *branch* into."""
    return f"refs/deploykey/pull/{branch}"


def _pull_locked(
    inv: Inventory, consumer: Consumer, env: Mapping[str, str], remote: str, branch: str
) -> Outcome:
    """Fetch *branch* into :func:`pull_ref`, then fast-forward HEAD to it. Caller holds the lock.

    No ``git pull``: it merges whatever ``FETCH_HEAD`` holds, and a foreign fetch in the
    same clone (an editor's git plugin, not stopped by our lock) can leave two merge
    lines there — ``Cannot fast-forward to multiple branches`` (tp#925). The fetch
    writes no ``FETCH_HEAD`` and, with an empty ``--refmap``, no ``refs/remotes/*``
    either, so it shares no ref with a foreign fetcher. The tracking ref is moved
    afterwards by :func:`_advance_tracking_ref`, compare-and-swap only.
    """
    private = pull_ref(branch)
    tracking = f"refs/remotes/{remote}/{branch}"
    seen = git(consumer, "rev-parse", "--verify", "--quiet", f"{tracking}^{{commit}}")
    tracking_old = seen.stdout.strip() if seen.returncode == 0 else None
    net_timeout = inv.settings.net_timeout_s or None
    # `+` forces only the PRIVATE local ref deploykey owns — never a remote ref, so it
    # is not a force push. It keeps a rewritten upstream from failing the fetch; the
    # `merge --ff-only` below is the safety check and still refuses a non-fast-forward.
    try:
        fetch = git(
            consumer,
            "fetch",
            "-q",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--no-tags",
            "--refmap=",
            remote,
            f"+refs/heads/{branch}:{private}",
            env=env,
            timeout=net_timeout,
        )
    except subprocess.TimeoutExpired:
        return Outcome(EXIT_FAILED, f"fetch timed out after {inv.settings.net_timeout_s}s")
    if fetch.returncode != 0:
        text = f"{fetch.stdout}\n{fetch.stderr}".strip()
        return Outcome(EXIT_FAILED, f"fetch failed (git rc={fetch.returncode}): {_tail(text)}")
    try:
        # `env` carries submodule.recurse=false (git_env), so a global
        # submodule.recurse=true does not make the merge update submodules.
        merge = git(
            consumer, "merge", "--ff-only", "-q", "--no-edit", private, env=env, timeout=net_timeout
        )
    except subprocess.TimeoutExpired:
        return Outcome(EXIT_FAILED, f"merge timed out after {inv.settings.net_timeout_s}s")
    if merge.returncode != 0:
        text = f"{merge.stdout}\n{merge.stderr}".strip()
        return Outcome(EXIT_FAILED, f"pull failed (git rc={merge.returncode}): {_tail(text)}")
    new = git(consumer, "rev-parse", "HEAD").stdout.strip()
    _advance_tracking_ref(consumer, tracking, new, tracking_old)
    return Outcome(EXIT_OK, f"pulled {branch} from {consumer.remote} at {new[:12]}", None, new)


def _advance_tracking_ref(consumer: Consumer, tracking: str, new: str, old: str | None) -> None:
    """Move *tracking* from *old* to *new* if nothing else moved it; never fails the pull.

    The ``--refmap=`` fetch leaves ``refs/remotes/<remote>/<branch>`` alone (no ref-lock
    race with a foreign fetch), but on a clone nothing else fetches, ``git status`` would
    then report "ahead N" for ever and mislead "is it pushed?" checks. So the ref is set
    with a compare-and-swap against the value read before the fetch: if a foreign fetch
    moved it in between, that fetch already updated it and the failed swap is ignored. A
    tracking ref that did not exist is not created (the remote's fetch refspec may not
    map the branch there).
    """
    if old is None or old == new:
        return
    with contextlib.suppress(subprocess.TimeoutExpired):
        git(consumer, "update-ref", "-m", "deploy-git pull", tracking, new, old)


def pull(
    inv: Inventory,
    label: str,
    base: Mapping[str, str] | None = None,
    *,
    lock_timeout: float | None = None,
) -> Outcome:
    """``deploy-git pull``: fetch one branch with the read key, then ``merge --ff-only``.

    Two steps under the repository lock: ``git fetch`` of ``refs/heads/<branch>`` into
    the private ref ``refs/deploykey/pull/<branch>`` (no ``FETCH_HEAD``, no
    remote-tracking ref), then ``git merge --ff-only`` of that ref into the checked-out
    branch. A non-fast-forward fails (exit 4) and leaves the checkout untouched. After
    a successful merge ``refs/remotes/<remote>/<branch>`` is advanced by compare-and-swap
    (skipped if another fetch moved it meanwhile), so ``git status`` is not "ahead".
    """
    consumer = inv.consumer(label)
    env_base = dict(os.environ if base is None else base)

    def body() -> Outcome:
        _require_usable(inv, consumer, "read")
        ref, _ = validate_refspec(consumer.refspec, "read")
        branch = ref[len("refs/heads/") :]
        env = git_env(inv, consumer, env_base)
        remote = resolve_remote(consumer, push=False)
        head = git(consumer, "symbolic-ref", "-q", "HEAD").stdout.strip()
        if head != ref:
            raise RefusedError(f"{consumer.checkout} is on {head or 'a detached HEAD'}, not {ref}")
        timeout = inv.settings.lock_timeout_s if lock_timeout is None else lock_timeout
        with repo_lock(git_common_dir(consumer), timeout):
            return _pull_locked(inv, consumer, env, remote, branch)

    return _attempt(consumer, "pull", body)


def resolve_argv0(argv0: str, fixed_path: str) -> str:
    """An absolute executable for *argv0*: itself if absolute, else looked up on *fixed_path*.

    The caller's ``$PATH`` is never consulted (a job's environment must not decide
    which program runs with the transaction lock held); a relative path with a
    slash is refused.
    """
    if os.path.isabs(argv0):
        if os.path.isfile(argv0) and os.access(argv0, os.X_OK):
            return argv0
        raise RefusedError(f"{argv0} is not an executable file")
    if os.sep in argv0 or not argv0:
        raise RefusedError(f"{argv0!r}: give an absolute path or a bare command name")
    found = shutil.which(argv0, path=fixed_path)
    if not found:
        raise RefusedError(f"{argv0!r} is not on the fixed PATH {fixed_path}")
    return os.path.abspath(found)


def run(
    inv: Inventory,
    label: str,
    argv: Sequence[str],
    base: Mapping[str, str] | None = None,
    *,
    lock_timeout: float | None = None,
    command_timeout: float | None = None,
) -> Outcome:
    """``deploy-git run``: under the lock, run the local commit command, then push.

    The command runs in the checkout with ``AI_PUSH_LOCAL_ONLY=1`` and no key (its
    env loses ``SSH_AUTH_SOCK``/``GIT_SSH*``); a non-zero exit pushes nothing.
    """
    consumer = inv.consumer(label)
    env = dict(os.environ if base is None else base)

    def body() -> Outcome:
        _require_usable(inv, consumer, "write")
        if not argv:
            raise RefusedError("run needs a command after --")
        exe = resolve_argv0(argv[0], inv.settings.path)
        validate_refspec(consumer.refspec, inv.key_of(consumer).direction)
        resolve_remote(consumer, push=True)
        timeout = inv.settings.lock_timeout_s if lock_timeout is None else lock_timeout
        with repo_lock(git_common_dir(consumer), timeout):
            try:
                proc = subprocess.run(  # nosec B603 - argv[0] resolved to an absolute path
                    [exe, *argv[1:]],
                    cwd=consumer.checkout,
                    env=local_env(env),
                    check=False,
                    timeout=command_timeout,
                )
            except subprocess.TimeoutExpired:
                return Outcome(EXIT_FAILED, f"{argv[0]} timed out; nothing pushed")
            if proc.returncode != 0:
                return Outcome(EXIT_FAILED, f"{argv[0]} exited {proc.returncode}; nothing pushed")
            return _push_locked(inv, consumer, env, None)

    return _attempt(consumer, "run", body)


def publish(
    inv: Inventory,
    label: str,
    commit: Callable[[Path], object] | None = None,
    base: Mapping[str, str] | None = None,
    *,
    lock_timeout: float | None = None,
) -> Outcome:
    """Library form of ``run``: *commit(checkout)* runs in-process under the lock.

    Raises :class:`DeployKeyError` when the push is refused (nothing was sent);
    returns an :class:`Outcome` with ``rc`` 0 or 4 otherwise. An ``OSError`` from
    *commit* is reported as ``rc`` 4; any other exception propagates after the lock
    is released. Either way nothing is pushed.
    """
    consumer = inv.consumer(label)
    env = dict(os.environ if base is None else base)

    def body() -> Outcome:
        _require_usable(inv, consumer, "write")
        validate_refspec(consumer.refspec, inv.key_of(consumer).direction)
        resolve_remote(consumer, push=True)
        timeout = inv.settings.lock_timeout_s if lock_timeout is None else lock_timeout
        with repo_lock(git_common_dir(consumer), timeout):
            if commit is not None:
                commit(Path(consumer.checkout))
            return _push_locked(inv, consumer, env, None)

    outcome = _attempt(consumer, "publish", body)
    if outcome.rc == EXIT_REFUSED:
        raise DeployKeyError(outcome.message)
    return outcome
