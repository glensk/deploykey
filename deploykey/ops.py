"""The three network operations: push, pull, run (commit+push) (stdlib only, 3.9+).

Every operation validates everything it can before the first network call and
raises :class:`RefusedError` on any doubt (exit 3). A network or remote failure —
including a non-fast-forward rejection — returns ``rc`` 4 and leaves the local
commits where they are: there is no automatic rebase, the next cycle retries.

The one exception is a transient *transport* failure of the read path (a reset or
refused connection, a name that did not resolve), which :func:`_network` re-attempts
a bounded number of times; see :func:`is_transient`. A rejected ref update is never
re-attempted.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess  # nosec B404 - fixed argv, never a shell
import time
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
    run_group,
)
from .gitenv import git, git_common_dir, git_env, local_env, resolve_remote
from .inventory import Consumer, Inventory, validate_refspec
from .lock import LockBusyError, repo_lock

_NFF_RE = re.compile(r"non-fast-forward|fetch first|\(rejected\)|stale info", re.IGNORECASE)

# A fault re-running the command cannot fix: the key is refused, the pinned host key does
# not match, the remote or ref is wrong, the remote refused the update on policy. Checked
# BEFORE _TRANSIENT_RE so it wins when both appear. The generic git envelope of EVERY ssh
# transport failure ("Could not read from remote repository.", "Please make sure you have
# the correct access rights", "and the repository exists.") is deliberately absent: as a
# terminal marker it would veto every retry.
_TERMINAL_RE = re.compile(
    r"""
      Permission\ denied
    | too\ many\ authentication\ failures
    | Host\ key\ verification\ failed
    | REMOTE\ HOST\ IDENTIFICATION\ HAS\ CHANGED
    | Unable\ to\ negotiate
    | no\ matching\ (?:host\ key|key\ exchange|cipher)
    | Bad\ (?:configuration\ option|owner\ or\ permissions)
    | Repository\ not\ found
    | couldn't\ find\ remote\ ref
    | does\ not\ appear\ to\ be\ a\ git\ repository
    | Write\ access\ to\ repository\ not\ granted
    | shallow\ update\ not\ allowed
    | pre-receive\ hook\ declined
    | protected\ branch
    """,
    re.IGNORECASE | re.VERBOSE,
)

# OpenSSH's own transport diagnostics (it is not localized, so matching its text is
# locale-safe). Deliberately NOT here: "early EOF", "index-pack failed", "RPC failed" and
# friends, which equally mean local disk exhaustion, a corrupt object store or a server
# defect — none of which another attempt fixes. Widen only with evidence.
_TRANSIENT_RE = re.compile(
    r"""
      Connection\ (?:reset|refused|closed|timed\ out)
    | Operation\ timed\ out
    | Network\ is\ unreachable
    | (?:No\ route\ to|Host\ is\ unreachable)
    | Could\ not\ resolve\ hostname
    | Temporary\ failure\ in\ name\ resolution
    | nodename\ nor\ servname
    | Name\ or\ service\ not\ known
    | Broken\ pipe
    | kex_exchange_identification
    | ssh_exchange_identification
    | banner\ exchange
    | remote\ end\ hung\ up\ unexpectedly
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Waits before the 2nd and 3rd attempt, and the wall-clock ceiling of the whole sequence
# measured from the first attempt. Fixed constants, not inventory settings: `to_json`
# serialises every settings field, so a new one would be written into the schema-1 runtime
# JSON and refused by a rolled-back helper (README "Rollback").
_RETRY_DELAYS_S = (2.0, 6.0)
_RETRY_DEADLINE_S = 300.0


def is_transient(stderr: str) -> bool:
    """True when *stderr* shows a transport failure another attempt may well survive.

    Only ``stderr`` is classified, and every ``remote:`` line is dropped first: that text
    comes from the server (or a remote hook) and must never be able to ask us for another
    attempt. Anything unrecognised is terminal — the default is today's behaviour.

    Re-running a command cannot change a verdict that does not depend on timing, so a
    failure wrongly called transient costs latency, never correctness; the terminal list
    is there to fail fast, not to keep us safe.
    """
    text = "\n".join(
        line for line in stderr.splitlines() if not line.lstrip().startswith("remote:")
    )
    if _NFF_RE.search(text) or _TERMINAL_RE.search(text):
        return False
    return bool(_TRANSIENT_RE.search(text))


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


@dataclass(frozen=True)
class _Net:
    """The last attempt of one network command: ``proc`` is ``None`` when it timed out.

    ``first_error`` is the diagnostic of the first attempt that failed, kept so that a
    success after a retry still names the instability it absorbed instead of erasing it.
    """

    proc: subprocess.CompletedProcess[str] | None
    attempts: int
    first_error: str = ""


def _network(
    inv: Inventory,
    consumer: Consumer,
    *argv: str,
    env: Mapping[str, str],
    cwd: str | None = None,
) -> _Net:
    """Run one git network command, re-running it only after a transient transport failure.

    Bounded three ways, because this runs with the repository lock held: at most
    ``len(_RETRY_DELAYS_S)`` retries, never past ``_RETRY_DEADLINE_S`` from the first
    attempt, and only while ``net_timeout_s`` bounds a single attempt — with no per-attempt
    timeout an attempt can hang forever, so an attempt count would bound nothing and there
    is exactly one try, as before.
    """
    timeout = inv.settings.net_timeout_s or None
    delays = _RETRY_DELAYS_S if timeout is not None else ()
    started = time.monotonic()
    proc: subprocess.CompletedProcess[str] | None = None
    attempts = 0
    first_error = ""
    for index in range(len(delays) + 1):
        attempts = index + 1
        try:
            proc = git(consumer, *argv, env=env, timeout=timeout, cwd=cwd)
        except subprocess.TimeoutExpired:
            proc = None  # a hung connection is the archetypal transient failure
        if proc is not None and proc.returncode == 0:
            break
        if not first_error:
            first_error = _first(proc.stderr) if proc is not None else "timed out"
        if index == len(delays):
            break
        if proc is not None and not is_transient(proc.stderr):
            break
        delay = delays[index]
        if time.monotonic() - started + delay + (timeout or 0) > _RETRY_DEADLINE_S:
            break
        time.sleep(delay)
    return _Net(proc, attempts, first_error)


def _retried(net: _Net) -> str:
    """`` (after N transient retries: …)`` for a success that needed more than one attempt.

    It names the diagnostic it absorbed, so a retried success is still visible as
    instability in the log and in the evidence record's ``last_attempt_message``.
    """
    if net.attempts < 2:
        return ""
    word = "retry" if net.attempts == 2 else "retries"
    return f" (after {net.attempts - 1} transient {word}: {net.first_error})"


def _of(attempts: int) -> str:
    """`` after N attempts`` for a failure that was re-attempted."""
    return f" after {attempts} attempts" if attempts > 1 else ""


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
    """Validate, then push exactly the inventory refspec. Caller holds the lock.

    Deliberately NOT retried, unlike the read path: ``git push`` runs the local
    ``pre-push`` hook on every attempt (Albert's is global, via ``core.hooksPath``, and
    forks a watcher that revokes a token-server token when the push process exits), so a
    second attempt repeats side effects that are not ours to repeat. A failed push keeps
    its commits locally and the next cycle sends them.
    """
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


def _first(text: str, lines: int = 1) -> str:
    """The first non-empty line(s) — where ssh writes its diagnostic.

    Not :func:`_tail`: git appends the same five-line envelope ("Could not read from
    remote repository", "correct access rights", …) to every transport failure, so the
    LAST lines are identical for a reset, a refused key and an unknown host alike. Only
    the first line says which one it was.
    """
    kept = [line.strip() for line in text.splitlines() if line.strip()][:lines]
    return " | ".join(kept)


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
    #
    # Retried on a transient transport failure (_network): the fetch is read-only, writes
    # only `private` and only on success, so re-running it has no side effect at all.
    net = _network(
        inv,
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
    )
    fetch = net.proc
    if fetch is None:
        return Outcome(
            EXIT_FAILED,
            f"fetch timed out after {inv.settings.net_timeout_s}s{_of(net.attempts)}",
        )
    if fetch.returncode != 0:
        text = f"{fetch.stdout}\n{fetch.stderr}".strip()
        return Outcome(
            EXIT_FAILED,
            f"fetch failed (git rc={fetch.returncode}{_of(net.attempts)}): {_tail(text)}",
        )
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
    return Outcome(
        EXIT_OK,
        f"pulled {branch} from {consumer.remote} at {new[:12]}{_retried(net)}",
        None,
        new,
    )


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

    Only the fetch is re-attempted, and only after a transient transport failure
    (:func:`is_transient`); the merge is local, where nothing is ever transient.
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
                proc = run_group(  # argv[0] resolved to an absolute path
                    [exe, *argv[1:]],
                    cwd=consumer.checkout,
                    env=local_env(env),
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
