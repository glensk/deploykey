"""Shared constants, errors and small helpers (stdlib only, Python 3.9+)."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess  # nosec B404 - callers pass a fixed argv, never a shell
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

#: Exit codes of both CLIs (and :attr:`deploykey.Outcome.rc`).
EXIT_OK = 0
EXIT_PROBLEMS = 1  # ``deploykey check``/``audit``: at least one red finding
EXIT_USAGE = 2
EXIT_REFUSED = 3  # validation refused; no network call was made
EXIT_FAILED = 4  # network/remote/local-command failure; commits stay local

#: Environment a commit command gets instead of a key: commit, never push.
LOCAL_ONLY_ENV = {"AI_PUSH_LOCAL_ONLY": "1"}

#: Environment variables that would route git's ssh through anything but the deploy key.
SSH_ENV_DROP = frozenset({"SSH_AUTH_SOCK", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT"})

#: The runtime inventory ``deploykey sync`` installs and ``deploy-git`` reads.
DEFAULT_RUNTIME = "~/.ssh/deploy/deploy-keys.json"
#: Environment override of :data:`DEFAULT_RUNTIME` (tests, a second inventory).
RUNTIME_ENV = "DEPLOYKEY_CONFIG"

SCHEMA_VERSION = 1

#: Seconds a timed-out command's process group gets between SIGTERM and SIGKILL. git
#: removes its ``index.lock``/ref locks on SIGTERM; a bare SIGKILL leaves them behind and
#: every later git command in that repository fails until someone deletes them by hand.
TERM_GRACE_S = 10.0


class DeployKeyError(RuntimeError):
    """A deploy-key operation was refused; nothing was sent over the network."""


class RefusedError(DeployKeyError):
    """Validation refused the operation (exit :data:`EXIT_REFUSED`)."""


def runtime_path(explicit: str | None = None) -> Path:
    """The runtime inventory path: *explicit*, else ``$DEPLOYKEY_CONFIG``, else the default."""
    raw = explicit or os.environ.get(RUNTIME_ENV) or DEFAULT_RUNTIME
    return Path(os.path.expanduser(raw))


def write_json_atomic(path: Path, data: Any, mode: int = 0o600) -> None:
    """Write *data* as JSON to *path* through a temp file + rename (never half-written)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def helper_sha() -> str:
    """The commit sha this package was installed from, or ``"dev"``.

    ``uv tool install git+https://github.com/glensk/deploykey@<sha>`` records the
    resolved commit in the distribution's PEP 610 ``direct_url.json``; a source
    checkout or an editable install has none.
    """
    try:
        from importlib import metadata  # pylint: disable=import-outside-toplevel

        raw = metadata.distribution("deploykey").read_text("direct_url.json")
    except Exception:  # pylint: disable=broad-except  # any metadata failure = dev
        return "dev"
    if not raw:
        return "dev"
    try:
        info = json.loads(raw)
    except ValueError:
        return "dev"
    commit = (info.get("vcs_info") or {}).get("commit_id")
    return str(commit) if commit else "dev"


def _signal_group(pgid: int, sig: int) -> None:
    """Send *sig* to process group *pgid*; a group that is already gone is fine."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, sig)


def run_group(
    argv: Sequence[str],
    *,
    timeout: float | None,
    capture_output: bool = False,
    text: bool = False,
    stdin_data: str | bytes | None = None,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[Any]:
    """:func:`subprocess.run` with a timeout that lets the command clean up.

    The command starts in a process group of its own. On timeout the whole group gets
    SIGTERM, then :data:`TERM_GRACE_S` seconds to exit, and SIGKILL only if it is still
    there; :class:`subprocess.TimeoutExpired` is raised as before. (``subprocess.run``
    SIGKILLs the direct child alone, which strands git's lock files and leaves hook
    processes running.) Any other exception — ``KeyboardInterrupt`` included — kills the
    group before it propagates.
    """
    pipe = subprocess.PIPE if capture_output else None
    with subprocess.Popen(  # nosec B603 - fixed argv from the caller, never a shell
        list(argv),
        stdin=subprocess.PIPE if stdin_data is not None else None,
        stdout=pipe,
        stderr=pipe,
        text=text,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        start_new_session=True,
    ) as proc:
        try:
            out, err = proc.communicate(stdin_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            _signal_group(proc.pid, signal.SIGTERM)
            try:
                out, err = proc.communicate(timeout=TERM_GRACE_S)
            except subprocess.TimeoutExpired:
                _signal_group(proc.pid, signal.SIGKILL)
                out, err = proc.communicate()
            raise subprocess.TimeoutExpired(
                proc.args, timeout or 0, output=out, stderr=err
            ) from None
        except BaseException:
            _signal_group(proc.pid, signal.SIGKILL)
            proc.wait()
            raise
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)
