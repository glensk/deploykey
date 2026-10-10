"""Per-repository transaction lock (stdlib only, Python 3.9+).

``flock`` on ``<git-common-dir>/deploykey.lock`` around the whole commit+push
transaction, so two unattended jobs of the same repository (the sdsc poller and
lifecycle, an overseer incident commit and its session push) never interleave a
commit of one with the push of the other. Every worktree of a repository shares
the git-common-dir, so they share the lock. A push inside a held transaction does
not take the lock again: ``flock`` on a second descriptor would block on itself.
"""

from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

LOCK_NAME = "deploykey.lock"


class LockBusyError(RuntimeError):
    """Another transaction holds the repository lock past the timeout."""


@contextmanager
def repo_lock(common_dir: Path, timeout: float = 600, poll: float = 0.2) -> Iterator[Path]:
    """Hold the exclusive lock of *common_dir*; :class:`LockBusyError` after *timeout* s."""
    path = common_dir / LOCK_NAME
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockBusyError(
                        f"{path} is held by another transaction (waited {timeout:g}s); "
                        "retry next cycle"
                    ) from None
                time.sleep(poll)
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
            yield path
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
