"""Repo-scoped ssh deploy keys for unattended git pushes and fetches.

Library API (stdlib only, Python 3.9+)::

    import deploykey

    inv = deploykey.load()                                   # the installed runtime inventory
    outcome = deploykey.publish(inv, "sdsc-runai", commit=lambda checkout: ...)
    # DeployKeyError: refused, nothing sent; outcome.rc 4: push failed, commit kept

``deploy-git`` (CLI) wraps the same functions for shell and Python 3.9 callers.
"""

from __future__ import annotations

from pathlib import Path

from ._common import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_REFUSED,
    LOCAL_ONLY_ENV,
    DeployKeyError,
    RefusedError,
    helper_sha,
    runtime_path,
)
from .gitenv import git_env, ssh_command
from .inventory import Consumer, Inventory, Key, load_runtime, parse_remote_url, validate_refspec
from .lock import LockBusyError, repo_lock
from .ops import Outcome, publish, pull, push, run


def load(path: str | Path | None = None) -> Inventory:
    """The installed runtime inventory (``$DEPLOYKEY_CONFIG`` or the default path)."""
    return load_runtime(runtime_path(str(path) if path is not None else None))


__all__ = [
    "EXIT_FAILED",
    "EXIT_OK",
    "EXIT_REFUSED",
    "LOCAL_ONLY_ENV",
    "Consumer",
    "DeployKeyError",
    "Inventory",
    "Key",
    "LockBusyError",
    "Outcome",
    "RefusedError",
    "git_env",
    "helper_sha",
    "load",
    "load_runtime",
    "parse_remote_url",
    "publish",
    "pull",
    "push",
    "repo_lock",
    "run",
    "ssh_command",
    "validate_refspec",
]
