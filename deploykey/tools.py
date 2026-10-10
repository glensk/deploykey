"""External executables the admin commands use, declared once (extdeps registry).

The runtime core (``deploy-git``) never resolves anything through this module:
its ``ssh``/``ssh-keygen``/``git`` paths are absolute and come from the inventory.
Only ``deploykey check`` (remote policy), ``reconcile`` and ``audit`` shell out to
``gh``/``glab``/``plutil``, and they need Python 3.10+ (extdeps).
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - fixed argv, never a shell
from typing import Any

from ._common import RefusedError

GH_ENV = "GH_BIN"
GLAB_ENV = "GLAB_BIN"


def _registry() -> dict[str, Any]:
    try:
        from extdeps import Dep  # pylint: disable=import-outside-toplevel
    except ImportError as exc:  # pragma: no cover - 3.9 / no extdeps installed
        raise RefusedError(
            "this command needs the extdeps package (Python 3.10+, run it under uv)"
        ) from exc
    return {
        "gh": Dep(
            name="gh",
            command="gh",
            env=GH_ENV,
            install_hint="`brew install gh` and `gh auth login` (GitHub CLI).",
        ),
        "glab": Dep(
            name="glab",
            command="glab",
            env=GLAB_ENV,
            install_hint="`brew install glab` and `glab auth login --hostname <host>`.",
        ),
    }


def require_tool(name: str, needed_for: str) -> str:
    """The resolved path of *name* (``gh``/``glab``), or :class:`RefusedError` (exit 3)."""
    from extdeps import (  # pylint: disable=import-outside-toplevel
        MissingExternalDependency,
        require,
    )

    try:
        return str(require(_registry()[name], needed_for=needed_for))
    except MissingExternalDependency as exc:
        raise RefusedError(str(exc)) from exc


def api_json(
    tool: str,
    path: str,
    *,
    host: str = "",
    method: str = "GET",
    fields: dict[str, Any] | None = None,
) -> Any:
    """``gh api`` / ``glab api`` returning parsed JSON; :class:`ApiError` on failure.

    *fields* go as a JSON body on stdin (``--input -``), so nested values
    (ruleset rules, GitLab ``allowed_to_push``) keep their types.
    """
    exe = require_tool(tool, f"{tool} api {path}")
    argv = [exe, "api"]
    if tool == "glab" and host:
        argv += ["--hostname", host]
    argv += ["-X", method, path]
    stdin = None
    if fields is not None:
        argv += ["-H", "Content-Type: application/json", "--input", "-"]
        stdin = json.dumps(fields)
    proc = subprocess.run(  # nosec B603 - resolved gh/glab, fixed argv
        argv, input=stdin, capture_output=True, text=True, check=False, timeout=60
    )
    if proc.returncode != 0:
        raise ApiError(path, proc.returncode, (proc.stderr or proc.stdout).strip())
    out = proc.stdout.strip()
    return json.loads(out) if out else None


class ApiError(RuntimeError):
    """A ``gh``/``glab`` API call failed."""

    def __init__(self, path: str, rc: int, detail: str) -> None:
        super().__init__(f"{path}: rc={rc}: {detail[:300]}")
        self.path = path
        self.rc = rc
        self.detail = detail

    @property
    def not_found(self) -> bool:
        """True for an HTTP 404."""
        return "404" in self.detail or "Not Found" in self.detail
