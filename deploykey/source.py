"""Reading the TOML source inventory (Python 3.11+: ``tomllib``)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from ._common import RefusedError, runtime_path, write_json_atomic
from .inventory import normalize


def load_toml(path: Path) -> dict[str, Any]:
    """Parse the source TOML; :class:`RefusedError` on a read or syntax error."""
    if sys.version_info < (3, 11):
        raise RefusedError(
            "reading the TOML inventory needs Python 3.11+ (tomllib); run it under uv"
        )
    import tomllib  # pylint: disable=import-outside-toplevel

    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except OSError as exc:
        raise RefusedError(f"cannot read {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RefusedError(f"{path} is not valid TOML: {exc}") from exc


def normalized_source(path: Path) -> dict[str, Any]:
    """The runtime-JSON form of the TOML at *path* (validated)."""
    return normalize(load_toml(path))


def sync(source: Path, target: str | None = None, *, dry_run: bool = False) -> Path:
    """Validate *source* and install it atomically as the runtime JSON; returns the target."""
    data = normalized_source(source)
    out = runtime_path(target)
    if not dry_run:
        write_json_atomic(out, data)
    return out
