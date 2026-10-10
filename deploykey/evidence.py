"""Last-attempt / last-success evidence records (stdlib only, Python 3.9+).

After every attempt ``deploy-git`` (and :func:`deploykey.publish`) rewrites the
consumer's ``evidence`` file atomically. A failed attempt keeps the previous
success fields, so a status check sees both "the last attempt failed" and "when
it last worked". Real publications are the evidence; probes never write here.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from ._common import write_json_atomic

FIELDS = (
    "consumer",
    "operation",
    "last_attempt_at",
    "last_attempt_rc",
    "last_attempt_message",
    "last_success_at",
    "pushed_sha",
    "remote_oid",
    "helper_sha",
)


def now_iso() -> str:
    """UTC now, second precision, ISO 8601 with offset."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def read(path: str | Path) -> dict[str, Any] | None:
    """The evidence record at *path*, ``None`` when absent or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def record(
    path: str | Path,
    *,
    consumer: str,
    operation: str,
    rc: int,
    message: str,
    helper: str,
    pushed_sha: str | None = None,
    remote_oid: str | None = None,
) -> dict[str, Any]:
    """Write one attempt; on success also the success fields. Returns the record."""
    previous = read(path) or {}
    at = now_iso()
    data: dict[str, Any] = {name: previous.get(name) for name in FIELDS}
    data.update(
        consumer=consumer,
        operation=operation,
        last_attempt_at=at,
        last_attempt_rc=rc,
        last_attempt_message=message[-2000:],
        helper_sha=helper,
    )
    if rc == 0:
        data.update(last_success_at=at, pushed_sha=pushed_sha, remote_oid=remote_oid)
    data["schema"] = 1
    write_json_atomic(Path(path), data, mode=0o644)
    return data


def parse_iso(value: Any) -> _dt.datetime | None:
    """A timezone-aware datetime from an evidence timestamp, else ``None``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed
