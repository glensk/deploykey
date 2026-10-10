"""``deploykey audit`` — re-check the launchd → network-git audit against today's jobs.

The exhaustive call-path audit is a reviewed document (credplane
``deploy/mac/audit/launchd-git-calls.json``): following a job through its imports
and subprocesses to every network git call is review work, not a grep. This
command keeps that document honest, read-only:

* a loaded-or-installed launchd job the audit never looked at is red
  (``unaudited``) — a new job needs a re-audit before it can be trusted;
* an audited network git call with status ``NEW`` (no decision yet) is red;
* a call marked ``consumer:<label>`` whose inventory row is missing is red;
* ``planned:<label>`` calls, stale audit rows (the job is gone) and moved
  scripts are notes.

Audit JSON: ``{"schema": 1, "vendor_prefixes": [...], "jobs_without_network_git":
[labels], "calls": [{"job", "plist", "script", "operation", "status", ...}]}``;
``status`` is ``consumer:<label>`` | ``planned:<label>`` | ``pending: <phase, what>``
(decided, not built yet) | ``no-key: <why>`` | ``out-of-scope: <why>`` |
``converted: <how>`` | ``NEW`` / ``NEW - <what to decide>`` (no decision yet).
"""

from __future__ import annotations

import json
import os
import plistlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ._common import RefusedError
from .check import Finding, Report
from .inventory import Inventory

DEFAULT_PLIST_DIRS = (
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
)


def load_audit(path: Path) -> dict[str, Any]:
    """Read the audit document."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RefusedError(f"cannot read the audit {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise RefusedError(f"audit {path} is not valid JSON: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema") != 1
        or not isinstance(data.get("calls"), list)
    ):
        raise RefusedError(f"audit {path}: expected an object with schema 1 and a calls list")
    return data


def installed_jobs(dirs: Iterable[str]) -> dict[str, str]:
    """``label -> plist path`` of every plist in *dirs* (unreadable plists keyed by file name)."""
    jobs: dict[str, str] = {}
    for raw in dirs:
        folder = Path(os.path.expanduser(raw))
        if not folder.is_dir():
            continue
        for plist in sorted(folder.glob("*.plist")):
            try:
                with plist.open("rb") as handle:
                    label = str(plistlib.load(handle).get("Label") or plist.stem)
            except (OSError, plistlib.InvalidFileException, ValueError):
                label = plist.stem
            jobs[label] = str(plist)
    return jobs


def _script_path(script: str) -> str:
    """The file part of ``/abs/path.py:123 (notes)``; '' when it is not a path."""
    head = script.split(" ", 1)[0] if script else ""
    path, _, line = head.rpartition(":")
    return path if path and line.isdigit() else head


def run_audit(inv: Inventory, audit: dict[str, Any], jobs: dict[str, str]) -> Report:
    """Compare *audit* with the installed *jobs* and the inventory."""
    findings: list[Finding] = []
    vendor = tuple(audit.get("vendor_prefixes") or ())
    quiet = set(audit.get("jobs_without_network_git") or ())
    audited = {str(c.get("job")) for c in audit["calls"]}

    for label, plist in sorted(jobs.items()):
        if label.startswith(vendor) or label in quiet or label in audited:
            continue
        findings.append(
            Finding(
                label,
                "audit",
                "problem",
                f"unaudited launchd job ({plist}); re-run the audit",
            )
        )

    for call in audit["calls"]:
        job = str(call.get("job"))
        status = str(call.get("status") or "")
        where = f"{call.get('script', '?')} {call.get('operation', '?')}"
        if call.get("plist") and job not in jobs:
            findings.append(Finding(job, "audit", "note", f"stale row, job not installed: {where}"))
        script = _script_path(str(call.get("script") or ""))
        if script and script.startswith("/") and not os.path.exists(script):
            findings.append(Finding(job, "audit", "note", f"script moved or gone: {script}"))
        if status == "NEW" or status.startswith(("NEW ", "NEW:")):
            findings.append(
                Finding(job, "audit", "problem", f"undecided network git call: {where}")
            )
        elif status.startswith("consumer:"):
            label = status.split(":", 1)[1].strip()
            if label not in inv.consumers:
                findings.append(
                    Finding(
                        job,
                        "audit",
                        "problem",
                        f"audit names consumer {label!r}; no such row",
                    )
                )
        elif status.startswith("planned:"):
            label = status.split(":", 1)[1].strip()
            row = inv.consumers.get(label)
            if row is not None and row.status == "active":
                findings.append(
                    Finding(
                        job,
                        "audit",
                        "note",
                        f"{label} is active now; mark the call consumer:{label}",
                    )
                )
            else:
                findings.append(Finding(job, "audit", "note", f"pending ({status}): {where}"))
        elif status.startswith("pending:"):
            findings.append(Finding(job, "audit", "note", f"{status}: {where}"))
        elif not status.startswith(("no-key", "out-of-scope", "converted")):
            findings.append(Finding(job, "audit", "problem", f"unknown status {status!r}: {where}"))

    for consumer in inv.consumers.values():
        if consumer.status == "planned":
            continue
        if consumer.launchd_label not in jobs and not consumer.launchd_label.startswith("hook:"):
            findings.append(
                Finding(
                    consumer.label,
                    "audit",
                    "note",
                    f"launchd job {consumer.launchd_label} is not installed",
                )
            )
    return Report(findings)
