"""``deploykey check`` — every unattended-push health rule, implemented once.

Five classes of red, per inventory row (credplane PLAN_unattended-push-keys.md (h)):

1. ``key-config``: key file missing or not 0600, fingerprint mismatch, pinned host
   keys missing, an active consumer's ``helper_sha`` differing from the installed
   CLI (or its ``uv_lock`` pin), the runtime JSON differing from the TOML source,
   and a live read-only ``ls-remote`` probe that fails authentication (the probe
   is configuration evidence only — it never counts as a publication);
2. ``publication``: the consumer's last recorded attempt failed, or a periodic
   consumer's last success is older than ``max_success_age_s``;
3. ``stuck``: the checkout is ahead of (or diverged from) the **live** remote OID
   with the oldest unpushed commit older than 24 h (behind is a note);
4. ``log``: a legacy log shows an ssh auth failure that no later success cleared;
5. ``policy``: a write repository is not append-only (GitHub effective rules
   without ``deletion``/``non_fast_forward``, GitLab branch unprotected, force
   push allowed or the deploy key missing from ``allowed_to_push``).

``offline`` (``-d``) skips everything that needs the network (probe, stuck,
policy). Checks never push, pull, fetch or write anything but their own
log-scan offsets under ``state_dir``.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import os
import re
import subprocess  # nosec B404 - fixed argv, never a shell
import sys
import urllib.parse
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import evidence
from ._common import RefusedError, write_json_atomic
from .gitenv import check_file, git, git_env
from .inventory import Consumer, Inventory, Key, to_json, validate_refspec

STUCK_AGE_S = 24 * 3600
AUTH_FAIL_RE = re.compile(
    r"Permission denied \(publickey|sign_and_send_pubkey|agent refused operation|"
    r"Host key verification failed|no mutual signature algorithm|"
    r"Could not read from remote repository",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    """One result line: ``level`` is ``problem`` (red) or ``note``."""

    row: str
    cls: str
    level: str
    text: str


@dataclass
class Report:
    """All findings of one check run."""

    findings: list[Finding]

    @property
    def ok(self) -> bool:
        """No red finding."""
        return not any(f.level == "problem" for f in self.findings)

    def to_json(self) -> dict[str, Any]:
        """The machine-readable report (infra/status renders this)."""
        return {"ok": self.ok, "findings": [asdict(f) for f in self.findings]}


#: Test seam: ``api(tool, path, host)`` → parsed JSON; raises tools.ApiError.
ApiFn = Callable[[str, str, str], Any]


def _default_api(tool: str, path: str, host: str) -> Any:
    from .tools import api_json  # pylint: disable=import-outside-toplevel

    return api_json(tool, path, host=host)


def fingerprint_of_public(line: str) -> str:
    """``SHA256:…`` of an OpenSSH public key line (``type base64 [comment]``)."""
    parts = line.split()
    if len(parts) < 2:
        raise ValueError("not an OpenSSH public key line")
    blob = base64.b64decode(parts[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def derive_fingerprint(ssh_keygen: str, key_path: str) -> str:
    """Fingerprint of the public half derived from the private key itself."""
    proc = subprocess.run(  # nosec B603 - absolute ssh-keygen from the inventory
        [ssh_keygen, "-y", "-P", "", "-f", key_path],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise ValueError((proc.stderr or "").strip() or f"ssh-keygen rc={proc.returncode}")
    return fingerprint_of_public(proc.stdout)


def _host_pinned(ssh_keygen: str, known_hosts: str, host: str) -> bool:
    proc = subprocess.run(  # nosec B603 - absolute ssh-keygen from the inventory
        [ssh_keygen, "-F", host, "-f", known_hosts],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return proc.returncode == 0 and bool(proc.stdout.strip())


def uv_lock_sha(path: str) -> str | None:
    """The commit sha a ``uv.lock`` pins ``deploykey`` to, ``None`` when absent."""
    if sys.version_info < (3, 11):
        return None
    import tomllib  # pylint: disable=import-outside-toplevel

    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    for package in data.get("package", []):
        if package.get("name") != "deploykey":
            continue
        git_url = str((package.get("source") or {}).get("git") or "")
        sha = git_url.rpartition("#")[2]
        return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None
    return None


class Checker:
    """Runs the five rule classes over one inventory."""

    def __init__(
        self,
        inv: Inventory,
        *,
        helper: str,
        source_json: dict[str, Any] | None = None,
        offline: bool = False,
        api: ApiFn | None = None,
        now: _dt.datetime | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.inv = inv
        self.helper = helper
        self.source_json = source_json
        self.offline = offline
        self.api = api or _default_api
        self.now = now or _dt.datetime.now(_dt.timezone.utc)
        self.env = dict(os.environ if env is None else env)
        self.findings: list[Finding] = []
        self.live_oid: dict[str, str | None] = {}

    def add(self, row: str, cls: str, level: str, text: str) -> None:
        """Record one finding."""
        self.findings.append(Finding(row, cls, level, text))

    def run(self) -> Report:
        """All classes, in order."""
        if self.source_json is not None and self.source_json != to_json(self.inv):
            self.add(
                "inventory",
                "key-config",
                "problem",
                "installed runtime JSON differs from the TOML source; "
                "run `deploykey sync -i <toml>`",
            )
        for key in self.inv.keys.values():
            self.check_key(key)
        for consumer in self.inv.consumers.values():
            self.check_consumer(consumer)
        if not self.offline:
            for key in self.inv.keys.values():
                if key.direction == "write" and key.status != "planned":
                    self.check_policy(key)
        return Report(self.findings)

    # -- class 1 --------------------------------------------------------------
    def check_key(self, key: Key) -> None:
        """Key file, mode, fingerprint and pinned host keys."""
        if key.status == "planned":
            self.add(key.name, "key-config", "note", "planned, not provisioned yet")
            return
        settings = self.inv.settings
        try:
            check_file(key.path, "deploy key", private=True)
        except RefusedError as exc:
            self.add(key.name, "key-config", "problem", str(exc))
        else:
            try:
                actual = derive_fingerprint(settings.ssh_keygen, key.path)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                self.add(key.name, "key-config", "problem", f"cannot read {key.path}: {exc}")
            else:
                if actual != key.fingerprint:
                    self.add(
                        key.name,
                        "key-config",
                        "problem",
                        f"fingerprint {actual} != inventory {key.fingerprint}",
                    )
        try:
            check_file(key.known_hosts, f"pinned {key.host} host keys", private=False)
        except RefusedError as exc:
            self.add(key.name, "key-config", "problem", str(exc))
        else:
            if not _host_pinned(settings.ssh_keygen, key.known_hosts, key.host):
                self.add(
                    key.name,
                    "key-config",
                    "problem",
                    f"{key.known_hosts} has no entry for {key.host}",
                )

    def check_consumer(self, consumer: Consumer) -> None:
        """Classes 1 (helper, probe), 2, 3 and 4 for one consumer row."""
        if consumer.status == "planned":
            self.add(consumer.label, "key-config", "note", "planned, not provisioned yet")
            return
        if consumer.status == "active":
            if consumer.helper_sha != self.helper:
                self.add(
                    consumer.label,
                    "key-config",
                    "problem",
                    f"helper_sha {consumer.helper_sha[:12]} != installed deploykey "
                    f"{self.helper[:12]}",
                )
            if consumer.uv_lock:
                pinned = uv_lock_sha(consumer.uv_lock)
                if pinned != consumer.helper_sha:
                    self.add(
                        consumer.label,
                        "key-config",
                        "problem",
                        f"{consumer.uv_lock} pins deploykey at {pinned or 'nothing'}, "
                        f"inventory says {consumer.helper_sha[:12]}",
                    )
            self.check_evidence(consumer)
        else:
            self.add(
                consumer.label,
                "publication",
                "note",
                "legacy: published by its in-repo helper",
            )
        if consumer.log:
            self.check_log(consumer)
        if not self.offline:
            self.probe(consumer)
            if self.inv.key_of(consumer).direction == "write":
                self.check_stuck(consumer)

    def probe(self, consumer: Consumer) -> None:
        """Read-only ``git ls-remote`` of the row's branch through its key (config evidence)."""
        key = self.inv.key_of(consumer)
        _, dst = validate_refspec(consumer.refspec, key.direction)
        try:
            env = git_env(self.inv, consumer, self.env)
            proc = git(
                consumer,
                "ls-remote",
                consumer.remote,
                dst,
                env=env,
                timeout=min(60, self.inv.settings.net_timeout_s or 60),
            )
        except RefusedError as exc:
            self.add(consumer.label, "key-config", "problem", f"probe refused: {exc}")
            self.live_oid[consumer.label] = None
            return
        except subprocess.TimeoutExpired:
            self.add(
                consumer.label,
                "key-config",
                "note",
                "probe inconclusive: ls-remote timed out",
            )
            self.live_oid[consumer.label] = None
            return
        if proc.returncode == 0:
            oid = proc.stdout.split()[0] if proc.stdout.split() else None
            self.live_oid[consumer.label] = oid
            self.add(
                consumer.label,
                "key-config",
                "note",
                f"probe ok: {dst} = {oid or 'absent'}",
            )
            return
        self.live_oid[consumer.label] = None
        text = (proc.stderr or "").strip()
        level = "problem" if AUTH_FAIL_RE.search(text) else "note"
        what = "probe failed authentication" if level == "problem" else "probe inconclusive"
        self.add(consumer.label, "key-config", level, f"{what}: {text[-300:]}")

    # -- class 2 --------------------------------------------------------------
    def check_evidence(self, consumer: Consumer) -> None:
        """The last real attempt, and the age of the last success for periodic rows."""
        record = evidence.read(consumer.evidence)
        if record is None:
            self.add(consumer.label, "publication", "note", "no publication recorded yet")
            return
        rc = record.get("last_attempt_rc")
        if rc != 0:
            self.add(
                consumer.label,
                "publication",
                "problem",
                f"last attempt {record.get('last_attempt_at')} failed (rc={rc}): "
                f"{str(record.get('last_attempt_message') or '')[-300:]}",
            )
        if consumer.max_success_age_s:
            last = evidence.parse_iso(record.get("last_success_at"))
            if last is None:
                self.add(consumer.label, "publication", "problem", "never succeeded")
            else:
                age = (self.now - last).total_seconds()
                if age > consumer.max_success_age_s:
                    self.add(
                        consumer.label,
                        "publication",
                        "problem",
                        f"last success {record.get('last_success_at')} is {int(age)}s old "
                        f"(> {consumer.max_success_age_s}s)",
                    )

    # -- class 3 --------------------------------------------------------------
    def check_stuck(self, consumer: Consumer) -> None:
        """Ahead/diverged against the live remote OID, oldest unpushed commit > 24 h."""
        remote = self.live_oid.get(consumer.label)
        if not remote:
            return
        src, _ = validate_refspec(consumer.refspec, "write")
        local = git(consumer, "rev-parse", "--verify", "--quiet", f"{src}^{{commit}}")
        if local.returncode != 0:
            self.add(
                consumer.label,
                "stuck",
                "note",
                f"{src} does not resolve in the checkout",
            )
            return
        sha = local.stdout.strip()
        if sha == remote:
            return
        if git(consumer, "cat-file", "-e", f"{remote}^{{commit}}").returncode != 0:
            self.add(
                consumer.label,
                "stuck",
                "note",
                f"remote is at {remote[:12]}, not present locally "
                "(behind or diverged; fetch to compare)",
            )
            return
        times = git(consumer, "log", "--format=%ct", f"{remote}..{sha}").stdout.split()
        behind = git(consumer, "rev-list", "--count", f"{sha}..{remote}").stdout.strip()
        if not times:
            self.add(
                consumer.label,
                "stuck",
                "note",
                f"behind the remote by {behind} commit(s)",
            )
            return
        oldest = min(int(t) for t in times)
        age = self.now.timestamp() - oldest
        state = "diverged" if behind not in ("", "0") else "ahead"
        level = "problem" if age > STUCK_AGE_S else "note"
        self.add(
            consumer.label,
            "stuck",
            level,
            f"{state}: {len(times)} unpushed commit(s), oldest {int(age // 3600)} h old",
        )

    # -- class 4 --------------------------------------------------------------
    def check_log(self, consumer: Consumer) -> None:
        """Auth failures in a legacy log since the last success (rotation-safe offsets)."""
        state_path = Path(self.inv.settings.state_dir) / f"logscan-{_safe(consumer.label)}.json"
        state = evidence.read(state_path) or {}
        try:
            st = os.stat(consumer.log)
        except OSError:
            self.add(consumer.label, "log", "note", f"log {consumer.log} not found")
            return
        offset = int(state.get("offset") or 0)
        if state.get("inode") != st.st_ino or st.st_size < offset:
            offset = 0  # rotated or truncated: rescan, keep any unresolved failure
        with open(consumer.log, "rb") as handle:
            handle.seek(offset)
            chunk = handle.read()
        hits = [
            line
            for line in chunk.decode("utf-8", "replace").splitlines()
            if AUTH_FAIL_RE.search(line)
        ]
        failure = state.get("failure")
        if hits:
            failure = {"line": hits[-1][-300:], "seen_at": self.now.isoformat()}
        if failure:
            record = evidence.read(consumer.evidence) or {}
            success = evidence.parse_iso(record.get("last_success_at"))
            seen = evidence.parse_iso(failure.get("seen_at"))
            if success and seen and success > seen:
                failure = None
        write_json_atomic(
            state_path,
            {"inode": st.st_ino, "offset": offset + len(chunk), "failure": failure},
            mode=0o644,
        )
        if failure:
            self.add(
                consumer.label,
                "log",
                "problem",
                f"ssh auth failure in {consumer.log} not cleared by a later success: "
                f"{failure['line']}",
            )

    # -- class 5 --------------------------------------------------------------
    def check_policy(self, key: Key) -> None:
        """The write repository is append-only on its default branch(es)."""
        from .tools import ApiError  # pylint: disable=import-outside-toplevel

        branches = sorted(
            {
                validate_refspec(c.refspec, "write")[1][len("refs/heads/") :]
                for c in self.inv.consumers.values()
                if c.key == key.name and c.status != "planned"
            }
        ) or ["main"]
        for branch in branches:
            try:
                problem = (
                    self._github_policy(key, branch)
                    if key.host == "github.com"
                    else self._gitlab_policy(key, branch)
                )
            except ApiError as exc:
                problem = f"cannot read the policy: {exc}"
            except RefusedError as exc:
                problem = str(exc)
            if problem:
                self.add(key.name, "policy", "problem", f"{key.repo}:{branch}: {problem}")

    def _github_policy(self, key: Key, branch: str) -> str:
        rules = self.api("gh", f"repos/{key.repo}/rules/branches/{branch}", "") or []
        types = {r.get("type") for r in rules if isinstance(r, dict)}
        missing = sorted({"deletion", "non_fast_forward"} - types)
        if missing:
            return f"effective rules lack {', '.join(missing)}"
        ruleset = self.api("gh", f"repos/{key.repo}/rulesets/{key.policy_id}", "") or {}
        if ruleset.get("enforcement") != "active":
            return f"ruleset {key.policy_id} enforcement is {ruleset.get('enforcement')!r}"
        return ""

    def _gitlab_policy(self, key: Key, branch: str) -> str:
        project = urllib.parse.quote(key.repo, safe="")
        data = self.api("glab", f"projects/{project}/protected_branches/{branch}", key.host) or {}
        if key.policy_id is not None and data.get("id") != key.policy_id:
            return f"protected branch id {data.get('id')} != policy_id {key.policy_id}"
        if data.get("allow_force_push") is not False:
            return "force push is allowed"
        pushers = {lvl.get("deploy_key_id") for lvl in data.get("push_access_levels") or []}
        if key.remote_key_id not in pushers:
            return f"deploy key {key.remote_key_id} is not in allowed_to_push"
        return ""


def _safe(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", label)


def run_check(
    inv: Inventory,
    *,
    helper: str,
    source_json: dict[str, Any] | None = None,
    offline: bool = False,
    api: ApiFn | None = None,
    now: _dt.datetime | None = None,
    env: dict[str, str] | None = None,
) -> Report:
    """Convenience wrapper around :class:`Checker`."""
    return Checker(
        inv,
        helper=helper,
        source_json=source_json,
        offline=offline,
        api=api,
        now=now,
        env=env,
    ).run()
