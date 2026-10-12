"""The deploy-key inventory: one schema, one validator (stdlib only, Python 3.9+).

The authoritative source is a TOML file (credplane ``deploy/mac/deploy-keys.toml``);
``deploykey sync`` validates it with :func:`normalize` and installs the result as
JSON. ``deploy-git`` reads only that JSON and re-validates it with the same
function, so a hand-edited runtime copy is refused exactly like a bad source.

Tables:

``[settings]`` (all optional)
    ``key_dir``, ``state_dir``, ``ssh``, ``ssh_keygen``, ``path`` (the fixed PATH
    ``deploy-git run`` resolves ``argv[0]`` on), ``lock_timeout_s``, ``net_timeout_s``.
``[[key]]``
    ``name``, ``path``, ``fingerprint``, ``host``, ``repo``, ``direction``
    (``read``/``write``), ``remote_key_id``, ``policy_id`` (required for active
    write keys), optional ``known_hosts`` (default ``<key_dir>/known_hosts_<host>``),
    ``status`` (``active``/``retiring``/``planned``), ``note``.
``[[consumer]]``
    ``label``, ``launchd_label``, ``key``, ``checkout``, ``remote``, ``refspec``,
    ``git`` (absolute), ``proxy_command``, ``helper_sha``, ``evidence``, optional
    ``max_success_age_s`` (periodic consumers), ``log`` (legacy log), ``uv_lock``
    (library consumers: the lock file that pins ``deploykey``), ``status``
    (``active``/``legacy``/``planned``), ``note``.

``status``: ``planned`` rows are validated for shape only (no key material yet);
``legacy`` consumers are still published by an in-repo helper copy, so
``deploy-git`` refuses them; ``retiring`` keys are in use until a migration is
accepted and are the only way two keys may cover the same repository and direction.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._common import SCHEMA_VERSION, RefusedError

DEFAULT_SETTINGS: dict[str, Any] = {
    "key_dir": "~/.ssh/deploy",
    "state_dir": "~/.local/state/deploykey",
    "ssh": "/usr/bin/ssh",
    "ssh_keygen": "/usr/bin/ssh-keygen",
    "path": (
        "~/.local/bin:~/obsidian/42-Git/home/mydotfiles/bin:/opt/homebrew/bin:"
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    ),
    "lock_timeout_s": 600,
    "net_timeout_s": 120,
}

KEY_FIELDS = {
    "name",
    "path",
    "fingerprint",
    "host",
    "repo",
    "direction",
    "remote_key_id",
    "policy_id",
    "known_hosts",
    "status",
    "note",
}
CONSUMER_FIELDS = {
    "label",
    "launchd_label",
    "key",
    "checkout",
    "remote",
    "refspec",
    "git",
    "proxy_command",
    "helper_sha",
    "evidence",
    "max_success_age_s",
    "log",
    "uv_lock",
    "status",
    "note",
}
KEY_STATUSES = ("active", "retiring", "planned")
CONSUMER_STATUSES = ("active", "legacy", "planned")

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)+$")
_SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9._-]*"
_REPO_RE = re.compile(rf"^{_SEGMENT}(?:/{_SEGMENT})+$")
_FPR_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SCP_URL_RE = re.compile(r"^git@(?P<host>[^:/@\s]+):(?P<path>[^\s]+?)(?:\.git)?/?$")
_SSH_URL_RE = re.compile(r"^ssh://git@(?P<host>[^:/@\s]+)/(?P<path>[^\s]+?)(?:\.git)?/?$")
# git check-ref-format, restricted: no "..", "@{", control chars, ~^:?*[\ or space.
_BAD_REF = re.compile(r"(\.\.|@\{|[\x00-\x20\x7f~^:?*\[\\]|//|/\.|\.lock(/|$)|^\.|/$|\.$)")


def parse_remote_url(url: str) -> tuple[str, str]:
    """``(host, path)`` of an ``git@host:path`` or ``ssh://git@host/path`` URL.

    Refuses ssh aliases (``github:glensk/x``), ports, other users and anything
    that is not a plain ``owner[/group…]/repo`` path: ``ssh -F /dev/null`` cannot
    resolve an alias, and the key opens exactly one repository.
    """
    match = _SCP_URL_RE.match(url) or _SSH_URL_RE.match(url)
    if not match:
        raise RefusedError(f"remote {url!r} is not git@<host>:<path> or ssh://git@<host>/<path>")
    host, path = match["host"], match["path"]
    if not _HOST_RE.match(host):
        raise RefusedError(f"remote {url!r}: {host!r} is not a fully qualified host name")
    if not _REPO_RE.match(path) or ".." in path.split("/"):
        raise RefusedError(f"remote {url!r}: {path!r} is not an owner[/group…]/repo path")
    return host, path


def validate_refspec(refspec: Any, direction: str) -> tuple[str, str]:
    """``(src, dst)`` of a consumer refspec, or :class:`RefusedError`.

    Write rows: exactly one ``<src>:refs/heads/<branch>``; refused are ``+``
    (force), ``*`` (wildcard), an empty source (deletion), several refs and any
    destination outside ``refs/heads/``. Read rows: exactly one
    ``refs/heads/<branch>`` (the branch ``deploy-git pull`` fetches and fast-forwards); ``src``
    and ``dst`` are then both that ref.
    """
    if not isinstance(refspec, str) or not refspec:
        raise RefusedError(f"refspec {refspec!r} must be one non-empty string (one ref)")
    if refspec != refspec.strip() or any(ch.isspace() for ch in refspec):
        raise RefusedError(f"refspec {refspec!r} contains whitespace (several refs?)")
    if refspec.startswith("+"):
        raise RefusedError(f"refspec {refspec!r} forces (leading '+')")
    if "*" in refspec:
        raise RefusedError(f"refspec {refspec!r} is a wildcard")
    if direction == "read":
        if ":" in refspec:
            raise RefusedError(f"read refspec {refspec!r} must be a single refs/heads/<branch>")
        _check_branch_ref(refspec)
        return refspec, refspec
    if refspec.count(":") != 1:
        raise RefusedError(f"write refspec {refspec!r} must be exactly one <src>:<dst>")
    src, dst = refspec.split(":")
    if not src:
        raise RefusedError(f"refspec {refspec!r} has an empty source: that deletes {dst!r}")
    if src != "HEAD" and (_BAD_REF.search(src) or src.startswith("-")):
        raise RefusedError(f"refspec {refspec!r}: source {src!r} is not a plain ref name")
    _check_branch_ref(dst)
    return src, dst


def _check_branch_ref(ref: str) -> None:
    if not ref.startswith("refs/heads/") or len(ref) == len("refs/heads/"):
        raise RefusedError(f"ref {ref!r} is not a branch under refs/heads/")
    if _BAD_REF.search(ref) or ref.endswith(".lock"):
        raise RefusedError(f"ref {ref!r} is not a valid git ref name")


@dataclass(frozen=True)
class Settings:
    """Inventory-wide settings (absolute paths after :func:`normalize`)."""

    key_dir: str
    state_dir: str
    ssh: str
    ssh_keygen: str
    path: str
    lock_timeout_s: int
    net_timeout_s: int


@dataclass(frozen=True)
class Key:
    """One deploy key: exactly one repository and direction."""

    name: str
    path: str
    fingerprint: str
    host: str
    repo: str
    direction: str
    remote_key_id: int | None
    policy_id: int | None
    known_hosts: str
    status: str = "active"
    note: str = ""


@dataclass(frozen=True)
class Consumer:
    """One unattended caller: what it may publish (or fetch), with which key."""

    label: str
    launchd_label: str
    key: str
    checkout: str
    remote: str
    refspec: str
    git: str
    proxy_command: str
    helper_sha: str
    evidence: str
    max_success_age_s: int | None = None
    log: str = ""
    uv_lock: str = ""
    status: str = "active"
    note: str = ""


@dataclass(frozen=True)
class Inventory:
    """A validated inventory."""

    settings: Settings
    keys: dict[str, Key] = field(default_factory=dict)
    consumers: dict[str, Consumer] = field(default_factory=dict)

    def consumer(self, label: str) -> Consumer:
        """The consumer row *label*, or :class:`RefusedError`."""
        try:
            return self.consumers[label]
        except KeyError:
            raise RefusedError(f"no consumer {label!r} in the inventory") from None

    def key_of(self, consumer: Consumer) -> Key:
        """The key row *consumer* uses."""
        return self.keys[consumer.key]


def _expand(value: str) -> str:
    return os.path.expanduser(value)


def _expand_pathlist(value: str) -> str:
    return os.pathsep.join(_expand(part) for part in value.split(os.pathsep) if part)


def _require_str(row: dict[str, Any], name: str, where: str, *, allow_empty: bool = False) -> str:
    value = row.get(name, "")
    if not isinstance(value, str):
        raise RefusedError(f"{where}: {name} must be a string, got {type(value).__name__}")
    if not value and not allow_empty:
        raise RefusedError(f"{where}: {name} is required")
    return value


def _opt_int(row: dict[str, Any], name: str, where: str) -> int | None:
    value = row.get(name)
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RefusedError(f"{where}: {name} must be a positive integer, got {value!r}")
    return value


def _abs_path(value: str, where: str, name: str) -> str:
    expanded = _expand(value)
    if not os.path.isabs(expanded):
        raise RefusedError(f"{where}: {name} {value!r} must be an absolute (or ~/) path")
    return os.path.normpath(expanded)


def _settings(raw: Any) -> Settings:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise RefusedError("settings must be a table")
    unknown = set(raw) - set(DEFAULT_SETTINGS)
    if unknown:
        raise RefusedError(f"settings: unknown field(s) {sorted(unknown)}")
    merged = dict(DEFAULT_SETTINGS, **raw)
    for name in ("lock_timeout_s", "net_timeout_s"):
        value = merged[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RefusedError(f"settings: {name} must be a non-negative integer")
    for name in ("key_dir", "state_dir", "ssh", "ssh_keygen"):
        merged[name] = _abs_path(_require_str(merged, name, "settings"), "settings", name)
    merged["path"] = _expand_pathlist(_require_str(merged, "path", "settings"))
    if any(not os.path.isabs(p) for p in merged["path"].split(os.pathsep)):
        raise RefusedError("settings: every entry of path must be absolute")
    return Settings(**merged)


def _key(row: Any, settings: Settings) -> Key:
    if not isinstance(row, dict):
        raise RefusedError("every [[key]] must be a table")
    where = f"key {row.get('name', '?')!r}"
    unknown = set(row) - KEY_FIELDS
    if unknown:
        raise RefusedError(f"{where}: unknown field(s) {sorted(unknown)}")
    name = _require_str(row, "name", where)
    if not _NAME_RE.match(name):
        raise RefusedError(f"{where}: name must match {_NAME_RE.pattern}")
    status = row.get("status", "active")
    if status not in KEY_STATUSES:
        raise RefusedError(f"{where}: status must be one of {KEY_STATUSES}")
    planned = status == "planned"
    direction = _require_str(row, "direction", where)
    if direction not in ("read", "write"):
        raise RefusedError(f"{where}: direction must be read or write")
    host = _require_str(row, "host", where)
    if not _HOST_RE.match(host):
        raise RefusedError(f"{where}: host {host!r} is not a fully qualified host name")
    repo = _require_str(row, "repo", where)
    if not _REPO_RE.match(repo):
        raise RefusedError(f"{where}: repo {repo!r} is not an owner[/group…]/repo path")
    fingerprint = _require_str(row, "fingerprint", where, allow_empty=planned)
    if fingerprint and not _FPR_RE.match(fingerprint):
        raise RefusedError(f"{where}: fingerprint must be SHA256:<43 base64 chars>")
    remote_key_id = _opt_int(row, "remote_key_id", where)
    policy_id = _opt_int(row, "policy_id", where)
    if not planned and remote_key_id is None:
        raise RefusedError(f"{where}: remote_key_id is required unless status = planned")
    if not planned and direction == "write" and policy_id is None:
        raise RefusedError(f"{where}: a write key needs policy_id (the append-only rule)")
    default_path = os.path.join(settings.key_dir, name)
    path = _abs_path(
        _require_str(row, "path", where, allow_empty=True) or default_path,
        where,
        "path",
    )
    known_default = os.path.join(settings.key_dir, f"known_hosts_{host}")
    known_hosts = _abs_path(
        _require_str(row, "known_hosts", where, allow_empty=True) or known_default,
        where,
        "known_hosts",
    )
    return Key(
        name=name,
        path=path,
        fingerprint=fingerprint,
        host=host,
        repo=repo,
        direction=direction,
        remote_key_id=remote_key_id,
        policy_id=policy_id,
        known_hosts=known_hosts,
        status=status,
        note=_require_str(row, "note", where, allow_empty=True),
    )


def _consumer(row: Any, keys: dict[str, Key]) -> Consumer:
    if not isinstance(row, dict):
        raise RefusedError("every [[consumer]] must be a table")
    where = f"consumer {row.get('label', '?')!r}"
    unknown = set(row) - CONSUMER_FIELDS
    if unknown:
        raise RefusedError(f"{where}: unknown field(s) {sorted(unknown)}")
    label = _require_str(row, "label", where)
    if not _LABEL_RE.match(label):
        raise RefusedError(f"{where}: label must match {_LABEL_RE.pattern}")
    status = row.get("status", "active")
    if status not in CONSUMER_STATUSES:
        raise RefusedError(f"{where}: status must be one of {CONSUMER_STATUSES}")
    key_name = _require_str(row, "key", where)
    if key_name not in keys:
        raise RefusedError(f"{where}: key {key_name!r} is not a [[key]] row")
    key = keys[key_name]
    if key.status == "planned" and status != "planned":
        raise RefusedError(
            f"{where}: uses planned key {key_name!r}; the consumer must be planned too"
        )
    remote = _require_str(row, "remote", where)
    host, path = parse_remote_url(remote)
    if (host, path) != (key.host, key.repo):
        raise RefusedError(
            f"{where}: remote {remote!r} is {host}:{path}, but key {key_name!r} opens "
            f"{key.host}:{key.repo}"
        )
    refspec = _require_str(row, "refspec", where)
    validate_refspec(refspec, key.direction)
    git = _require_str(row, "git", where)
    if not os.path.isabs(git):
        raise RefusedError(f"{where}: git {git!r} must be an absolute path")
    helper = _require_str(row, "helper_sha", where, allow_empty=status != "active")
    if helper and not _SHA_RE.match(helper):
        raise RefusedError(f"{where}: helper_sha must be a full 40-hex commit sha")
    log = _require_str(row, "log", where, allow_empty=True)
    uv_lock = _require_str(row, "uv_lock", where, allow_empty=True)
    return Consumer(
        label=label,
        launchd_label=_require_str(row, "launchd_label", where),
        key=key_name,
        checkout=_abs_path(_require_str(row, "checkout", where), where, "checkout"),
        remote=remote,
        refspec=refspec,
        git=os.path.normpath(git),
        proxy_command=_require_str(row, "proxy_command", where, allow_empty=True),
        helper_sha=helper,
        evidence=_abs_path(_require_str(row, "evidence", where), where, "evidence"),
        max_success_age_s=_opt_int(row, "max_success_age_s", where),
        log=_abs_path(log, where, "log") if log else "",
        uv_lock=_abs_path(uv_lock, where, "uv_lock") if uv_lock else "",
        status=status,
        note=_require_str(row, "note", where, allow_empty=True),
    )


def build(raw: Any) -> Inventory:
    """Validate a raw inventory mapping (parsed TOML or runtime JSON)."""
    if not isinstance(raw, dict):
        raise RefusedError("the inventory must be a table/object")
    unknown = set(raw) - {"schema", "settings", "key", "consumer"}
    if unknown:
        raise RefusedError(f"inventory: unknown top-level field(s) {sorted(unknown)}")
    if raw.get("schema") != SCHEMA_VERSION:
        raise RefusedError(f"inventory: schema must be {SCHEMA_VERSION}, got {raw.get('schema')!r}")
    settings = _settings(raw.get("settings"))
    keys: dict[str, Key] = {}
    for row in raw.get("key", []) or []:
        key = _key(row, settings)
        if key.name in keys:
            raise RefusedError(f"duplicate key name {key.name!r}")
        keys[key.name] = key
    _check_one_key_per_repo(keys)
    consumers: dict[str, Consumer] = {}
    for row in raw.get("consumer", []) or []:
        consumer = _consumer(row, keys)
        if consumer.label in consumers:
            raise RefusedError(f"duplicate consumer label {consumer.label!r}")
        consumers[consumer.label] = consumer
    return Inventory(settings=settings, keys=keys, consumers=consumers)


def _check_one_key_per_repo(keys: dict[str, Key]) -> None:
    """One key per repository and direction; only ``retiring`` keys may overlap."""
    seen: dict[tuple[str, str, str], str] = {}
    for key in keys.values():
        if key.status == "retiring":
            continue
        slot = (key.host, key.repo, key.direction)
        if slot in seen:
            raise RefusedError(
                f"keys {seen[slot]!r} and {key.name!r} both cover {key.host}:{key.repo} "
                f'({key.direction}); mark the one being replaced status = "retiring"'
            )
        seen[slot] = key.name


def normalize(raw: Any) -> dict[str, Any]:
    """The runtime JSON form of a raw inventory: validated, ``~`` expanded, defaults filled."""
    inv = build(raw)
    return to_json(inv)


def to_json(inv: Inventory) -> dict[str, Any]:
    """Serialise a validated inventory (stable field order, JSON-safe)."""

    def row(obj: Any) -> dict[str, Any]:
        return {name: getattr(obj, name) for name in obj.__dataclass_fields__}

    return {
        "schema": SCHEMA_VERSION,
        "settings": row(inv.settings),
        "key": [row(k) for k in inv.keys.values()],
        "consumer": [row(c) for c in inv.consumers.values()],
    }


def load_runtime(path: Path) -> Inventory:
    """Read and validate the installed runtime JSON; any problem is :class:`RefusedError`."""
    import json  # pylint: disable=import-outside-toplevel

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RefusedError(f"cannot read the runtime inventory {path}: {exc.strerror}") from exc
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise RefusedError(f"runtime inventory {path} is not valid JSON: {exc}") from exc
    return build(raw)
