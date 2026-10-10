"""``deploykey reconcile`` — provision one key, keyed by fingerprint and remote id.

Create if absent, verify if present, refuse on any mismatch — never "fix" a
mismatch by overwriting. Reconcile never edits the TOML inventory: it prints the
fingerprint, remote key id and policy id to record there.

Order of one run (credplane PLAN_unattended-push-keys.md (i)/(j)):

1. local key: generate (ed25519, no passphrase, 0600) when the file is absent;
   its derived fingerprint must equal the inventory's when that is set;
2. remote deploy key: find the repository's deploy key carrying that
   fingerprint; its id must equal ``remote_key_id`` when set; its write access
   must match ``direction``; absent → register it;
3. with ``policy`` (write keys only): snapshot every ruleset + the effective rules
   (GitHub) or the protected branches, deploy keys and project settings (GitLab)
   into the evidence directory, then verify or create the append-only rule —
   GitHub ruleset ``append-only-main`` (``deletion`` + ``non_fast_forward``, no
   bypass actors), GitLab protected branch with ``allow_force_push=false`` and the
   deploy key in ``allowed_to_push``.

Rollback order (documented, never automated): restore the consumer → restore the
policy from its snapshot → revoke the remote key → remove the local key material.
"""

from __future__ import annotations

import datetime as _dt
import os
import subprocess  # nosec B404 - fixed argv, never a shell
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ._common import RefusedError, write_json_atomic
from .check import derive_fingerprint, fingerprint_of_public
from .gitenv import check_file
from .inventory import Inventory, Key, validate_refspec

#: ``api(tool, path, host, method, fields)`` → parsed JSON; raises tools.ApiError.
ApiFn = Callable[[str, str, str, str, "dict[str, Any] | None"], Any]

RULESET_NAME = "append-only-main"


def _default_api(
    tool: str, path: str, host: str, method: str, fields: dict[str, Any] | None
) -> Any:
    from .tools import api_json  # pylint: disable=import-outside-toplevel

    return api_json(tool, path, host=host, method=method, fields=fields)


def ruleset_body(branch: str) -> dict[str, Any]:
    """The append-only ruleset (copied from glensk/obsidian_vault 24836889)."""
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [f"refs/heads/{branch}"], "exclude": []}},
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
        "bypass_actors": [],
    }


class Reconciler:
    """One reconcile run for one key row."""

    def __init__(
        self,
        inv: Inventory,
        key_name: str,
        *,
        dry_run: bool = False,
        policy: bool = False,
        evidence_dir: Path | None = None,
        api: ApiFn | None = None,
        say: Callable[[str], None] = print,
    ) -> None:
        if key_name not in inv.keys:
            raise RefusedError(f"no key {key_name!r} in the inventory")
        self.inv = inv
        self.key: Key = inv.keys[key_name]
        self.dry_run = dry_run
        self.policy = policy
        self.evidence_dir = evidence_dir
        self.api = api or _default_api
        self.say = say
        self.stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @property
    def gitlab(self) -> bool:
        """True for a GitLab host (everything that is not github.com)."""
        return self.key.host != "github.com"

    @property
    def project(self) -> str:
        """URL-encoded GitLab project path."""
        return urllib.parse.quote(self.key.repo, safe="")

    def _call(self, path: str, method: str = "GET", fields: dict[str, Any] | None = None) -> Any:
        tool = "glab" if self.gitlab else "gh"
        return self.api(tool, path, self.key.host if self.gitlab else "", method, fields)

    def run(self) -> dict[str, Any]:
        """Reconcile; returns the values to record in the inventory."""
        fingerprint = self.local_key()
        result: dict[str, Any] = {"name": self.key.name, "fingerprint": fingerprint}
        result["remote_key_id"] = self.remote_key(fingerprint)
        if self.policy:
            if self.key.direction != "write":
                raise RefusedError(f"key {self.key.name!r} is a read key; it has no push policy")
            result["policy_id"] = self.remote_policy(result["remote_key_id"])
        return result

    # -- 1. local ----------------------------------------------------------------
    def local_key(self) -> str | None:
        """Generate when absent; verify the fingerprint when present."""
        key = self.key
        if not os.path.lexists(key.path):
            if self.dry_run:
                self.say(f"would generate {key.path} (ed25519, 0600)")
                return key.fingerprint or None
            Path(key.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            comment = f"mac deploykey {key.name} -> {key.host}:{key.repo} ({key.direction})"
            subprocess.run(  # nosec B603 - absolute ssh-keygen from the inventory
                [
                    self.inv.settings.ssh_keygen,
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    comment,
                    "-f",
                    key.path,
                ],
                check=True,
                capture_output=True,
                timeout=60,
                stdin=subprocess.DEVNULL,
            )
            self.say(f"✅ generated {key.path}")
        check_file(key.path, "deploy key", private=True)
        try:
            actual = derive_fingerprint(self.inv.settings.ssh_keygen, key.path)
        except ValueError as exc:
            raise RefusedError(f"cannot read {key.path}: {exc}") from exc
        if key.fingerprint and actual != key.fingerprint:
            raise RefusedError(f"{key.path} is {actual}, inventory says {key.fingerprint}")
        pub = Path(f"{key.path}.pub")
        if pub.exists() and fingerprint_of_public(pub.read_text(encoding="utf-8")) != actual:
            raise RefusedError(f"{pub} does not belong to {key.path}")
        self.say(f"✅ local key {key.path} {actual}")
        return actual

    def _public_line(self) -> str:
        proc = subprocess.run(  # nosec B603 - absolute ssh-keygen from the inventory
            [self.inv.settings.ssh_keygen, "-y", "-P", "", "-f", self.key.path],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
        )
        return " ".join(proc.stdout.split()[:2])

    # -- 2. remote key -----------------------------------------------------------
    def remote_key(self, fingerprint: str | None) -> int | None:
        """Find by fingerprint, verify id and access, register when absent."""
        key = self.key
        listing = self._call(
            f"projects/{self.project}/deploy_keys" if self.gitlab else f"repos/{key.repo}/keys"
        )
        found = None
        for entry in listing or []:
            try:
                if fingerprint and fingerprint_of_public(str(entry.get("key", ""))) == fingerprint:
                    found = entry
                    break
            except (ValueError, TypeError):
                continue
        if found is not None:
            rid = int(found["id"])
            if key.remote_key_id is not None and rid != key.remote_key_id:
                raise RefusedError(
                    f"{key.repo}: fingerprint {fingerprint} is remote key {rid}, "
                    f"inventory says {key.remote_key_id}"
                )
            writes = (
                bool(found.get("can_push")) if self.gitlab else not found.get("read_only", True)
            )
            if writes != (key.direction == "write"):
                raise RefusedError(
                    f"{key.repo}: remote key {rid} has write={writes}, inventory direction is "
                    f"{key.direction}"
                )
            self.say(f"✅ remote deploy key {rid} on {key.host}:{key.repo}")
            return rid
        if key.remote_key_id is not None:
            raise RefusedError(
                f"{key.repo}: inventory remote_key_id {key.remote_key_id} but no deploy key "
                f"there carries {fingerprint}"
            )
        title = f"Mac deploykey {key.name} ({key.direction})"
        if self.dry_run or fingerprint is None:
            self.say(f"would register {key.name} on {key.host}:{key.repo} ({key.direction})")
            return None
        if self.gitlab:
            body = {
                "title": title,
                "key": self._public_line(),
                "can_push": key.direction == "write",
            }
            created = self._call(f"projects/{self.project}/deploy_keys", "POST", body)
        else:
            body = {
                "title": title,
                "key": self._public_line(),
                "read_only": key.direction == "read",
            }
            created = self._call(f"repos/{key.repo}/keys", "POST", body)
        rid = int(created["id"])
        self.say(f"✅ registered remote deploy key {rid} on {key.host}:{key.repo}")
        return rid

    # -- 3. policy ---------------------------------------------------------------
    def _branch(self) -> str:
        branches = {
            validate_refspec(c.refspec, "write")[1][len("refs/heads/") :]
            for c in self.inv.consumers.values()
            if c.key == self.key.name
        }
        if len(branches) > 1:
            raise RefusedError(
                f"key {self.key.name!r} consumers push to several branches {sorted(branches)}"
            )
        return branches.pop() if branches else "main"

    def snapshot(self, branch: str) -> Path | None:
        """Write the current remote policy state before any change."""
        if self.evidence_dir is None:
            raise RefusedError("policy reconcile needs an evidence directory (-e) for the snapshot")
        slug = self.key.repo.replace("/", "_")
        if self.gitlab:
            data = {
                "protected_branches": self._call(f"projects/{self.project}/protected_branches"),
                "deploy_keys": self._call(f"projects/{self.project}/deploy_keys"),
                "settings": self._call(f"projects/{self.project}"),
            }
        else:
            rulesets = self._call(f"repos/{self.key.repo}/rulesets?includes_parents=true") or []
            data = {
                "rulesets": rulesets,
                "detail": [
                    self._call(f"repos/{self.key.repo}/rulesets/{r['id']}") for r in rulesets
                ],
                "effective": self._call(f"repos/{self.key.repo}/rules/branches/{branch}"),
            }
        path = self.evidence_dir / f"{self.stamp}-{slug}-policy.json"
        write_json_atomic(path, data, mode=0o644)
        self.say(f"✅ snapshot {path}")
        return path

    def remote_policy(self, remote_key_id: int | None) -> int | None:
        """Verify or create the append-only rule; returns its id."""
        branch = self._branch()
        self.snapshot(branch)
        if self.gitlab:
            return self._gitlab_policy(branch, remote_key_id)
        return self._github_policy(branch)

    def _github_policy(self, branch: str) -> int | None:
        repo = self.key.repo
        candidates = []
        if self.key.policy_id is not None:
            candidates = [self._call(f"repos/{repo}/rulesets/{self.key.policy_id}")]
        else:
            for item in self._call(f"repos/{repo}/rulesets") or []:
                if item.get("name") == RULESET_NAME:
                    candidates.append(self._call(f"repos/{repo}/rulesets/{item['id']}"))
        for ruleset in candidates:
            problem = _ruleset_problem(ruleset, branch)
            if problem:
                raise RefusedError(f"{repo}: ruleset {ruleset.get('id')} {problem}")
            self.say(f"✅ ruleset {ruleset['id']} keeps {repo}:{branch} append-only")
            return int(ruleset["id"])
        if self.dry_run:
            self.say(f"would create ruleset {RULESET_NAME} on {repo}:{branch}")
            return None
        created = self._call(f"repos/{repo}/rulesets", "POST", ruleset_body(branch))
        self.say(f"✅ created ruleset {created['id']} on {repo}:{branch}")
        return int(created["id"])

    def _gitlab_policy(self, branch: str, remote_key_id: int | None) -> int | None:
        from .tools import ApiError  # pylint: disable=import-outside-toplevel

        repo = self.key.repo
        try:
            data = self._call(f"projects/{self.project}/protected_branches/{branch}")
        except ApiError as exc:
            if not exc.not_found:
                raise RefusedError(f"{repo}: cannot read protected branch {branch}: {exc}") from exc
            data = None
        if data:
            pushers = {lvl.get("deploy_key_id") for lvl in data.get("push_access_levels") or []}
            if self.key.policy_id is not None and data.get("id") != self.key.policy_id:
                raise RefusedError(
                    f"{repo}: protected {branch} is id {data.get('id')}, "
                    f"inventory says {self.key.policy_id}"
                )
            if data.get("allow_force_push") is not False:
                raise RefusedError(
                    f"{repo}: protected {branch} allows force push; fix it by hand, then rerun"
                )
            if remote_key_id not in pushers:
                raise RefusedError(
                    f"{repo}: deploy key {remote_key_id} is not allowed to push to {branch}"
                )
            self.say(f"✅ {repo}:{branch} protected (id {data['id']}), deploy key may push")
            return int(data["id"])
        if self.key.policy_id is not None:
            raise RefusedError(
                f"{repo}: inventory policy_id {self.key.policy_id} but {branch} is unprotected"
            )
        if self.dry_run or remote_key_id is None:
            self.say(f"would protect {repo}:{branch} (no force push, deploy key may push)")
            return None
        body = {
            "name": branch,
            "allowed_to_push": [{"access_level": 30}, {"deploy_key_id": remote_key_id}],
            "merge_access_level": 30,
            "allow_force_push": False,
        }
        created = self._call(f"projects/{self.project}/protected_branches", "POST", body)
        self.say(f"✅ protected {repo}:{branch} (id {created['id']})")
        return int(created["id"])


def _ruleset_problem(ruleset: dict[str, Any], branch: str) -> str:
    """Why *ruleset* is not an append-only rule for *branch* ('' when it is)."""
    if ruleset.get("enforcement") != "active":
        return f"is {ruleset.get('enforcement')!r}, not active"
    include = ((ruleset.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    if f"refs/heads/{branch}" not in include and "~DEFAULT_BRANCH" not in include:
        return f"does not target refs/heads/{branch} ({include})"
    types = {r.get("type") for r in ruleset.get("rules") or []}
    missing = {"deletion", "non_fast_forward"} - types
    if missing:
        return f"lacks {sorted(missing)}"
    if ruleset.get("bypass_actors"):
        return "has bypass actors"
    return ""
