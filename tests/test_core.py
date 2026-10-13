"""Runtime core: inventory rules, ssh/git env, push/pull/run/publish, lock, evidence.

stdlib ``unittest`` only — this module also runs under macOS's /usr/bin/python3 (3.9).
"""

from __future__ import annotations

import contextlib
import copy
import io
import os
import shlex
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import deploykey
from deploykey import cli_git, ops
from deploykey._common import EXIT_FAILED, EXIT_OK, EXIT_REFUSED, DeployKeyError, RefusedError
from deploykey.gitenv import append_git_config, git_common_dir, git_env, local_env, ssh_command
from deploykey.inventory import Inventory, build, parse_remote_url, validate_refspec
from deploykey.lock import repo_lock

from .support import GIT, Sandbox, run


class UrlAndRefspecTest(unittest.TestCase):
    """Remote URL parsing and refspec validation."""

    def test_scp_and_ssh_forms(self) -> None:
        """scp-style and ``ssh://`` URLs both parse to (host, repo)."""
        self.assertEqual(
            parse_remote_url("git@github.com:glensk/demo.git"), ("github.com", "glensk/demo")
        )
        self.assertEqual(
            parse_remote_url("ssh://git@github.com/glensk/demo"), ("github.com", "glensk/demo")
        )

    def test_nested_gitlab_group(self) -> None:
        """A nested GitLab group path is kept whole as the repo."""
        self.assertEqual(
            parse_remote_url("git@gitlab.datascience.ch:cloud-services/sub/cscs.git"),
            ("gitlab.datascience.ch", "cloud-services/sub/cscs"),
        )

    def test_ssh_alias_and_odd_urls_refused(self) -> None:
        """ssh aliases, https, ports, other users and path tricks are refused."""
        for url in (
            "github:glensk/demo",
            "git@github:glensk/demo.git",
            "https://github.com/glensk/demo",
            "ssh://git@github.com:22/glensk/demo",
            "root@github.com:glensk/demo",
            "git@github.com:demo",
            "git@github.com:glensk/../x",
        ):
            with self.subTest(url=url), self.assertRaises(RefusedError):
                parse_remote_url(url)

    def test_forbidden_refspecs(self) -> None:
        """Forcing, wildcard, deleting, tag, multi and malformed refspecs are refused."""
        for spec in (
            "+HEAD:refs/heads/main",
            "refs/heads/*:refs/heads/*",
            ":refs/heads/main",
            "HEAD:refs/tags/v1",
            "HEAD:main",
            "HEAD:refs/heads/main HEAD:refs/heads/x",
            "HEAD:refs/heads/a:refs/heads/b",
            "HEAD:refs/heads/",
            "HEAD:refs/heads/a..b",
            "--force:refs/heads/main",
            "",
        ):
            with self.subTest(spec=spec), self.assertRaises(RefusedError):
                validate_refspec(spec, "write")
        with self.assertRaises(RefusedError):
            validate_refspec(["HEAD:refs/heads/main"], "write")
        with self.assertRaises(RefusedError):
            validate_refspec("HEAD:refs/heads/main", "read")

    def test_valid_refspecs(self) -> None:
        """A plain write and a plain read refspec parse to (source, destination)."""
        self.assertEqual(
            validate_refspec("HEAD:refs/heads/main", "write"), ("HEAD", "refs/heads/main")
        )
        self.assertEqual(
            validate_refspec("refs/heads/main", "read"), ("refs/heads/main", "refs/heads/main")
        )


class InventoryTest(Sandbox):
    """Inventory validation rules in ``build``."""

    def test_valid(self) -> None:
        """The sandbox inventory builds and defaults known_hosts to the key dir."""
        inv = self.inventory()
        self.assertEqual(sorted(inv.consumers), ["demo-pull", "demo-push"])
        self.assertEqual(
            inv.keys["github-demo-write"].known_hosts, str(self.keydir / "known_hosts_github.com")
        )

    def _refused(self, raw: dict, needle: str) -> None:  # type: ignore[type-arg]
        with self.assertRaises(RefusedError) as ctx:
            build(raw)
        self.assertIn(needle, str(ctx.exception))

    def test_write_key_needs_policy(self) -> None:
        """A write key without ``policy_id`` is refused."""
        raw = self.raw_inventory()
        del raw["key"][0]["policy_id"]
        self._refused(raw, "policy_id")

    def test_consumer_key_must_exist(self) -> None:
        """A consumer naming an unknown key is refused."""
        self._refused(self.raw_inventory(key="nope"), "not a [[key]] row")

    def test_unique_names(self) -> None:
        """Duplicate key names and duplicate consumer labels are refused."""
        raw = self.raw_inventory()
        raw["key"].append(copy.deepcopy(raw["key"][0]))
        self._refused(raw, "duplicate key name")
        raw = self.raw_inventory()
        raw["consumer"].append(copy.deepcopy(raw["consumer"][0]))
        self._refused(raw, "duplicate consumer label")

    def test_one_key_per_repo_and_direction(self) -> None:
        """Two active keys for one repo and direction are refused unless one is retiring."""
        raw = self.raw_inventory()
        extra = copy.deepcopy(raw["key"][0])
        extra["name"] = "github-demo-write-2"
        raw["key"].append(extra)
        self._refused(raw, "both cover")
        extra["status"] = "retiring"
        build(raw)

    def test_wrong_repo_remote(self) -> None:
        """A consumer remote outside its key's repo is refused."""
        self._refused(self.raw_inventory(remote="git@github.com:glensk/other.git"), "opens")

    def test_forbidden_refspec_in_row(self) -> None:
        """A consumer row with a forcing refspec is refused."""
        self._refused(self.raw_inventory(refspec="+HEAD:refs/heads/main"), "forces")

    def test_relative_git_and_unknown_field(self) -> None:
        """A relative git path and an unknown field are refused."""
        self._refused(self.raw_inventory(git="git"), "absolute")
        self._refused(self.raw_inventory(colour="red"), "unknown field")

    def test_active_needs_full_helper_sha(self) -> None:
        """An active consumer needs a full helper sha; a legacy one does not."""
        self._refused(self.raw_inventory(helper_sha=""), "helper_sha")
        build(self.raw_inventory(helper_sha="", status="legacy"))

    def test_planned_rows_need_no_material(self) -> None:
        """Planned rows build without fingerprint, remote key id or policy id."""
        raw = self.raw_inventory(status="planned", helper_sha="")
        raw["key"][0].update(status="planned", fingerprint="")
        del raw["key"][0]["remote_key_id"]
        del raw["key"][0]["policy_id"]
        inv = build(raw)
        self.assertEqual(inv.keys["github-demo-write"].status, "planned")


class EnvTest(Sandbox):
    """The ssh command line and git environments built for consumers."""

    def test_ssh_command_ignores_user_config_and_agent(self) -> None:
        """The ssh command ignores ~/.ssh/config and the agent and pins the key and hosts."""
        inv = self.inventory()
        argv = shlex.split(ssh_command("/usr/bin/ssh", inv.keys["github-demo-write"]))
        self.assertEqual(argv[:3], ["/usr/bin/ssh", "-F", "/dev/null"])
        for opt in (
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            f"UserKnownHostsFile={self.known_hosts}",
            "ControlMaster=no",
        ):
            self.assertIn(opt, argv)
        self.assertIn(str(self.key_path), argv)
        self.assertFalse(any(a.startswith("ProxyCommand") for a in argv))

    def test_proxy_command(self) -> None:
        """A consumer proxy command is passed as one ``ProxyCommand`` option."""
        inv = self.inventory()
        cmd = ssh_command("/usr/bin/ssh", inv.keys["github-demo-write"], "/x/socks.sh epfl %h %p")
        self.assertIn("ProxyCommand=/x/socks.sh epfl %h %p", shlex.split(cmd))

    def test_git_env_drops_agent_and_appends_config(self) -> None:
        """git_env drops agent/ssh overrides and appends to existing GIT_CONFIG pairs."""
        inv = self.inventory()
        base = {
            "SSH_AUTH_SOCK": "/a",
            "GIT_SSH": "/b",
            "GIT_SSH_VARIANT": "ssh",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": "x",
            "PATH": "/usr/bin",
        }
        env = git_env(inv, inv.consumers["demo-push"], base)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("GIT_SSH", env)
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "user.name")
        self.assertEqual(env["GIT_CONFIG_KEY_1"], "push.recurseSubmodules")
        self.assertEqual(env["GIT_CONFIG_VALUE_1"], "check")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertIn("-F /dev/null", env["GIT_SSH_COMMAND"])
        with self.assertRaises(RefusedError):
            append_git_config({"GIT_CONFIG_COUNT": "x"}, [("a.b", "c")])

    def test_local_env_has_no_key(self) -> None:
        """The key-less local env carries no agent or ssh command."""
        env = local_env({"SSH_AUTH_SOCK": "/a", "GIT_SSH_COMMAND": "ssh -i k", "HOME": "/h"})
        self.assertEqual(env["AI_PUSH_LOCAL_ONLY"], "1")
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("GIT_SSH_COMMAND", env)


class PushTest(Sandbox):
    """``deploykey.push`` against the fake ssh and bare remote."""

    def test_push_success_writes_evidence(self) -> None:
        """A push updates the remote and records sha and success in the evidence."""
        sha = self.commit(self.checkout)
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        self.assertEqual(self.remote_main(), sha)
        record = self.evidence()
        self.assertEqual(record["last_attempt_rc"], 0)
        self.assertEqual(record["pushed_sha"], sha)
        self.assertEqual(record["remote_oid"], sha)
        self.assertIsNotNone(record["last_success_at"])
        self.assertEqual(record["helper_sha"], "dev")
        calls = self.ssh_calls()
        self.assertEqual(len(calls), 1)
        self.assertIn("IdentityAgent=none", calls[0])
        self.assertIn("git-receive-pack 'glensk/demo.git'", calls[0][-1])

    def _assert_refused_offline(self) -> None:
        self.commit(self.checkout)
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_REFUSED, outcome.message)
        self.assertEqual(self.ssh_calls(), [])
        self.assertEqual(self.evidence()["last_attempt_rc"], EXIT_REFUSED)

    def test_missing_key_refused(self) -> None:
        """A missing key file refuses the push before any ssh call."""
        self.key_path.rename(self.root / "moved")
        self._assert_refused_offline()

    def test_key_mode_0644_refused(self) -> None:
        """A world-readable key file refuses the push before any ssh call."""
        self.key_path.chmod(0o644)
        self._assert_refused_offline()

    def test_missing_pinned_hosts_refused(self) -> None:
        """A missing known_hosts file refuses the push before any ssh call."""
        self.known_hosts.unlink()
        self._assert_refused_offline()

    def test_checkout_remote_must_match(self) -> None:
        """A checkout without a remote at the inventory URL is refused."""
        run([GIT, "-C", self.checkout, "remote", "set-url", "origin", "git@github.com:glensk/x"])
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertIn("no remote", outcome.message)

    def test_mirror_config_refused(self) -> None:
        """A remote configured as mirror is refused."""
        run([GIT, "-C", self.checkout, "config", "remote.origin.mirror", "true"])
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertIn("mirror", outcome.message)

    def test_several_push_urls_refused(self) -> None:
        """A remote with several push URLs is refused."""
        run([GIT, "-C", self.checkout, "remote", "set-url", "--add", "--push", "origin", self.URL])
        run([GIT, "-C", self.checkout, "remote", "set-url", "--add", "--push", "origin", self.URL])
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertIn("URLs", outcome.message)

    def test_push_url_vs_fetch_url(self) -> None:
        """Push matches the push URL; pull refuses a fetch URL that differs."""
        run([GIT, "-C", self.checkout, "remote", "set-url", "origin", "git@github.com:glensk/x"])
        run([GIT, "-C", self.checkout, "remote", "set-url", "--push", "origin", self.URL])
        sha = self.commit(self.checkout)
        self.assertEqual(deploykey.push(self.inventory(), "demo-push").rc, EXIT_OK)
        self.assertEqual(self.remote_main(), sha)
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertIn("fetches", outcome.message)

    def test_non_fast_forward_keeps_commit_no_rebase(self) -> None:
        """A non-fast-forward push fails without rebasing or touching either side."""
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        remote_sha = self.commit(other, "c.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        local_sha = self.commit(self.checkout)
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertIn("non-fast-forward", outcome.message)
        self.assertEqual(self.remote_main(), remote_sha)
        self.assertEqual(run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip(), local_sha)
        record = self.evidence()
        self.assertEqual(record["last_attempt_rc"], EXIT_FAILED)
        self.assertIsNone(record["last_success_at"])

    def test_failure_keeps_last_success(self) -> None:
        """A rejected push keeps the previous success and records the failure message."""
        self.commit(self.checkout)
        self.assertEqual(deploykey.push(self.inventory(), "demo-push").rc, EXIT_OK)
        first = self.evidence()
        (self.root / "deny").write_text("")
        self.commit(self.checkout, "d.txt")
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        record = self.evidence()
        self.assertEqual(record["last_success_at"], first["last_success_at"])
        self.assertEqual(record["pushed_sha"], first["pushed_sha"])
        self.assertIn("Permission denied", record["last_attempt_message"])

    def test_submodule_recurse_is_check(self) -> None:
        """Pushes run with submodule recursion ``check`` and no tag following."""
        self.commit(self.checkout)
        env_seen = git_env(self.inventory(), self.inventory().consumers["demo-push"], {})
        pairs = {
            env_seen[f"GIT_CONFIG_KEY_{i}"]: env_seen[f"GIT_CONFIG_VALUE_{i}"]
            for i in range(int(env_seen["GIT_CONFIG_COUNT"]))
        }
        self.assertEqual(pairs["push.recurseSubmodules"], "check")
        self.assertEqual(pairs["push.followTags"], "false")

    def test_legacy_and_planned_refused(self) -> None:
        """Legacy and planned consumers cannot push."""
        for status in ("legacy", "planned"):
            with self.subTest(status=status):
                inv = self.inventory(self.raw_inventory(status=status, helper_sha=""))
                outcome = deploykey.push(inv, "demo-push")
                self.assertEqual(outcome.rc, EXIT_REFUSED)
                self.assertIn(status, outcome.message)

    def test_read_key_cannot_push(self) -> None:
        """A consumer on a read key cannot push."""
        outcome = deploykey.push(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertIn("needs a write key", outcome.message)

    def test_worktree_must_share_repository(self) -> None:
        """A linked worktree of the checkout pushes; an unrelated repo is refused."""
        wt = self.root / "wt"
        run([GIT, "-C", self.checkout, "worktree", "add", "-q", "-b", "side", wt])
        sha = self.commit(wt, "w.txt")
        outcome = deploykey.push(self.inventory(), "demo-push", worktree=str(wt))
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        self.assertEqual(self.remote_main(), sha)
        stranger = self.root / "stranger"
        run([GIT, "init", "-q", stranger])
        outcome = deploykey.push(self.inventory(), "demo-push", worktree=str(stranger))
        self.assertEqual(outcome.rc, EXIT_REFUSED)


class LockTest(Sandbox):
    """The per-repository transaction lock."""

    def test_contention_returns_failure_and_pushes_nothing(self) -> None:
        """A held lock fails the push after the timeout without any ssh call."""
        self.commit(self.checkout)
        inv = self.inventory()
        common = git_common_dir(inv.consumers["demo-push"])
        before = self.remote_main()
        with repo_lock(common):
            outcome = deploykey.push(inv, "demo-push", lock_timeout=0.3)
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertIn("held by another transaction", outcome.message)
        self.assertEqual(self.remote_main(), before)
        self.assertEqual(self.ssh_calls(), [])

    def test_lock_serialises_threads(self) -> None:
        """A second holder waits until the first releases the lock."""
        common = git_common_dir(self.inventory().consumers["demo-push"])
        order: list[str] = []
        release = threading.Event()

        def holder() -> None:
            with repo_lock(common):
                order.append("a-in")
                release.wait(5)
                order.append("a-out")

        thread = threading.Thread(target=holder)
        thread.start()
        while not order:
            pass
        timer = threading.Timer(0.3, release.set)
        timer.start()
        with repo_lock(common, timeout=5):
            order.append("b-in")
        thread.join()
        self.assertEqual(order, ["a-in", "a-out", "b-in"])


class PullTest(Sandbox):
    """``deploykey.pull`` with the read key."""

    def rev(self, ref: str) -> str:
        """The sha *ref* names in the checkout."""
        return run([GIT, "-C", self.checkout, "rev-parse", ref]).strip()

    def test_pull_fast_forwards(self) -> None:
        """Pull fast-forwards the checkout using the read key."""
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        sha = self.commit(other, "n.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        self.assertEqual(run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip(), sha)
        self.assertEqual(self.evidence("demo-pull")["remote_oid"], sha)
        self.assertIn(str(self.read_key_path), self.ssh_calls()[0])

    def test_pull_survives_concurrent_foreign_fetch(self) -> None:
        """A foreign ``git fetch`` looping in the clone never breaks pull (tp#925).

        An editor's git plugin fetches in the same clone without deploykey's lock; with
        ``git pull`` the two fetches interleaved on ``FETCH_HEAD`` ("Cannot fast-forward
        to multiple branches") and on ``refs/remotes/origin/*``.
        """
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        inv = self.inventory()
        stop = threading.Event()
        fetch_env = dict(os.environ, GIT_SSH_COMMAND=str(self.ssh))

        def foreign_fetch() -> None:
            while not stop.is_set():
                subprocess.run(
                    [GIT, "-C", str(self.checkout), "fetch", "-q", "origin"],
                    capture_output=True,
                    check=False,
                    env=fetch_env,
                )

        thread = threading.Thread(target=foreign_fetch, daemon=True)
        thread.start()
        try:
            for i in range(30):
                sha = self.commit(other, "n.txt", f"{i}\n")
                run([GIT, "-C", other, "push", "-q", "origin", "main"])
                outcome = deploykey.pull(inv, "demo-pull")
                with self.subTest(iteration=i):
                    self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
                    self.assertEqual(
                        run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip(), sha
                    )
        finally:
            stop.set()
            thread.join()

    def test_pull_refuses_non_fast_forward(self) -> None:
        """A diverged checkout fails the merge (exit 4) and keeps its local commit."""
        local = self.commit(self.checkout, "local.txt")
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        self.commit(other, "n.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertIn("pull failed", outcome.message)
        self.assertEqual(run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip(), local)

    def test_pull_fetch_failure_message(self) -> None:
        """A rejected key fails the fetch step (exit 4) with a ``fetch failed`` message."""
        (self.root / "deny").write_text("")
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertIn("fetch failed (git rc=", outcome.message)

    def test_pull_touches_no_shared_fetch_state(self) -> None:
        """No FETCH_HEAD; the tracking ref moves by compare-and-swap, so status is not ahead."""
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        sha = self.commit(other, "n.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        (self.checkout / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
        self.assertEqual(deploykey.pull(self.inventory(), "demo-pull").rc, EXIT_OK)
        self.assertFalse((self.checkout / ".git" / "FETCH_HEAD").exists())
        self.assertEqual(self.rev(ops.pull_ref("main")), sha)
        self.assertEqual(self.rev("HEAD"), sha)
        self.assertEqual(self.rev("refs/remotes/origin/main"), sha)
        status = run([GIT, "-C", self.checkout, "status", "-sb"]).splitlines()[0]
        self.assertNotIn("ahead", status)
        self.assertIn(
            "deploy-git pull",
            run([GIT, "-C", self.checkout, "reflog", "-1", "refs/remotes/origin/main"]),
        )

    def test_pull_tracking_ref_cas_lost_is_ignored(self) -> None:
        """A lost compare-and-swap leaves the moved tracking ref alone and raises nothing."""
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        sha = self.commit(other, "n.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        consumer = self.inventory().consumer("demo-pull")
        seed = run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip()
        moved = run(
            [GIT, "-C", self.checkout, "commit-tree", "-m", "x", f"{seed}^{{tree}}"]
        ).strip()
        run([GIT, "-C", self.checkout, "update-ref", "refs/remotes/origin/main", moved])
        ops._advance_tracking_ref(  # pylint: disable=protected-access
            consumer, "refs/remotes/origin/main", sha, seed
        )
        self.assertEqual(self.rev("refs/remotes/origin/main"), moved)

    def test_pull_does_not_create_missing_tracking_ref(self) -> None:
        """A tracking ref that did not exist before the pull is not created."""
        run([GIT, "-C", self.checkout, "update-ref", "-d", "refs/remotes/origin/main"])
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        self.commit(other, "n.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        self.assertEqual(deploykey.pull(self.inventory(), "demo-pull").rc, EXIT_OK)
        proc = subprocess.run(
            [GIT, "-C", str(self.checkout), "rev-parse", "--verify", "--quiet",
             "refs/remotes/origin/main"],
            capture_output=True, check=False,
        )  # fmt: skip
        self.assertNotEqual(proc.returncode, 0)

    def test_pull_refuses_other_branch(self) -> None:
        """Pull refuses while another branch is checked out."""
        run([GIT, "-C", self.checkout, "checkout", "-q", "-b", "feature"])
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_REFUSED)

    def test_write_row_cannot_pull(self) -> None:
        """A consumer on a write key cannot pull."""
        self.assertEqual(deploykey.pull(self.inventory(), "demo-push").rc, EXIT_REFUSED)


def make_committer(root: Path, rc: int = 0) -> Path:
    """Write an executable script into *root* that commits one file and exits *rc*."""
    script = root / "committer"
    script.write_text(
        "#!/bin/sh\n"
        f'env > "{root}/committer.env"\n'
        "echo x >> c.txt\n"
        f'"{GIT}" add c.txt && "{GIT}" commit -q -m c\n'
        f"exit {rc}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


class RunAndPublishTest(Sandbox):
    """``deploykey.run`` and ``deploykey.publish``: commit locally, then push."""

    def test_run_commits_without_key_then_pushes(self) -> None:
        """The command runs without key or agent, then its commit is pushed."""
        script = make_committer(self.root)
        outcome = deploykey.run(self.inventory(), "demo-push", [str(script)])
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        env = (self.root / "committer.env").read_text()
        self.assertIn("AI_PUSH_LOCAL_ONLY=1", env)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("GIT_SSH_COMMAND", env)
        self.assertEqual(
            self.remote_main(), run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip()
        )

    def test_run_failure_pushes_nothing(self) -> None:
        """A failing command pushes nothing and makes no ssh call."""
        before = self.remote_main()
        outcome = deploykey.run(
            self.inventory(), "demo-push", [str(make_committer(self.root, rc=1))]
        )
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(self.remote_main(), before)
        self.assertEqual(self.ssh_calls(), [])

    def test_argv0_resolution(self) -> None:
        """argv[0] must resolve on the fixed PATH; relative and unknown commands are refused."""
        inv = self.inventory()
        for argv in (["no-such-command-xyz"], ["./committer"], ["rel/committer"], []):
            with self.subTest(argv=argv):
                self.assertEqual(deploykey.run(inv, "demo-push", argv).rc, EXIT_REFUSED)
        self.assertEqual(ops.resolve_argv0("sh", "/bin:/usr/bin"), "/bin/sh")
        with self.assertRaises(RefusedError):
            ops.resolve_argv0("sh", str(self.root))

    def hung_command(self, *, honour_term: bool) -> tuple[list[str], Path, Path]:
        """A command that holds a lock file and sleeps past any timeout.

        With *honour_term* it removes the lock and exits on SIGTERM (as git does);
        without, it ignores SIGTERM. Returns (argv, lock file, pid file).
        """
        lock, pidfile, ready = self.root / "index.lock", self.root / "child.pid", "child.ready"
        handler = (
            "def bye(*_):\n    os.unlink(LOCK)\n    sys.exit(143)\n"
            if honour_term
            else "def bye(*_):\n    pass\n"
        )
        script = self.root / "hung.py"
        script.write_text(
            "import os, signal, sys, time\n"
            f"LOCK = {str(lock)!r}\n" + handler + "signal.signal(signal.SIGTERM, bye)\n"
            "open(LOCK, 'w').close()\n"
            f"open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
            f"open({str(self.root / ready)!r}, 'w').close()\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        return [sys.executable, str(script)], lock, pidfile

    def test_run_timeout_lets_the_command_remove_its_lock(self) -> None:
        """A timed-out command gets SIGTERM first, so git-style lock cleanup runs."""
        argv, lock, _ = self.hung_command(honour_term=True)
        before = self.remote_main()
        outcome = deploykey.run(self.inventory(), "demo-push", argv, command_timeout=2.0)
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(outcome.message, f"{argv[0]} timed out; nothing pushed")
        self.assertTrue((self.root / "child.ready").exists(), "child never started")
        self.assertFalse(lock.exists(), "SIGTERM handler did not run: lock left behind")
        self.assertEqual(self.remote_main(), before)
        self.assertEqual(self.ssh_calls(), [])

    def test_run_timeout_kills_a_command_that_ignores_sigterm(self) -> None:
        """A command that ignores SIGTERM is SIGKILLed once the grace period is over."""
        argv, lock, pidfile = self.hung_command(honour_term=False)
        started = time.monotonic()
        with mock.patch("deploykey._common.TERM_GRACE_S", 0.3):
            outcome = deploykey.run(self.inventory(), "demo-push", argv, command_timeout=2.0)
        self.assertLess(time.monotonic() - started, 8)  # < timeout + default grace
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(outcome.message, f"{argv[0]} timed out; nothing pushed")
        self.assertTrue(lock.exists())
        pid = int(pidfile.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_argv0_ignores_caller_path(self) -> None:
        """A command found only on the caller's PATH is refused."""
        shim = self.root / "bin"
        shim.mkdir()
        (shim / "evil-tool").write_text("#!/bin/sh\nexit 0\n")
        (shim / "evil-tool").chmod(0o755)
        os.environ["PATH"] = f"{shim}:{os.environ.get('PATH', '')}"
        outcome = deploykey.run(self.inventory(), "demo-push", ["evil-tool"])
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertIn("fixed PATH", outcome.message)

    def test_publish_library(self) -> None:
        """publish calls the commit callback with the checkout and records success."""
        seen: list[Path] = []

        def commit(checkout: Path) -> None:
            seen.append(checkout)
            self.commit(checkout, "p.txt")

        outcome = deploykey.publish(self.inventory(), "demo-push", commit=commit)
        self.assertTrue(outcome.ok, outcome.message)
        self.assertEqual(seen, [self.checkout])
        self.assertEqual(self.evidence()["last_attempt_rc"], 0)

    def test_publish_refusal_raises(self) -> None:
        """publish raises DeployKeyError on a refusal."""
        self.key_path.chmod(0o644)
        with self.assertRaises(DeployKeyError):
            deploykey.publish(self.inventory(), "demo-push", commit=lambda _p: None)


class CliTest(Sandbox):
    """The ``deploy-git`` command-line interface."""

    def test_push_via_cli(self) -> None:
        """``deploy-git push`` publishes the checkout's commit."""
        self.write_runtime()
        sha = self.commit(self.checkout)
        self.assertEqual(cli_git.main(["push", "demo-push"]), EXIT_OK)
        self.assertEqual(self.remote_main(), sha)

    def test_git_options_and_refs_refused(self) -> None:
        """Extra git options and refspecs on the CLI are refused before any ssh call."""
        self.write_runtime()
        self.commit(self.checkout)
        for extra in (
            ["--force"],
            ["--force-with-lease"],
            ["--mirror"],
            ["--all"],
            ["--tags"],
            ["--delete"],
            ["-o", "ci.skip"],
            ["HEAD:refs/heads/x"],
        ):
            with self.subTest(extra=extra):
                self.assertEqual(cli_git.main(["push", "demo-push", *extra]), EXIT_REFUSED)
        self.assertEqual(self.ssh_calls(), [])

    def test_unknown_consumer_and_bad_runtime(self) -> None:
        """An unknown consumer and an unreadable runtime JSON are refused."""
        self.write_runtime()
        self.assertEqual(cli_git.main(["push", "nope"]), EXIT_REFUSED)
        Path(os.environ["DEPLOYKEY_CONFIG"]).write_text("{not json", encoding="utf-8")
        self.assertEqual(cli_git.main(["push", "demo-push"]), EXIT_REFUSED)

    def test_run_via_cli(self) -> None:
        """``deploy-git run -- <cmd>`` runs the command and pushes."""
        self.write_runtime()
        script = make_committer(self.root)
        self.assertEqual(cli_git.main(["run", "demo-push", "--", str(script)]), EXIT_OK)

    def test_usage(self) -> None:
        """No arguments is a usage error (exit 2)."""
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli_git.main([]), 2)

    def test_help_and_version_subprocess(self) -> None:
        """``-h`` documents the exit codes and ``-V`` prints ``dev`` from a source tree."""
        top = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ, PYTHONPATH=top)
        out = subprocess.run(
            [sys.executable, "-m", "deploykey.cli_git", "-h"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(out.returncode, 0)
        self.assertIn("exit codes", out.stdout)
        out = subprocess.run(
            [sys.executable, "-m", "deploykey.cli_git", "-V"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(out.stdout.strip(), "dev")


RESET = "Connection reset by 20.250.119.67 port 22"


class ClassifyTest(unittest.TestCase):
    """``ops.is_transient``: the allow-list, and everything that must defeat it."""

    def test_measured_transport_diagnostics_are_transient(self) -> None:
        """Every ssh diagnostic observed for a blip is retried."""
        for line in (
            RESET,
            "kex_exchange_identification: Connection closed by remote host",
            "ssh: connect to host github.com port 22: Operation timed out",
            "ssh: connect to host github.com port 22: Connection refused",
            "ssh: Could not resolve hostname github.com: nodename nor servname provided",
            "ssh: connect to host github.com port 22: Network is unreachable",
            "fatal: the remote end hung up unexpectedly",
        ):
            with self.subTest(line=line):
                self.assertTrue(ops.is_transient(f"{line}\nfatal: Could not read from remote.\n"))

    def test_terminal_diagnostics_are_never_transient(self) -> None:
        """A fault another attempt cannot fix is never retried."""
        for line in (
            "git@github.com: Permission denied (publickey).",
            "Host key verification failed.",
            "@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@@",
            "Unable to negotiate with 1.2.3.4: no matching host key type found",
            "ERROR: Repository not found.",
            "fatal: couldn't find remote ref refs/heads/nope",
            "! [remote rejected] main -> main (pre-receive hook declined)",
        ):
            with self.subTest(line=line):
                self.assertFalse(ops.is_transient(f"{line}\nfatal: Could not read from remote.\n"))

    def test_git_envelope_alone_is_not_transient(self) -> None:
        """The envelope every transport failure carries must decide nothing by itself."""
        self.assertFalse(
            ops.is_transient(
                "fatal: Could not read from remote repository.\n\n"
                "Please make sure you have the correct access rights\n"
                "and the repository exists.\n"
            )
        )

    def test_terminal_wins_when_both_markers_appear(self) -> None:
        """A refused key that also reports a reset is terminal, not transient."""
        self.assertFalse(ops.is_transient(f"{RESET}\ngit@github.com: Permission denied.\n"))

    def test_non_fast_forward_is_never_transient(self) -> None:
        """A rejected ref update needs a new commit, not another attempt."""
        self.assertFalse(ops.is_transient("! [rejected] main -> main (non-fast-forward)\n"))

    def test_remote_output_cannot_request_a_retry(self) -> None:
        """``remote:`` text is server-controlled and is dropped before classifying."""
        self.assertFalse(ops.is_transient(f"remote: {RESET}\nfatal: push declined\n"))

    def test_unknown_output_is_not_transient(self) -> None:
        """Anything unrecognised keeps today's fail-on-the-first-try behaviour."""
        self.assertFalse(ops.is_transient("fatal: something nobody has ever seen\n"))

    def test_diagnostic_is_classified_beyond_the_tail_window(self) -> None:
        """Classification reads the whole stderr, not ``_tail``'s last six lines."""
        stderr = RESET + "\n" + "\n".join(f"noise {i}" for i in range(20))
        self.assertNotIn(RESET, ops._tail(stderr))  # pylint: disable=protected-access
        self.assertTrue(ops.is_transient(stderr))


class RetryTest(Sandbox):
    """The bounded fetch retry: it absorbs a blip and nothing else."""

    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch("deploykey.ops.time.sleep")
        self.sleep = patch.start()
        self.addCleanup(patch.stop)

    def pull_inventory(self, **settings: Any) -> Inventory:
        """An inventory whose settings are overridden."""
        raw = self.raw_inventory()
        raw["settings"].update(settings)
        return self.inventory(raw)

    def advance_remote(self) -> str:
        """Put one new commit on the bare remote; returns its sha."""
        other = self.root / "other"
        run([GIT, "clone", "-q", str(self.bare), other])
        sha = self.commit(other, "n.txt")
        run([GIT, "-C", other, "push", "-q", "origin", "main"])
        return sha

    def test_transient_fetch_is_retried_and_then_succeeds(self) -> None:
        """One reset connection no longer fails the job: the second attempt pulls."""
        sha = self.advance_remote()
        self.fail_ssh(1, RESET)
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        self.assertEqual(run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip(), sha)
        self.assertEqual(len(self.ssh_calls()), 2)
        self.assertIn("after 1 transient retry", outcome.message)
        self.assertIn(RESET, outcome.message)
        record = self.evidence("demo-pull")
        self.assertEqual(record["last_attempt_rc"], 0)
        self.assertIn("after 1 transient retry", record["last_attempt_message"])
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [2.0])

    def test_two_transient_failures_still_succeed(self) -> None:
        """The third attempt is still made, after the 2 s and 6 s waits."""
        sha = self.advance_remote()
        self.fail_ssh(2, RESET)
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        self.assertEqual(run([GIT, "-C", self.checkout, "rev-parse", "HEAD"]).strip(), sha)
        self.assertEqual(len(self.ssh_calls()), 3)
        self.assertIn("after 2 transient retries", outcome.message)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [2.0, 6.0])

    def test_transient_exhaustion_fails_after_three_attempts(self) -> None:
        """A real outage is still exit 4 — the retry only delays the same verdict."""
        self.fail_ssh(99, RESET)
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertIn("after 3 attempts", outcome.message)
        self.assertEqual(len(self.ssh_calls()), 3)
        self.assertEqual(self.evidence("demo-pull")["last_attempt_rc"], EXIT_FAILED)

    def test_refused_key_is_not_retried(self) -> None:
        """A terminal failure still costs exactly one attempt."""
        (self.root / "deny").write_text("")
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(len(self.ssh_calls()), 1)
        self.assertNotIn("attempts", outcome.message)
        self.sleep.assert_not_called()

    def test_unknown_failure_is_not_retried(self) -> None:
        """An unrecognised diagnostic keeps the single-attempt behaviour."""
        self.fail_ssh(99, "fatal: a diagnostic nobody has ever seen")
        outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(len(self.ssh_calls()), 1)
        self.sleep.assert_not_called()

    def test_no_retry_without_a_per_attempt_timeout(self) -> None:
        """``net_timeout_s = 0`` cannot bound an attempt, so there is exactly one."""
        self.fail_ssh(99, RESET)
        outcome = deploykey.pull(self.pull_inventory(net_timeout_s=0), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(len(self.ssh_calls()), 1)
        self.sleep.assert_not_called()

    def test_deadline_stops_further_attempts(self) -> None:
        """The wall-clock ceiling wins even while attempts remain."""
        self.fail_ssh(99, RESET)
        with mock.patch.object(ops, "_RETRY_DEADLINE_S", 1.0):
            outcome = deploykey.pull(self.inventory(), "demo-pull")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(len(self.ssh_calls()), 1)
        self.sleep.assert_not_called()

    def test_a_timed_out_attempt_is_retried(self) -> None:
        """A hung connection is transient; the retry's success is what counts."""
        ok = subprocess.CompletedProcess(["git"], 0, "", "")
        calls = [subprocess.TimeoutExpired("git", 60), subprocess.TimeoutExpired("git", 60), ok]
        with mock.patch.object(ops, "git", side_effect=calls) as fake:
            net = ops._network(  # pylint: disable=protected-access
                self.inventory(), self.inventory().consumer("demo-pull"), "fetch", env={}
            )
        self.assertEqual(fake.call_count, 3)
        self.assertEqual(net.attempts, 3)
        self.assertIs(net.proc, ok)
        self.assertEqual(net.first_error, "timed out")

    def test_push_is_never_retried(self) -> None:
        """The write path keeps the schedule as its only retry (local pre-push hooks)."""
        self.fail_ssh(99, RESET)
        self.commit(self.checkout)
        outcome = deploykey.push(self.inventory(), "demo-push")
        self.assertEqual(outcome.rc, EXIT_FAILED)
        self.assertEqual(len(self.ssh_calls()), 1)
        self.sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
