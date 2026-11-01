"""Regression tests of the known_hosts quoting, lock, fsync and remote-env fixes.

stdlib ``unittest`` only — this module also runs under macOS's /usr/bin/python3 (3.9).
"""

from __future__ import annotations

import errno
import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import deploykey
from deploykey._common import (
    EXIT_OK,
    EXIT_REFUSED,
    DeployKeyError,
    RefusedError,
    write_json_atomic,
)
from deploykey.gitenv import git_common_dir, ssh_command
from deploykey.lock import LOCK_NAME, repo_lock

from .support import Sandbox, run

SSH = shutil.which("ssh")


def ssh_option_values(option: str) -> list[str]:
    """The values ssh takes from ``-o Keyword=args`` (OpenSSH ``argv_split`` + ``%%``).

    Quotes group words, a backslash escapes a quote, backslash or (unquoted) space,
    unquoted whitespace separates values; then ``%%`` is ``%`` and any other ``%x``
    is a token ssh would substitute (here: an AssertionError).
    """
    _, _, rest = option.partition("=")
    words: list[str] = []
    word, quote, started, i = "", "", False, 0
    while i < len(rest):
        c = rest[i]
        if c == "\\" and i + 1 < len(rest) and rest[i + 1] in "'\"\\" + ("" if quote else " "):
            word, started, i = word + rest[i + 1], True, i + 2
            continue
        if quote:
            if c == quote:
                quote = ""
            else:
                word += c
        elif c in "'\"":
            quote, started = c, True
        elif c in " \t":
            if started:
                words.append(word)
            word, started = "", False
        else:
            word, started = word + c, True
        i += 1
    assert not quote, f"unterminated quote in {option!r}"
    if started:
        words.append(word)
    out = []
    for value in words:
        parts = value.split("%%")
        for part in parts:
            assert "%" not in part, f"ssh would expand a % token in {value!r}"
        out.append("%".join(parts))
    return out


class KnownHostsQuotingTest(Sandbox):
    """``UserKnownHostsFile`` survives ssh's word splitting and ``%`` expansion."""

    def odd_command(self, known_hosts: str, ssh: str = "/usr/bin/ssh") -> list[str]:
        """The ssh argv for the write key with *known_hosts* as its pinned host file."""
        raw = self.raw_inventory()
        raw["key"][0]["known_hosts"] = known_hosts
        return shlex.split(ssh_command(ssh, self.inventory(raw).keys["github-demo-write"]))

    def test_known_hosts_path_survives_ssh_option_parsing(self) -> None:
        """A known_hosts path with a space and ``%`` reaches ssh as that one file.

        Fails on the unquoted ``UserKnownHostsFile=<path>``: ssh splits it into two
        files and reads ``%h`` as the host-name token.
        """
        odd = str(self.root / "my keys" / "known_hosts_%h_100%")
        argv = self.odd_command(odd)
        options = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
        known = [o for o in options if o.startswith("UserKnownHostsFile=")]
        self.assertEqual(len(known), 1)
        self.assertEqual(ssh_option_values(known[0]), [odd])

    @unittest.skipUnless(SSH, "no ssh on PATH")
    def test_known_hosts_path_through_real_ssh_config_parser(self) -> None:
        """``ssh -G`` (parse only, no connection) reports the odd path unchanged."""
        odd = str(self.root / "my keys" / "known_hosts_%h_100%")
        argv = self.odd_command(odd, str(SSH))
        out = run([*argv, "-G", "example.org"], stdin=subprocess.DEVNULL)
        lines = [ln for ln in out.splitlines() if ln.startswith("userknownhostsfile ")]
        self.assertEqual(lines, [f"userknownhostsfile {odd}"])

    def test_known_hosts_path_without_ssh_spelling_is_refused(self) -> None:
        """A ``"``, backslash or control character in the path is refused up front."""
        for bad in ('/k/a"b', "/k/a\\b", "/k/a\nb"):
            with self.subTest(bad=bad), self.assertRaises(RefusedError):
                self.odd_command(bad)


class LockSymlinkTest(Sandbox):
    """The repository lock never follows a symlink planted at its path."""

    def test_symlinked_lock_path_is_refused_and_target_untouched(self) -> None:
        """Fails on the old open without O_NOFOLLOW: it locked and truncated the target."""
        common = git_common_dir(self.inventory().consumers["demo-push"])
        target = self.root / "victim.txt"
        target.write_text("keep me\n")
        (common / LOCK_NAME).symlink_to(target)
        with self.assertRaises(RefusedError), repo_lock(common, timeout=0.2):
            pass
        self.assertEqual(target.read_text(), "keep me\n")

    def test_symlinked_lock_refuses_the_push(self) -> None:
        """deploy-git push exits 3 (refused) with no ssh call when the lock is a symlink."""
        self.commit(self.checkout)
        inv = self.inventory()
        common = git_common_dir(inv.consumers["demo-push"])
        (common / LOCK_NAME).symlink_to(self.root / "absent" / "elsewhere.lock")
        outcome = deploykey.push(inv, "demo-push", lock_timeout=0.2)
        self.assertEqual(outcome.rc, EXIT_REFUSED)
        self.assertEqual(self.ssh_calls(), [])


class FsyncTest(unittest.TestCase):
    """``write_json_atomic`` syncs the file before the rename and the directory after."""

    def setUp(self) -> None:
        # pylint: disable-next=consider-using-with  # cleaned up in tearDown
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "sub" / "evidence.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fsync_file_then_replace_then_directory(self) -> None:
        """Fails on the old code, which never called os.fsync."""
        calls: list[str] = []
        real_replace = os.replace

        def fake_fsync(fd: int) -> None:
            calls.append("fsync-dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync-file")

        def recording_replace(src: str, dst: object) -> None:
            calls.append("replace")
            real_replace(src, str(dst))

        with mock.patch("os.fsync", fake_fsync), mock.patch("os.replace", recording_replace):
            write_json_atomic(self.path, {"a": 1})
        self.assertEqual(calls, ["fsync-file", "replace", "fsync-dir"])
        self.assertEqual(json.loads(self.path.read_text()), {"a": 1})

    def test_directory_fsync_refusal_is_tolerated(self) -> None:
        """A platform that refuses a directory fsync still gets the file written."""

        def fake_fsync(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "directory fsync not supported")

        with mock.patch("os.fsync", fake_fsync):
            write_json_atomic(self.path, {"b": 2})
        self.assertEqual(json.loads(self.path.read_text()), {"b": 2})

    def test_file_fsync_failure_propagates_and_keeps_the_old_file(self) -> None:
        """A failed file fsync (disk error) raises and never renames over the old file."""
        write_json_atomic(self.path, {"old": True})

        def fake_fsync(fd: int) -> None:
            raise OSError(errno.EIO, "I/O error")

        with mock.patch("os.fsync", fake_fsync), self.assertRaises(OSError):
            write_json_atomic(self.path, {"new": True})
        self.assertEqual(json.loads(self.path.read_text()), {"old": True})
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["evidence.json"])


class RemoteEnvTest(Sandbox):
    """``resolve_remote`` sees the same git config as the push it checks for."""

    OTHER = "git@github.com:glensk/other.git"

    def injected(self, env: dict[str, str]) -> dict[str, str]:
        """*env* plus a ``GIT_CONFIG_*`` pair pointing origin's push URL elsewhere."""
        return {
            **env,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "remote.origin.pushurl",
            "GIT_CONFIG_VALUE_0": self.OTHER,
        }

    def test_base_env_pushurl_is_seen_by_the_remote_check(self) -> None:
        """Fails on the old code: origin was checked without, then pushed with, the pushurl."""
        self.commit(self.checkout)
        before = self.remote_main()
        for name in ("push", "publish"):
            with self.subTest(name=name):
                base = self.injected(dict(os.environ))
                if name == "push":
                    rc = deploykey.push(self.inventory(), "demo-push", base=base).rc
                else:
                    with self.assertRaises(DeployKeyError):
                        deploykey.publish(self.inventory(), "demo-push", base=base)
                    rc = EXIT_REFUSED
                self.assertEqual(rc, EXIT_REFUSED)
                self.assertEqual(self.ssh_calls(), [])
        self.assertEqual(self.remote_main(), before)

    def test_process_env_does_not_decide_the_remote(self) -> None:
        """A pushurl only in os.environ (not the push's base env) does not refuse the push."""
        sha = self.commit(self.checkout)
        clean = dict(os.environ)
        os.environ.update(self.injected({}))
        outcome = deploykey.push(self.inventory(), "demo-push", base=clean)
        self.assertEqual(outcome.rc, EXIT_OK, outcome.message)
        self.assertEqual(self.remote_main(), sha)
