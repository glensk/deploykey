"""Regression tests of the known_hosts quoting, lock, fsync and remote-env fixes.

stdlib ``unittest`` only — this module also runs under macOS's /usr/bin/python3 (3.9).
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import unittest

import deploykey
from deploykey._common import EXIT_REFUSED, RefusedError
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
