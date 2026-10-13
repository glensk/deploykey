"""Test fixtures: a throw-away key, pinned hosts, bare "remotes" and a fake ssh.

The fake ssh is a /bin/sh script baked with the sandbox root: it records its argv
(one file per call) and serves ``git-receive-pack``/``git-upload-pack`` from
``<root>/remotes/<host>/<path>`` with the local git, so every network operation
runs end to end without leaving the machine. ``<root>/deny`` makes it answer like
an ssh server that rejects the key; ``<root>/fail-times`` (a count, decremented on
each call) plus ``<root>/fail-message`` make the next N calls fail like a blip —
:meth:`Sandbox.fail_ssh` writes both.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from deploykey.inventory import Inventory, build, normalize

GIT = shutil.which("git") or "/usr/bin/git"
SSH_KEYGEN = "/usr/bin/ssh-keygen"

FAKE_SSH = """#!/bin/sh
n=$(ls "{root}"/ssh-calls 2>/dev/null | wc -l | tr -d ' ')
printf '%s\\n' "$@" > "{root}/ssh-calls/call-$n"
for last; do :; done
host=""
for a; do case "$a" in git@*) host="${{a#git@}}";; esac; done
if [ -f "{root}/deny" ]; then
  echo "git@$host: Permission denied (publickey)." >&2
  exit 255
fi
if [ -f "{root}/fail-times" ]; then
  left=$(cat "{root}/fail-times")
  if [ "$left" -gt 0 ]; then
    echo $((left - 1)) > "{root}/fail-times"
    cat "{root}/fail-message" >&2
    exit 255
  fi
fi
verb="${{last%% *}}"
path="${{last#* }}"
path="${{path#\\'}}"
path="${{path%\\'}}"
path="${{path#/}}"
exec "{git}" "${{verb#git-}}" "{root}/remotes/$host/$path"
"""


def run(argv: list[Any], cwd: str | Path | None = None, **kw: Any) -> str:
    """Run a command, fail loudly, return stdout."""
    proc = subprocess.run(
        [str(a) for a in argv], cwd=cwd, capture_output=True, text=True, check=False, **kw
    )
    if proc.returncode != 0:
        raise AssertionError(f"{argv} rc={proc.returncode}: {proc.stdout}{proc.stderr}")
    return str(proc.stdout)


class Sandbox(unittest.TestCase):
    """A temp dir with one write key, one read key, two remotes and checkouts."""

    HOST = "github.com"
    REPO = "glensk/demo"
    URL = "git@github.com:glensk/demo.git"

    def setUp(self) -> None:
        # pylint: disable-next=consider-using-with  # lives until tearDown cleans it up
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self._env = os.environ.copy()
        os.environ.update(
            {
                "GIT_CONFIG_GLOBAL": str(self.root / "gitconfig"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.invalid",
                "SSH_AUTH_SOCK": "/nonexistent/agent.sock",
            }
        )
        for name in ("GIT_CONFIG_COUNT", "GIT_SSH_COMMAND", "DEPLOYKEY_CONFIG"):
            os.environ.pop(name, None)
        (self.root / "gitconfig").write_text(
            "[init]\n\tdefaultBranch = main\n[submodule]\n\trecurse = true\n"
            "[commit]\n\tgpgsign = false\n"
        )
        (self.root / "ssh-calls").mkdir()
        self.keydir = self.root / "keys"
        self.keydir.mkdir(mode=0o700)
        self.key_path = self.keydir / "github-demo-write"
        self.read_key_path = self.keydir / "github-demo-read"
        for path in (self.key_path, self.read_key_path):
            run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", path])
        self.fpr = {p.name: self.fingerprint(p) for p in (self.key_path, self.read_key_path)}
        self.known_hosts = self.keydir / "known_hosts_github.com"
        pub = (self.key_path.with_suffix(".pub")).read_text().split()
        self.known_hosts.write_text(f"github.com {pub[0]} {pub[1]}\n")
        self.ssh = self.root / "fake-ssh"
        self.ssh.write_text(FAKE_SSH.format(root=self.root, git=GIT))
        self.ssh.chmod(0o755)
        self.bare = self.root / "remotes" / self.HOST / f"{self.REPO}.git"
        self.bare.parent.mkdir(parents=True)
        run([GIT, "init", "-q", "--bare", "-b", "main", self.bare])
        self.seed = self.root / "seed"
        run([GIT, "init", "-q", "-b", "main", self.seed])
        (self.seed / "a.txt").write_text("a\n")
        run([GIT, "-C", self.seed, "add", "a.txt"])
        run([GIT, "-C", self.seed, "commit", "-q", "-m", "seed"])
        run([GIT, "-C", self.seed, "push", "-q", str(self.bare), "main"])
        self.checkout = self.root / "checkout"
        run([GIT, "clone", "-q", str(self.bare), self.checkout])
        run([GIT, "-C", self.checkout, "remote", "set-url", "origin", self.URL])
        self.state = self.root / "state"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        self._tmp.cleanup()

    # -- inventory --------------------------------------------------------------
    def fingerprint(self, path: Path) -> str:
        """``SHA256:…`` of a key file."""
        return run([SSH_KEYGEN, "-lf", path]).split()[1]

    def raw_inventory(self, **consumer_over: Any) -> dict[str, Any]:
        """A valid raw inventory with one write and one read consumer."""
        write = {
            "label": "demo-push",
            "launchd_label": "ch.test.push",
            "key": "github-demo-write",
            "checkout": str(self.checkout),
            "remote": self.URL,
            "refspec": "HEAD:refs/heads/main",
            "git": GIT,
            "proxy_command": "",
            "helper_sha": "a" * 40,
            "evidence": str(self.state / "demo-push.json"),
        }
        write.update(consumer_over)
        return {
            "schema": 1,
            "settings": {
                "key_dir": str(self.keydir),
                "state_dir": str(self.state),
                "ssh": str(self.ssh),
                "lock_timeout_s": 5,
                "net_timeout_s": 60,
            },
            "key": [
                {
                    "name": "github-demo-write",
                    "path": str(self.key_path),
                    "fingerprint": self.fpr[self.key_path.name],
                    "host": self.HOST,
                    "repo": self.REPO,
                    "direction": "write",
                    "remote_key_id": 11,
                    "policy_id": 22,
                },
                {
                    "name": "github-demo-read",
                    "path": str(self.read_key_path),
                    "fingerprint": self.fpr[self.read_key_path.name],
                    "host": self.HOST,
                    "repo": self.REPO,
                    "direction": "read",
                    "remote_key_id": 12,
                    "known_hosts": str(self.known_hosts),
                },
            ],
            "consumer": [
                write,
                {
                    "label": "demo-pull",
                    "launchd_label": "ch.test.pull",
                    "key": "github-demo-read",
                    "checkout": str(self.checkout),
                    "remote": self.URL,
                    "refspec": "refs/heads/main",
                    "git": GIT,
                    "proxy_command": "",
                    "helper_sha": "a" * 40,
                    "evidence": str(self.state / "demo-pull.json"),
                },
            ],
        }

    def inventory(self, raw: dict[str, Any] | None = None) -> Inventory:
        """A validated :class:`deploykey.Inventory`."""
        return build(raw if raw is not None else self.raw_inventory())

    def write_runtime(self, raw: dict[str, Any] | None = None) -> Path:
        """Install the runtime JSON in the sandbox and point $DEPLOYKEY_CONFIG at it."""
        path = self.root / "deploy-keys.json"
        path.write_text(json.dumps(normalize(raw if raw is not None else self.raw_inventory())))
        os.environ["DEPLOYKEY_CONFIG"] = str(path)
        return path

    # -- git helpers --------------------------------------------------------------
    def commit(self, repo: Path, name: str = "b.txt", text: str = "b\n") -> str:
        """Commit one file in *repo*; returns the new sha."""
        (repo / name).write_text(text)
        run([GIT, "-C", repo, "add", name])
        run([GIT, "-C", repo, "commit", "-q", "-m", f"add {name}"])
        return run([GIT, "-C", repo, "rev-parse", "HEAD"]).strip()

    def remote_main(self) -> str:
        """The bare remote's main."""
        return run([GIT, "-C", self.bare, "rev-parse", "refs/heads/main"]).strip()

    def fail_ssh(self, times: int, message: str) -> None:
        """Make the next *times* fake-ssh calls fail with *message* on stderr (exit 255)."""
        (self.root / "fail-message").write_text(f"{message}\n")
        (self.root / "fail-times").write_text(f"{times}\n")

    def ssh_calls(self) -> list[list[str]]:
        """Every recorded fake-ssh argv."""
        calls = sorted((self.root / "ssh-calls").iterdir(), key=lambda p: int(p.name.split("-")[1]))
        return [p.read_text().splitlines() for p in calls]

    def evidence(self, label: str = "demo-push") -> dict[str, Any]:
        """The consumer's evidence record."""
        data: dict[str, Any] = json.loads((self.state / f"{label}.json").read_text())
        return data
