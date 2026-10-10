"""The installed CLI end to end: ``uv tool install git+file://…@<sha>``, fake ssh.

Proves what the unit tests cannot: the console scripts exist, ``-V`` reports the
commit sha the install was pinned to (PEP 610 ``direct_url.json``), and an
installed ``deploy-git`` pushes through the inventory's ssh with ``-F /dev/null``
— on the default interpreter and on Python 3.9.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import GIT, Sandbox, run

ROOT = Path(__file__).resolve().parents[1]
UV = shutil.which("uv") or str(Path.home() / ".local" / "bin" / "uv")


@unittest.skipUnless(os.path.exists(UV), "uv is not installed")
class InstalledCliTest(Sandbox):
    """The console scripts as installed by ``uv tool install`` from a pinned commit."""

    def _snapshot_repo(self) -> tuple[Path, str]:
        """A throw-away git repo holding the current source, committed."""
        src = self.root / "src"
        src.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copy2(ROOT / name, src / name)
        shutil.copytree(
            ROOT / "deploykey", src / "deploykey", ignore=shutil.ignore_patterns("__pycache__")
        )
        run([GIT, "init", "-q", "-b", "main", src])
        run([GIT, "-C", src, "add", "-A"])
        run([GIT, "-C", src, "commit", "-q", "-m", "snapshot"])
        return src, run([GIT, "-C", src, "rev-parse", "HEAD"]).strip()

    def _install(self, src: Path, sha: str, python: str | None = None) -> Path:
        tag = python or "default"
        env = dict(
            os.environ,
            UV_TOOL_DIR=str(self.root / f"tools-{tag}"),
            UV_TOOL_BIN_DIR=str(self.root / f"bin-{tag}"),
        )
        argv = [UV, "tool", "install", "-q", f"git+file://{src}@{sha}"]
        if python:
            argv += ["--python", python]
        proc = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return self.root / f"bin-{tag}"

    def _cli(self, exe: Path, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(exe), *argv], capture_output=True, text=True, check=False, env=dict(os.environ)
        )

    def test_installed_cli_end_to_end(self) -> None:
        """Installed CLIs report the pinned sha, push via the inventory ssh, refuse forcing."""
        src, sha = self._snapshot_repo()
        for python in (None, "3.9"):
            with self.subTest(python=python or "default"):
                self._clear_ssh_calls()
                bindir = self._install(src, sha, python)
                deploy_git = bindir / "deploy-git"
                self.assertEqual(self._cli(deploy_git, "-V").stdout.strip(), sha)
                raw = self.raw_inventory(helper_sha=sha)
                raw["consumer"][1]["helper_sha"] = sha
                self.write_runtime(raw)
                pushed = self.commit(self.checkout, f"cli-{python}.txt")
                proc = self._cli(deploy_git, "push", "demo-push")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(self.remote_main(), pushed)
                call = self.ssh_calls()[-1]
                self.assertEqual(call[:2], ["-F", "/dev/null"])
                self.assertIn("IdentityAgent=none", call)
                self.assertEqual(self.evidence()["helper_sha"], sha)
                if python is None:
                    check = self._cli(bindir / "deploykey", "check", "-d", "-j")
                    self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
                    self.assertEqual(self._cli(bindir / "deploykey", "-V").stdout.strip(), sha)
                refused = self._cli(deploy_git, "push", "demo-push", "--force")
                self.assertEqual(refused.returncode, 3)
                refused = self._cli(deploy_git, "run", "demo-push", "--", "./relative-tool")
                self.assertEqual(refused.returncode, 3)
                if python is None:  # a refused attempt is recorded and turns the check red
                    check = self._cli(bindir / "deploykey", "check", "-d")
                    self.assertEqual(check.returncode, 1, check.stdout)

    def _clear_ssh_calls(self) -> None:
        """Clear recorded ssh calls between interpreter rounds."""
        for call in (self.root / "ssh-calls").iterdir():
            call.unlink()


if __name__ == "__main__":
    unittest.main()
