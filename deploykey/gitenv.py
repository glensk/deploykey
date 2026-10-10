"""The ssh/git environment of one deploy key (stdlib only, Python 3.9+).

``GIT_SSH_COMMAND`` runs ``ssh -F /dev/null``: the user's ssh config — the PIV
``IdentityFile``/``IdentityAgent``, a ``ControlMaster`` mux a PIV-authenticated
session may hold open, ``StrictHostKeyChecking no``, host aliases — is not read
at all, and ``IdentityAgent=none`` + ``IdentitiesOnly=yes`` keep every agent key
out. The host key is pinned (``known_hosts`` of the key row) and ``BatchMode=yes``
turns any prompt into a failure instead of a hang. A row's ``proxy_command`` is
the one ssh-config feature carried over explicitly (gitlab.datascience.ch is only
reachable through the EPFL SOCKS hop).
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess  # nosec B404 - fixed argv, never a shell
from collections.abc import Mapping, Sequence
from pathlib import Path

from ._common import SSH_ENV_DROP, RefusedError
from .inventory import Consumer, Inventory, Key, parse_remote_url


def ssh_command(ssh: str, key: Key, proxy_command: str = "", connect_timeout: int = 30) -> str:
    """The ``GIT_SSH_COMMAND`` that offers *key* and nothing else."""
    argv = [
        ssh,
        "-F", "/dev/null",
        "-i", key.path,
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={key.known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
    ]  # fmt: skip
    if proxy_command:
        argv += ["-o", f"ProxyCommand={proxy_command}"]
    return shlex.join(argv)


def check_file(path: str, what: str, *, private: bool) -> None:
    """Refuse unless *path* is a regular file (and, if *private*, mode 0600 or stricter)."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise RefusedError(f"{what} {path} is missing ({exc.strerror})") from exc
    if not stat.S_ISREG(st.st_mode):
        raise RefusedError(f"{what} {path} is not a regular file")
    if private and st.st_mode & 0o077:
        raise RefusedError(
            f"{what} {path} is readable by others (mode {stat.S_IMODE(st.st_mode):o}); chmod 600 it"
        )


def check_key_files(key: Key) -> None:
    """The private key (0600, regular) and its pinned host keys must exist."""
    if key.status == "planned":
        raise RefusedError(f"key {key.name!r} is planned, not provisioned yet")
    check_file(key.path, "deploy key", private=True)
    check_file(key.known_hosts, f"pinned {key.host} host keys", private=False)


def git_env(
    inv: Inventory,
    consumer: Consumer,
    base: Mapping[str, str],
    *,
    extra_config: Sequence[tuple[str, str]] = (),
) -> dict[str, str]:
    """*base* minus every other ssh route, plus the consumer's deploy-key ssh setup.

    ``push.recurseSubmodules=check`` (through ``GIT_CONFIG_COUNT``, appended to any
    existing entries) stops a global ``submodule.recurse=true`` from pushing
    submodules with this repository's key; ``push.pushOption`` is cleared and tags
    are never followed, so a push carries exactly the one inventory ref.
    """
    key = inv.key_of(consumer)
    check_key_files(key)
    env = {k: v for k, v in base.items() if k not in SSH_ENV_DROP}
    env["GIT_SSH_COMMAND"] = ssh_command(
        inv.settings.ssh,
        key,
        consumer.proxy_command,
        min(30, inv.settings.net_timeout_s or 30),
    )
    env["GIT_SSH_VARIANT"] = "ssh"  # OpenSSH argv; no `ssh -G` variant probe
    env["GIT_TERMINAL_PROMPT"] = "0"
    config = [
        ("push.recurseSubmodules", "check"),
        ("push.followTags", "false"),
        ("push.pushOption", ""),
        ("submodule.recurse", "false"),
        ("fetch.recurseSubmodules", "false"),
        *extra_config,
    ]
    return append_git_config(env, config)


def append_git_config(env: dict[str, str], pairs: Sequence[tuple[str, str]]) -> dict[str, str]:
    """Append ``GIT_CONFIG_KEY_n``/``VALUE_n`` pairs after any existing ones."""
    try:
        count = int(env.get("GIT_CONFIG_COUNT", "0") or "0")
    except ValueError as exc:
        raise RefusedError(f"GIT_CONFIG_COUNT={env['GIT_CONFIG_COUNT']!r} is not a number") from exc
    for name, value in pairs:
        env[f"GIT_CONFIG_KEY_{count}"] = name
        env[f"GIT_CONFIG_VALUE_{count}"] = value
        count += 1
    env["GIT_CONFIG_COUNT"] = str(count)
    return env


def local_env(base: Mapping[str, str]) -> dict[str, str]:
    """The env of a commit command ``deploy-git run`` starts: no key, no agent, no push."""
    env = {k: v for k, v in base.items() if k not in SSH_ENV_DROP}
    env["AI_PUSH_LOCAL_ONLY"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git(
    consumer: Consumer,
    *argv: str,
    env: Mapping[str, str] | None = None,
    timeout: float | None = 60,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the consumer's absolute ``git`` in its checkout (no shell, captured)."""
    return subprocess.run(  # nosec B603 - absolute git from the inventory
        [consumer.git, "-C", cwd or consumer.checkout, *argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=dict(env) if env is not None else None,
    )


def git_common_dir(consumer: Consumer, worktree: str | None = None) -> Path:
    """The absolute git-common-dir of the checkout (or of *worktree*)."""
    proc = git(
        consumer,
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
        cwd=worktree,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip() or f"git rc={proc.returncode}"
        raise RefusedError(f"{worktree or consumer.checkout} is not a git checkout: {detail}")
    return Path(proc.stdout.strip())


def resolve_remote(consumer: Consumer, *, push: bool, cwd: str | None = None) -> str:
    """The name of the checkout's remote whose (push) URL is the inventory ``remote``.

    RefusedError: no such remote, a remote with several URLs, and ``remote.<n>.mirror``.
    """
    want = parse_remote_url(consumer.remote)
    names = git(consumer, "remote", cwd=cwd)
    if names.returncode != 0:
        raise RefusedError(
            f"cannot list remotes in {cwd or consumer.checkout}: {names.stderr.strip()}"
        )
    matches = []
    for name in names.stdout.split():
        argv = ["remote", "get-url", "--all", *(["--push"] if push else []), name]
        urls = git(consumer, *argv, cwd=cwd).stdout.split()
        try:
            parsed = {parse_remote_url(u) for u in urls}
        except RefusedError:
            continue
        if parsed == {want}:
            if len(urls) != 1:
                raise RefusedError(
                    f"remote {name!r} has {len(urls)} URLs; deploy-git needs exactly one"
                )
            matches.append(name)
    if not matches:
        raise RefusedError(
            f"no remote of {cwd or consumer.checkout} {'pushes' if push else 'fetches'} to "
            f"{consumer.remote}"
        )
    name = "origin" if "origin" in matches else sorted(matches)[0]
    mirror = git(consumer, "config", "--bool", "--get", f"remote.{name}.mirror", cwd=cwd)
    if mirror.stdout.strip() == "true":
        raise RefusedError(f"remote.{name}.mirror is set; a mirror push is never allowed")
    return name
