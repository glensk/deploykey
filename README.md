# deploykey

Repo-scoped ssh deploy keys for **unattended** git pushes and fetches on a Mac whose
interactive ssh identity lives on a hardware token (a YubiKey PIV agent that cannot sign
after deep sleep). A launchd job never gets a free `git push`: it names its row in an
inventory, and `deploy-git` pushes exactly that row's single refspec with that row's key.

- `deploy-git push <consumer>` — push the inventory refspec (e.g. `HEAD:refs/heads/main`)
  to the inventory remote with the consumer's write key.
- `deploy-git pull <consumer>` — fetch one branch with a read key into the private ref
  `refs/deploykey/pull/<branch>`, then `git merge --ff-only` it (no `git pull`: a foreign
  fetch in the same clone cannot race it on `FETCH_HEAD` or `refs/remotes/*`). The
  remote-tracking ref is then advanced by compare-and-swap (left alone if another fetch
  moved it meanwhile), so `git status` does not report "ahead".
- `deploy-git run <consumer> -- <cmd…>` — under the repository lock, run the local commit
  command with `AI_PUSH_LOCAL_ONLY=1` and no key, then push.
- `deploykey sync | check | audit | reconcile` — install the runtime inventory, health
  rules, launchd audit drift, provision one key (create if absent, verify if present,
  refuse on mismatch).
- Library: `deploykey.publish(inv, "<consumer>", commit=callable)`, `deploykey.push/pull/run`,
  `deploykey.repo_lock`, `deploykey.git_env`, `DeployKeyError`, `LOCAL_ONLY_ENV`.

The runtime core (`deploy-git`, the library) is **stdlib-only and Python 3.9-compatible**
(macOS's `/usr/bin/python3`). Only the admin commands need Python 3.11+ (`tomllib`) and
`gh`/`glab` (resolved through [extdeps](https://github.com/glensk/extdeps)).

## Install

Pin an exact commit sha, never a tag or a branch:

```commands
SHA=<commit sha>
D=~/.local/share/deploykey/$SHA
UV_TOOL_DIR=$D/tools UV_TOOL_BIN_DIR=$D/bin uv tool install git+https://github.com/glensk/deploykey@$SHA
for b in deploy-git deploykey; do ln -sfn $D/bin/$b ~/.local/bin/.$b.new && /bin/mv -h ~/.local/bin/.$b.new ~/.local/bin/$b; done
deploy-git -V        # prints $SHA (read from the install's PEP 610 direct_url.json)
```

Rollback = point the two links back at the previous `<sha>` directory. A library consumer
pins it in its own project: `uv add "deploykey @ git+https://github.com/glensk/deploykey@<sha>"`.

## What `deploy-git` guarantees

- ssh runs as `/usr/bin/ssh -F /dev/null -i <key> -o IdentitiesOnly=yes -o IdentityAgent=none
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<pinned>
  -o ControlMaster=no …` (plus the row's `ProxyCommand`, if any). The user's ssh config and
  agent are never read; `SSH_AUTH_SOCK`/`GIT_SSH*` are dropped.
- The remote URL must be `git@<host>:<path>` or `ssh://git@<host>/<path>` and match the
  key's repository; the checkout's remote must carry exactly that one (push) URL; a
  `remote.<name>.mirror` remote is refused.
- Refused before any network call (exit 3): `+` (force), `*`, an empty source (deletion),
  several refs, a destination outside `refs/heads/`, any git option on the command line
  (`--force`, `--mirror`, `--tags`, `--delete`, `-o` …), a key file missing or not 0600,
  missing pinned host keys, a `run` command that is neither absolute nor found on the
  inventory's fixed `PATH` (the caller's `$PATH` is never used).
- `push.recurseSubmodules=check`, `push.followTags=false`, cleared `push.pushOption`,
  `submodule.recurse=false` are appended through `GIT_CONFIG_COUNT`.
- `flock` on `<git-common-dir>/deploykey.lock` around the whole commit+push transaction.
  A non-fast-forward rejection exits 4 and keeps the commit local: no automatic rebase.
- `deploy-git pull` updates only its private ref `refs/deploykey/pull/<branch>`, with `+`
  (a local ref deploykey owns — not a force push); the `merge --ff-only` that follows refuses
  a non-fast-forward (exit 4) and leaves the checkout untouched.
- No network operation is retried, with one exception: `deploy-git pull` re-runs its
  read-only fetch (at most 3 attempts, only while `net_timeout_s > 0`) after an allowlisted
  client-side transient transport failure (connection reset/refused/timed out, unresolved
  host). Authentication, host-key, protocol, ref-update and merge failures are never
  retried; exhaustion still exits 4. A retried success names the failure it absorbed.
- Every attempt rewrites `<evidence>.json` (`last_attempt_at`, `last_attempt_rc`,
  `last_success_at`, `pushed_sha`, `remote_oid`, `helper_sha`); a failure keeps the last
  success fields.

Exit codes: 0 ok, 1 red findings (`check`/`audit`), 2 usage, 3 refused, 4 network/remote/
local-command failure.

## Inventory

TOML source (one per machine, kept in a private repo) → `deploykey sync -i <toml>` →
runtime JSON `~/.ssh/deploy/deploy-keys.json` (atomic). `deploy-git` reads only the JSON
and re-validates it. Schema: [`deploykey/inventory.py`](deploykey/inventory.py).

```toml
schema = 1

[settings]
key_dir = "~/.ssh/deploy"

[[key]]
name = "github-demo-write"
fingerprint = "SHA256:…"
host = "github.com"
repo = "owner/demo"
direction = "write"
remote_key_id = 123
policy_id = 456          # the append-only ruleset / protected branch

[[consumer]]
label = "demo-push"
launchd_label = "ch.example.job"
key = "github-demo-write"
checkout = "~/src/demo"
remote = "git@github.com:owner/demo.git"
refspec = "HEAD:refs/heads/main"
git = "/opt/homebrew/bin/git"
proxy_command = ""
helper_sha = "<sha of the installed deploykey>"
evidence = "~/.local/state/deploykey/demo-push.json"
```

## Trust model

Deploy keys here are unencrypted files of the same Unix user as everything else that
runs unattended — any same-user process holds their authority. The bounds that hold:
one repository per key, one refspec per consumer, and (on the remote) an append-only rule
on every write branch, so a leaked key can only add fast-forward commits there.

## Development

```commands
uv sync
uv run pytest -q
/usr/bin/python3 -m unittest discover -s tests -t .
uv run ruff format . && uv run ruff check . && uv run mypy deploykey && uv run pylint deploykey
```

`tests/test_installed_cli.py` installs the CLI from a throw-away git commit with
`uv tool install git+file://…@<sha>` (default Python and 3.9) and pushes through a fake
ssh to a local bare repository.

License: Apache-2.0.
