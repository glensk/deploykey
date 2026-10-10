# AGENTS.md

Conventions for AI coding agents (and humans) working in this repo.

## What this is

Public package `deploykey`: repo-scoped ssh deploy keys for unattended git pushes and
fetches — the `deploy-git` CLI (no free refspec, per-repository lock, evidence records),
the `deploykey` admin CLI (`sync`, `check`, `audit`, `reconcile`) and the library behind
both. The inventory it reads is private data and lives elsewhere (for Albert's Mac:
credplane `deploy/mac/deploy-keys.toml`, plan `PLAN_unattended-push-keys.md`, tp#891).

## Environment

- `uv` for everything: `uv sync`, `uv run …`. The CLI is installed per commit sha with
  `uv tool install git+https://github.com/glensk/deploykey@<sha>` (README "Install").
- No secrets in this repo, ever: no key material, no inventories, no host names beyond
  examples. Tests generate throw-away keys in temp directories.

## Build / test / lint

- `uv run pytest -q` and `/usr/bin/python3 -m unittest discover -s tests -t .` (Python 3.9)
- `uv run ruff format . && uv run ruff check . && uv run mypy deploykey && uv run pylint deploykey`
- Pre-commit: `pre-commit run --all-files` (gitleaks secret scan)

## Conventions

- **The runtime core is stdlib-only and Python 3.9-compatible**: `_common`, `inventory`,
  `gitenv`, `lock`, `evidence`, `ops`, `cli_git`, `check`, `audit`, `reconcile`. No
  third-party imports there, no `match`, no runtime `X | Y` (annotations only, with
  `from __future__ import annotations`), no `datetime.UTC`. `tomllib` is confined to
  `source.py` (and `check.uv_lock_sha`), behind a version guard. The 3.9 unittest run
  enforces this.
- **External executables**: the runtime core never resolves a tool by name. `ssh`,
  `ssh-keygen` and `git` are absolute paths from the inventory, and a `run` command's
  `argv[0]` is looked up only on the inventory's fixed `PATH` — this is the deliberate
  exception to the extdeps convention (a launchd job's environment must not choose the
  binary that runs with the repository lock held). `gh`/`glab` for the admin commands are
  declared in `deploykey/tools.py` through `extdeps` (env override `GH_BIN`/`GLAB_BIN`).
- Every rule is implemented once, here. Consumers (credplane, infra/status) call the CLI
  or the library; they never re-implement a check.
- Every CLI option has a short flag; `-h` works on both CLIs.
- Refusals happen before any network call and exit 3; network failures exit 4 and keep
  local commits. Never add an automatic rebase, force push or retry loop.
- Tests never touch real keys, real remotes or the real inventory: use `tests/support.py`
  (temp keys, fake ssh serving local bare repos, `DEPLOYKEY_CONFIG` pointing into the
  sandbox, `GIT_CONFIG_GLOBAL` isolated).

## Where things live

- Design: credplane `PLAN_unattended-push-keys.md` (tp#891).
- Private/local notes: CLAUDE.local.md (gitignored).
