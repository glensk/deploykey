# deploykey

## Purpose

`deploykey` manages repository-scoped SSH deploy keys for unattended Git automation, especially macOS `launchd` jobs that cannot safely depend on an interactive hardware-backed SSH identity. It separates runtime operations from administration: `deploy-git` executes tightly constrained push, pull, and commit-then-push actions from a validated inventory, while `deploykey` installs and checks that inventory and reconciles remote key state. The design limits each consumer to one repository, one key, and one allowed refspec, with pinned SSH behavior and per-attempt evidence files.

## Key Capabilities

- Enforces safe unattended Git operations with inventory-defined consumers: `deploy-git push <consumer>`, `pull <consumer>`, and `run <consumer> -- <cmd...>` operate under a repository lock, reject unsafe Git options/refspecs before any network call, and use only the configured key and remote.
- Provides admin workflows to manage and verify deployment state: `deploykey sync`, `check`, `audit`, and `reconcile` convert TOML inventory to runtime JSON, validate configuration and health rules, detect launchd drift, and provision or verify deploy keys.

## Tech Stack

Python package with two CLIs (`deploy-git`, `deploykey`); stdlib-only Python 3.9-compatible runtime core, Python 3.11+ admin features using `tomllib`, plus Git, OpenSSH, launchd, and `extdeps`-resolved `gh`/`glab`.

## Key Scripts / Files

| File | Purpose |
|---|---|
| `deploykey/cli_git.py` | Entry point for `deploy-git` push/pull/run operations against one inventory consumer. |
| `deploykey/cli_admin.py` | Entry point for admin commands such as `sync`, `check`, `audit`, and `reconcile`. |
| `deploykey/ops.py` | Core runtime logic for push, pull, run, and publish operations. |
| `deploykey/inventory.py` | Defines and validates the runtime inventory schema used by both CLIs. |
| `deploykey/gitenv.py` | Builds the constrained Git/SSH environment that ignores user SSH config and agents. |
| `deploykey/lock.py` | Implements repository locking around commit-and-push transactions. |
| `deploykey/evidence.py` | Records JSON evidence for each attempt and last successful operation. |
| `deploykey/check.py` | Health and policy checks for inventory and runtime configuration. |
| `deploykey/audit.py` | Audits launchd-related drift and deployment state. |
| `deploykey/reconcile.py` | Provisions or verifies a deploy key and refuses mismatches. |
| `deploykey/source.py` | Loads source inventory data from TOML for admin workflows. |
| `deploykey/tools.py` | Resolves external admin tools such as `gh` and `glab` via `extdeps`. |
| `README.md` | Usage, guarantees, inventory format, install instructions, and trust model. |
