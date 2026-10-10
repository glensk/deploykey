# deploykey — scope (short)

Public Python package + CLIs for repo-scoped ssh deploy keys used by unattended (launchd)
git pushes/fetches: `deploy-git` (push/pull/run a consumer row; no free refspec; flock per
repository; evidence JSON per attempt) and `deploykey` (sync/check/audit/reconcile).
Runtime core stdlib-only, Python 3.9+. Inventory data lives in credplane
`deploy/mac/deploy-keys.toml` (tp#891, `PLAN_unattended-push-keys.md`).
