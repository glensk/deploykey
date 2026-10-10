"""Admin commands: check (5 classes), audit, reconcile, sync. stdlib ``unittest``."""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import plistlib
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from deploykey import cli_admin, evidence
from deploykey._common import RefusedError
from deploykey.audit import installed_jobs, run_audit
from deploykey.check import Checker, fingerprint_of_public, run_check, uv_lock_sha
from deploykey.inventory import build, normalize
from deploykey.reconcile import Reconciler, ruleset_body
from deploykey.tools import ApiError

from .support import GIT, Sandbox, run

HELPER = "a" * 40
NEEDS_TOMLLIB = unittest.skipIf(sys.version_info < (3, 11), "tomllib needs Python 3.11+")


def problems(report: Any, cls: str | None = None) -> list[str]:
    """Texts of the report's ``problem`` findings, optionally of one class only."""
    return [
        f.text for f in report.findings if f.level == "problem" and (cls is None or f.cls == cls)
    ]


class FakeApi:
    """Records calls; answers from a ``{(method, path): value}`` table."""

    def __init__(self, table: dict[tuple[str, str], Any]) -> None:
        self.table = table
        self.calls: list[tuple[str, str, str, Any]] = []

    def check(self, tool: str, path: str, host: str) -> Any:
        """Answer a ``check``-style ``api(tool, path, host)`` call as a GET."""
        return self.reconcile(tool, path, host, "GET", None)

    def reconcile(
        self, tool: str, path: str, _host: str, method: str, fields: dict[str, Any] | None
    ) -> Any:
        """Record the call and answer it from the table; unknown keys raise a 404."""
        self.calls.append((tool, method, path, fields))
        key = (method, path)
        if key not in self.table:
            raise ApiError(path, 1, "HTTP 404 Not Found")
        value = self.table[key]
        return value(fields) if callable(value) else value


class CheckOfflineTest(Sandbox):
    """``deploykey check`` rules that need no network (``offline=True``)."""

    def test_healthy(self) -> None:
        """A consistent sandbox inventory yields no problem and an ok report."""
        report = run_check(self.inventory(), helper=HELPER, offline=True)
        self.assertEqual(problems(report), [])
        self.assertTrue(report.ok)

    def test_fingerprint_mismatch(self) -> None:
        """A key whose file does not match its recorded fingerprint is a key-config problem."""
        raw = self.raw_inventory()
        raw["key"][0]["fingerprint"] = self.fpr[self.read_key_path.name]
        raw["key"][0]["status"] = "retiring"  # same fingerprint twice is legal only then
        report = run_check(build(raw), helper=HELPER, offline=True)
        self.assertTrue(any("fingerprint" in p for p in problems(report, "key-config")))

    def test_mode_and_pinned_hosts(self) -> None:
        """A world-readable key and a known_hosts without the host are both reported."""
        self.key_path.chmod(0o644)
        self.known_hosts.write_text("other.example.org ssh-ed25519 AAAA\n")
        texts = problems(run_check(self.inventory(), helper=HELPER, offline=True))
        self.assertTrue(any("readable by others" in t for t in texts))
        self.assertTrue(any("no entry for github.com" in t for t in texts))

    def test_helper_sha_drift(self) -> None:
        """A helper sha other than the consumer's ``helper_sha`` is reported."""
        texts = problems(run_check(self.inventory(), helper="b" * 40, offline=True))
        self.assertTrue(any("helper_sha" in t for t in texts))

    def test_runtime_drift(self) -> None:
        """An installed runtime JSON differing from the TOML is red; an identical one is clean."""
        source = normalize(self.raw_inventory(refspec="HEAD:refs/heads/other"))
        report = run_check(self.inventory(), helper=HELPER, source_json=source, offline=True)
        self.assertTrue(any("differs from the TOML" in t for t in problems(report)))
        same = normalize(self.raw_inventory())
        report = run_check(self.inventory(), helper=HELPER, source_json=same, offline=True)
        self.assertEqual(problems(report), [])

    def test_failed_attempt_stays_red_until_success(self) -> None:
        """A failed push stays a publication problem until a later success clears it."""
        inv = self.inventory()
        path = inv.consumers["demo-push"].evidence
        evidence.record(
            path, consumer="demo-push", operation="push", rc=0, message="ok", helper="x"
        )
        evidence.record(
            path, consumer="demo-push", operation="push", rc=4, message="denied", helper="x"
        )
        self.assertTrue(problems(run_check(inv, helper=HELPER, offline=True), "publication"))
        evidence.record(
            path, consumer="demo-push", operation="push", rc=0, message="ok", helper="x"
        )
        self.assertFalse(problems(run_check(inv, helper=HELPER, offline=True), "publication"))

    def test_periodic_success_age(self) -> None:
        """A last success older than ``max_success_age_s`` is a publication problem."""
        inv = self.inventory(self.raw_inventory(max_success_age_s=3600))
        path = inv.consumers["demo-push"].evidence
        evidence.record(
            path, consumer="demo-push", operation="push", rc=0, message="ok", helper="x"
        )
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
        texts = problems(run_check(inv, helper=HELPER, offline=True, now=later), "publication")
        self.assertTrue(any("old" in t for t in texts))

    def test_legacy_log_failure_rotation_and_clearing(self) -> None:
        """A legacy log failure survives log rotation and clears only after a newer success."""
        log = self.root / "job.log"
        log.write_text("ok\nfatal: Permission denied (publickey).\n")
        inv = self.inventory(self.raw_inventory(log=str(log)))
        self.assertTrue(problems(run_check(inv, helper=HELPER, offline=True), "log"))
        # rotation (new inode, smaller file) without a success keeps the failure
        log.unlink()
        log.write_text("x\n")
        self.assertTrue(problems(run_check(inv, helper=HELPER, offline=True), "log"))
        # a later real success clears it
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=5)
        path = inv.consumers["demo-push"].evidence
        evidence.record(
            path, consumer="demo-push", operation="push", rc=0, message="ok", helper="x"
        )
        record = evidence.read(path) or {}
        record["last_success_at"] = later.isoformat()
        Path(path).write_text(json.dumps(record), encoding="utf-8")
        self.assertFalse(problems(run_check(inv, helper=HELPER, offline=True), "log"))

    def test_planned_rows_are_notes(self) -> None:
        """Planned key and consumer rows produce notes, never problems."""
        raw = self.raw_inventory(status="planned", helper_sha="")
        raw["key"][0].update(status="planned", fingerprint="")
        report = run_check(build(raw), helper=HELPER, offline=True)
        self.assertEqual(problems(report), [])


class CheckOnlineTest(Sandbox):
    """``deploykey check`` rules that probe the remote and read its branch policy."""

    def api(self, rules: list[str], enforcement: str = "active") -> FakeApi:
        """A fake GitHub API answering the effective branch rules and the ruleset."""
        return FakeApi(
            {
                ("GET", "repos/glensk/demo/rules/branches/main"): [{"type": t} for t in rules],
                ("GET", "repos/glensk/demo/rulesets/22"): {"id": 22, "enforcement": enforcement},
            }
        )

    def test_probe_policy_and_stuck(self) -> None:
        """A healthy probe passes; an unpushed commit older than 24 h is stuck."""
        api = self.api(["deletion", "non_fast_forward"])
        report = run_check(self.inventory(), helper=HELPER, api=api.check)
        self.assertEqual(problems(report), [], report.findings)
        self.assertTrue(any("probe ok" in f.text for f in report.findings))
        # an unpushed commit older than 24 h is stuck
        old = (dt.datetime.now() - dt.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
        os.environ["GIT_COMMITTER_DATE"] = old
        self.commit(self.checkout)
        del os.environ["GIT_COMMITTER_DATE"]
        report = run_check(self.inventory(), helper=HELPER, api=api.check)
        self.assertTrue(any("ahead" in t for t in problems(report, "stuck")))

    def test_recent_unpushed_commit_is_a_note(self) -> None:
        """An unpushed commit younger than 24 h is not a problem."""
        self.commit(self.checkout)
        report = run_check(
            self.inventory(), helper=HELPER, api=self.api(["deletion", "non_fast_forward"]).check
        )
        self.assertEqual(problems(report), [])

    def test_policy_missing_rule(self) -> None:
        """A missing ``non_fast_forward`` rule or a disabled ruleset is a policy problem."""
        report = run_check(self.inventory(), helper=HELPER, api=self.api(["deletion"]).check)
        self.assertTrue(any("non_fast_forward" in t for t in problems(report, "policy")))
        report = run_check(
            self.inventory(),
            helper=HELPER,
            api=self.api(["deletion", "non_fast_forward"], "disabled").check,
        )
        self.assertTrue(problems(report, "policy"))

    def test_probe_auth_failure_is_red(self) -> None:
        """A probe the server rejects for the key is an authentication problem."""
        (self.root / "deny").write_text("")
        api = self.api(["deletion", "non_fast_forward"])
        texts = problems(run_check(self.inventory(), helper=HELPER, api=api.check), "key-config")
        self.assertTrue(any("authentication" in t for t in texts))

    def test_gitlab_policy(self) -> None:
        """A GitLab protected branch passes only while force push stays disallowed."""
        raw = self.raw_inventory(remote="git@gitlab.example.org:glensk/demo.git")
        raw["key"][0]["host"] = "gitlab.example.org"
        inv = build(raw)
        branch = ("GET", "projects/glensk%2Fdemo/protected_branches/main")
        checker_api = FakeApi(
            {
                branch: {
                    "id": 22,
                    "allow_force_push": False,
                    "push_access_levels": [{"access_level": 30}, {"deploy_key_id": 11}],
                }
            }
        )
        checker = Checker(inv, helper=HELPER, api=checker_api.check)
        checker.check_policy(inv.keys["github-demo-write"])
        self.assertEqual([f.text for f in checker.findings], [])
        checker_api.table[branch]["allow_force_push"] = True
        checker.check_policy(inv.keys["github-demo-write"])
        self.assertEqual(len(checker.findings), 1, checker.findings)
        self.assertEqual(checker.findings[0].cls, "policy")
        self.assertIn("force", checker.findings[0].text)


class AuditTest(Sandbox):
    """``deploykey audit`` over installed launchd jobs and the audit table."""

    def _plist(self, folder: Path, label: str) -> None:
        folder.mkdir(exist_ok=True)
        with (folder / f"{label}.plist").open("wb") as handle:
            plistlib.dump({"Label": label, "ProgramArguments": ["/bin/true"]}, handle)

    def test_audit(self) -> None:
        """Unaudited, gone, undecided and unknown rows are problems; stale, pending are notes."""
        agents = self.root / "agents"
        for label in ("ch.test.push", "com.apple.x", "ch.quiet", "ch.brand.new", "ch.covered"):
            self._plist(agents, label)
        audit = {
            "schema": 1,
            "vendor_prefixes": ["com.apple."],
            "jobs_without_network_git": ["ch.quiet"],
            "calls": [
                {
                    "job": "ch.test.push",
                    "plist": "x",
                    "script": "/x.py:1",
                    "status": "consumer:demo-push",
                },
                {"job": "ch.covered", "plist": "x", "script": "", "status": "consumer:gone"},
                {"job": "ch.covered", "plist": "x", "script": "", "status": "NEW - decide x"},
                {"job": "ch.covered", "plist": "x", "script": "", "status": "planned:later"},
                {"job": "ch.removed", "plist": "x", "script": "", "status": "no-key: maintenance"},
                {
                    "job": "ch.covered",
                    "plist": "x",
                    "script": "",
                    "status": "pending: P3.2 opt-outs",
                },
                {"job": "ch.covered", "plist": "x", "script": "", "status": "maybe"},
            ],
        }
        report = run_audit(self.inventory(), audit, installed_jobs([str(agents)]))
        texts = problems(report)
        self.assertTrue(any("unaudited" in t for t in texts))
        self.assertTrue(any("'gone'" in t for t in texts))
        self.assertTrue(any("undecided" in t for t in texts))
        self.assertTrue(any("unknown status" in t for t in texts))
        self.assertEqual(len(texts), 4, texts)
        notes = [f.text for f in report.findings if f.level == "note"]
        self.assertTrue(any("stale row" in t for t in notes))
        self.assertTrue(any("pending (planned:later)" in t for t in notes))
        self.assertTrue(any(t.startswith("pending: P3.2") for t in notes))


class ReconcileTest(Sandbox):
    """``deploykey reconcile`` against a fake GitHub/GitLab API."""

    def _pub(self, path: Path) -> str:
        return " ".join(path.with_suffix(".pub").read_text().split()[:2])

    def test_existing_key_verified(self) -> None:
        """A registered key with matching id and access is verified without any write call."""
        api = FakeApi(
            {
                ("GET", "repos/glensk/demo/keys"): [
                    {"id": 11, "key": self._pub(self.key_path), "read_only": False}
                ]
            }
        )
        out = Reconciler(
            self.inventory(), "github-demo-write", api=api.reconcile, say=lambda _s: None
        ).run()
        self.assertEqual(out["remote_key_id"], 11)
        self.assertFalse([c for c in api.calls if c[1] != "GET"])

    def test_id_mismatch_refused(self) -> None:
        """A registered key under another id than the inventory's is refused."""
        api = FakeApi(
            {
                ("GET", "repos/glensk/demo/keys"): [
                    {"id": 99, "key": self._pub(self.key_path), "read_only": False}
                ]
            }
        )
        with self.assertRaises(RefusedError):
            Reconciler(
                self.inventory(), "github-demo-write", api=api.reconcile, say=lambda _s: None
            ).run()

    def test_access_mismatch_refused(self) -> None:
        """A write key registered read-only on the remote is refused."""
        api = FakeApi(
            {
                ("GET", "repos/glensk/demo/keys"): [
                    {"id": 11, "key": self._pub(self.key_path), "read_only": True}
                ]
            }
        )
        with self.assertRaises(RefusedError):
            Reconciler(
                self.inventory(), "github-demo-write", api=api.reconcile, say=lambda _s: None
            ).run()

    def _planned(self, path: Path) -> dict[str, Any]:
        raw = self.raw_inventory(status="planned", helper_sha="")
        raw["key"][0].update(status="planned", fingerprint="", path=str(path))
        del raw["key"][0]["remote_key_id"]
        del raw["key"][0]["policy_id"]
        return raw

    def test_generate_register_and_create_policy(self) -> None:
        """A planned key is generated 0600, registered and gets an append-only ruleset."""
        new = self.keydir / "github-demo-new"
        created: list[Any] = []

        def register(fields: Any) -> dict[str, int]:
            created.append(fields)
            return {"id": 55}

        api = FakeApi(
            {
                ("GET", "repos/glensk/demo/keys"): [],
                ("POST", "repos/glensk/demo/keys"): register,
                ("GET", "repos/glensk/demo/rulesets?includes_parents=true"): [],
                ("GET", "repos/glensk/demo/rules/branches/main"): [],
                ("GET", "repos/glensk/demo/rulesets"): [],
                ("POST", "repos/glensk/demo/rulesets"): lambda f: {"id": 77, **f},
            }
        )
        out = Reconciler(
            self.inventory(self._planned(new)),
            "github-demo-write",
            api=api.reconcile,
            policy=True,
            evidence_dir=self.root / "ev",
            say=lambda _s: None,
        ).run()
        self.assertTrue(new.exists())
        self.assertEqual(new.stat().st_mode & 0o777, 0o600)
        self.assertEqual(out["remote_key_id"], 55)
        self.assertEqual(out["policy_id"], 77)
        self.assertEqual(created[0]["read_only"], False)
        self.assertEqual(fingerprint_of_public(created[0]["key"]), out["fingerprint"])
        posted = [c[3] for c in api.calls if c[1] == "POST" and c[2].endswith("rulesets")]
        self.assertEqual(posted, [ruleset_body("main")])
        self.assertEqual(len(list((self.root / "ev").iterdir())), 1)

    def test_dry_run_changes_nothing(self) -> None:
        """A dry run creates no key file and issues no write call."""
        new = self.keydir / "github-demo-new"
        api = FakeApi({("GET", "repos/glensk/demo/keys"): []})
        Reconciler(
            self.inventory(self._planned(new)),
            "github-demo-write",
            api=api.reconcile,
            dry_run=True,
            say=lambda _s: None,
        ).run()
        self.assertFalse(new.exists())
        self.assertEqual([c for c in api.calls if c[1] != "GET"], [])

    def test_gitlab_protect_branch(self) -> None:
        """On GitLab the deploy key may push and the protected branch forbids force push."""
        raw = self._planned(self.key_path)
        raw["key"][0]["fingerprint"] = self.fpr[self.key_path.name]
        raw["key"][0]["host"] = "gitlab.example.org"
        raw["key"][0]["repo"] = "group/sub/proj"
        raw["consumer"] = [
            dict(raw["consumer"][0], remote="git@gitlab.example.org:group/sub/proj.git")
        ]
        project = "projects/group%2Fsub%2Fproj"
        api = FakeApi(
            {
                ("GET", f"{project}/deploy_keys"): [],
                ("POST", f"{project}/deploy_keys"): {"id": 9},
                ("GET", f"{project}/protected_branches"): [],
                ("GET", project): {"id": 419},
                ("POST", f"{project}/protected_branches"): {"id": 31},
            }
        )
        out = Reconciler(
            build(raw),
            "github-demo-write",
            api=api.reconcile,
            policy=True,
            evidence_dir=self.root / "ev",
            say=lambda _s: None,
        ).run()
        self.assertEqual((out["remote_key_id"], out["policy_id"]), (9, 31))
        body = next(
            c[3] for c in api.calls if c[1] == "POST" and c[2].endswith("protected_branches")
        )
        self.assertEqual(body["allowed_to_push"], [{"access_level": 30}, {"deploy_key_id": 9}])
        self.assertIs(body["allow_force_push"], False)
        posted_key = next(
            c[3] for c in api.calls if c[1] == "POST" and c[2].endswith("deploy_keys")
        )
        self.assertIs(posted_key["can_push"], True)


TOML = """\
schema = 1

[settings]
key_dir = "{keydir}"
state_dir = "{state}"
ssh = "{ssh}"

[[key]]
name = "github-demo-write"
path = "{key}"
fingerprint = "{fpr}"
host = "github.com"
repo = "glensk/demo"
direction = "write"
remote_key_id = 11
policy_id = 22

[[consumer]]
label = "demo-push"
launchd_label = "ch.test.push"
key = "github-demo-write"
checkout = "{checkout}"
remote = "git@github.com:glensk/demo.git"
refspec = "HEAD:refs/heads/main"
git = "{git}"
proxy_command = ""
helper_sha = ""
evidence = "{state}/demo-push.json"
status = "legacy"
"""


@NEEDS_TOMLLIB
class SyncAndCliTest(Sandbox):
    """``deploykey sync`` and ``check`` through the admin CLI entry point."""

    def _toml(self) -> Path:
        path = self.root / "deploy-keys.toml"
        path.write_text(
            TOML.format(
                keydir=self.keydir,
                state=self.state,
                ssh=self.ssh,
                key=self.key_path,
                fpr=self.fpr[self.key_path.name],
                checkout=self.checkout,
                git=GIT,
            )
        )
        return path

    def _main(self, argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_admin.main(argv)
        return rc, buf.getvalue()

    def test_sync_then_check(self) -> None:
        """Sync writes a 0600 runtime JSON that checks green until the TOML changes."""
        toml = self._toml()
        out = self.root / "rt.json"
        rc, _ = self._main(["sync", "-i", str(toml), "-o", str(out)])
        self.assertEqual(rc, 0)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        rc, text = self._main(["check", "-d", "-i", str(toml), "-c", str(out), "-j"])
        self.assertEqual(rc, 0, text)
        self.assertTrue(json.loads(text)["ok"])
        toml.write_text(toml.read_text().replace("ch.test.push", "ch.test.other"))
        rc, text = self._main(["check", "-d", "-i", str(toml), "-c", str(out)])
        self.assertEqual(rc, 1)
        self.assertIn("differs from the TOML", text)

    def test_sync_refuses_bad_inventory(self) -> None:
        """Sync refuses a forcing refspec with exit 3 and writes no runtime file."""
        toml = self._toml()
        toml.write_text(
            toml.read_text().replace('"HEAD:refs/heads/main"', '"+HEAD:refs/heads/main"')
        )
        out = self.root / "rt.json"
        self.assertEqual(cli_admin.main(["sync", "-i", str(toml), "-o", str(out)]), 3)
        self.assertFalse(out.exists())

    def test_uv_lock_sha(self) -> None:
        """The deploykey git rev is read from uv.lock; a missing lock gives None."""
        lock = self.root / "uv.lock"
        lock.write_text(
            'version = 1\n[[package]]\nname = "deploykey"\nversion = "0.1.0"\n'
            f'source = {{ git = "https://github.com/glensk/deploykey?rev={HELPER}#{HELPER}" }}\n'
        )
        self.assertEqual(uv_lock_sha(str(lock)), HELPER)
        self.assertIsNone(uv_lock_sha(str(self.root / "missing.lock")))

    def test_check_missing_runtime_is_red(self) -> None:
        """A missing runtime JSON makes ``check`` exit 1 with a readable reason."""
        rc, text = self._main(["check", "-d", "-c", str(self.root / "absent.json")])
        self.assertEqual(rc, 1)
        self.assertIn("cannot read", text)


class RunToolTest(unittest.TestCase):
    """The ``run`` test helper itself."""

    def test_run_helper(self) -> None:
        """``run`` returns the command's stdout."""
        self.assertIn("git version", run([GIT, "--version"]))


if __name__ == "__main__":
    unittest.main()
