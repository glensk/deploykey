"""``deploykey check``'s network phase: one wave, one cap, unchanged findings.

Every network read of a check run is capped on its own (60 s), so reading them one
after the other made a run cost the *sum* of the caps. On the Mac's inventory that
is 21 reads against the status hub's 90 s budget, and a single stalled ssh
connection was enough to push a healthy ~25 s run past it (``mac/unattended-push``
flapped, last `deploykey check -j timed out after 90s`). The reads now start
together, so one cap bounds them all.

The concurrency is asserted with a :class:`threading.Barrier` rather than a stopwatch:
a serial run never gets a second reader to the barrier, so it breaks it and the test
fails outright instead of flaking on a loaded machine.
"""

from __future__ import annotations

import io
import json
import subprocess
import threading
from contextlib import redirect_stdout
from typing import Any
from unittest import mock

from deploykey import cli_admin
from deploykey.check import Checker, run_check
from deploykey.gitenv import git as real_git

from .support import Sandbox

HELPER = "a" * 40
#: Long enough that a serial run really is stuck, short enough to fail fast.
BARRIER_TIMEOUT_S = 30
PROBES = 5


class Api:
    """A GitHub policy that answers every read, optionally through a barrier."""

    def __init__(self, barrier: threading.Barrier | None = None) -> None:
        self.barrier = barrier
        self.table: dict[str, Any] = {
            "repos/glensk/demo/rules/branches/main": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
            ],
            "repos/glensk/demo/rulesets/22": {"id": 22, "enforcement": "active"},
        }

    def __call__(self, _tool: str, path: str, _host: str) -> Any:
        if self.barrier is not None:
            self.barrier.wait(timeout=BARRIER_TIMEOUT_S)
        return self.table[path]


class Timeout(Api):
    """A policy read that exceeds ``tools.api_json``'s cap."""

    def __call__(self, _tool: str, path: str, _host: str) -> Any:
        raise subprocess.TimeoutExpired(cmd=["gh", "api", path], timeout=60)


class NetworkPhaseTest(Sandbox):
    """The reads of one run start together and report exactly what they did before."""

    def raw(self) -> dict[str, Any]:
        """The sandbox inventory with :data:`PROBES` read consumers instead of one."""
        raw = self.raw_inventory()
        pull = raw["consumer"][1]
        raw["consumer"] = [raw["consumer"][0]] + [
            {**pull, "label": f"demo-pull-{n}", "launchd_label": f"ch.test.pull{n}"}
            for n in range(PROBES - 1)
        ]
        return raw

    def test_every_read_of_a_run_starts_together(self) -> None:
        """All probes and both policy reads meet at one barrier; serial would break it."""
        reads = PROBES + 2  # one ls-remote per consumer, two gh reads for the write key
        barrier = threading.Barrier(reads)
        api = Api(barrier)

        def gated_git(consumer: Any, *argv: str, **kw: Any) -> Any:
            if argv and argv[0] == "ls-remote":
                barrier.wait(timeout=BARRIER_TIMEOUT_S)
            return real_git(consumer, *argv, **kw)

        with mock.patch("deploykey.check.git", gated_git):
            report = run_check(self.inventory(self.raw()), helper=HELPER, api=api)
        self.assertFalse(barrier.broken)
        self.assertEqual([f.text for f in report.findings if f.level == "problem"], [])
        self.assertEqual(sum("probe ok" in f.text for f in report.findings), PROBES)

    def test_findings_keep_their_content_and_order(self) -> None:
        """Still inventory order, and ``stuck`` still sees the ``live_oid`` of its own probe.

        ``check_stuck`` runs inside the per-consumer traversal, right after the probe
        that fills ``live_oid`` — prefetching the reads must not move either.
        """
        self.commit(self.checkout)
        report = run_check(self.inventory(self.raw()), helper=HELPER, api=Api())
        self.assertEqual(
            [(f.row, f.cls) for f in report.findings],
            [("demo-push", "publication"), ("demo-push", "key-config"), ("demo-push", "stuck")]
            + [
                (f"demo-pull-{n}", cls)
                for n in range(PROBES - 1)
                for cls in ("publication", "key-config")
            ],
        )
        stuck = [f for f in report.findings if f.cls == "stuck"]
        self.assertEqual(len(stuck), 1)
        self.assertIn("1 unpushed commit(s)", stuck[0].text)

    def test_a_policy_read_that_times_out_is_a_finding(self) -> None:
        """``tools.api_json``'s cap ends in a red finding, never in an aborted run."""
        report = run_check(self.inventory(), helper=HELPER, api=Timeout())
        self.assertEqual(
            [f.text for f in report.findings if f.cls == "policy"],
            ["glensk/demo:main: cannot read the policy: timed out after 60s"],
        )

    def test_the_cli_still_prints_a_verdict_when_a_policy_read_times_out(self) -> None:
        """``check -j`` answers with its JSON report and exit 1, never with a traceback."""
        self.write_runtime()
        with mock.patch("deploykey.check._default_api", Timeout()):
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli_admin.main(["check", "-j"])
        self.assertEqual(code, 1)
        report = json.loads(out.getvalue())
        self.assertFalse(report["ok"])
        self.assertIn(
            "cannot read the policy: timed out after 60s",
            [f["text"] for f in report["findings"]][-1],
        )

    def test_a_single_read_still_works_without_a_prefetch(self) -> None:
        """A :class:`Checker` method called on its own reads the network itself."""
        inv = self.inventory()
        checker = Checker(inv, helper=HELPER, api=Api())
        checker.check_policy(inv.keys["github-demo-write"])
        self.assertEqual(checker.findings, [])
        checker.probe(inv.consumers["demo-push"])
        self.assertEqual(checker.live_oid["demo-push"], self.remote_main())

    def test_three_consumers_of_one_remote_each_get_their_own_probe(self) -> None:
        """Sharing a key, a remote and a ref does not merge two rows into one finding."""
        report = run_check(self.inventory(self.raw()), helper=HELPER, api=Api())
        probes = [f.row for f in report.findings if "probe ok" in f.text]
        self.assertEqual(len(probes), PROBES)
        self.assertEqual(len(set(probes)), PROBES)
