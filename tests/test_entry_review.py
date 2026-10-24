"""Independent adversarial review regressions for the trusted entry point.

Written after reviewing entry.py; failures demonstrate unverified trust claims.
No external network calls occur in these tests.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import entry


REPOSITORY = "example-org/example-repo"
RED = "a" * 40
GREEN = "b" * 40


def evidence():
    return {"tdd": {
        "red_commit": RED,
        "green_commit": GREEN,
        "red_run_url": f"https://github.com/{REPOSITORY}/actions/runs/12",
        "green_run_url": f"https://github.com/{REPOSITORY}/actions/runs/13",
    }}


def profile():
    return {"tdd_workflows": {
        "red": ".github/workflows/test.yml",
        "green": ".github/workflows/test.yml",
    }}


def run(red):
    return {
        "repository": {"full_name": REPOSITORY},
        "head_sha": RED if red else GREEN,
        "path": ".github/workflows/test.yml",
        "status": "completed",
        "conclusion": "failure" if red else "success",
        "created_at": "2026-10-23T12:00:00Z" if red else "2026-10-23T12:10:00Z",
        "run_started_at": "2026-10-23T12:00:00Z" if red else "2026-10-23T12:10:00Z",
        "updated_at": "2026-10-23T12:05:00Z" if red else "2026-10-23T12:15:00Z",
    }


class EntryReviewTests(unittest.TestCase):
    def test_prepare_cannot_write_workflow_command_channels(self):
        channels = ["GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            candidate = base / "candidate"
            candidate.mkdir()
            observed = candidate / "observed-channels.json"
            code = "import json,os; from pathlib import Path; Path('observed-channels.json').write_text(json.dumps([key for key in " + repr(channels) + " if key in os.environ]))"
            approved = {category: {"command": ["python3", "test.py"], "report": category + ".xml"} for category in entry.CATEGORIES}
            approved.update(runner="ubuntu-24.04", python_version="3.12", prepare=[[sys.executable, "-c", code]])
            (base / "profiles.json").write_text(json.dumps({"schema_version": 1, "repositories": {REPOSITORY: approved}}))
            original_run = subprocess.run

            def execute_setup_only(command, *args, **kwargs):
                if len(command) > 1 and command[1] == "-c":
                    return original_run(command, *args, **kwargs)
                return subprocess.CompletedProcess(command, 0)

            environment = {"QUALITY_REPOSITORY": REPOSITORY, **{key: str(base / key) for key in channels}}
            with patch.object(entry, "HERE", base), patch.dict(os.environ, environment), patch.object(entry.subprocess, "run", side_effect=execute_setup_only), patch.object(entry.changed_tests, "check_changed_tests", return_value={"classification": "feature"}):
                result = entry.main(["--mode", "run", "--root", str(candidate), "--reports", str(base / "reports")])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(observed.read_text()), [])

    def test_green_run_before_red_does_not_establish_tdd(self):
        def fetch(path):
            result = run(path.endswith("/12"))
            if path.endswith("/12"):
                result.update(created_at="2026-10-23T13:00:00Z", run_started_at="2026-10-23T13:00:00Z", updated_at="2026-10-23T13:05:00Z")
            return result

        with self.assertRaises(ValueError):
            entry.verify_run_links(evidence(), profile(), REPOSITORY, fetch)

    def test_missing_run_chronology_does_not_establish_tdd(self):
        def fetch(path):
            result = run(path.endswith("/12"))
            for key in ("created_at", "run_started_at", "updated_at"):
                result.pop(key)
            return result

        with self.assertRaises(ValueError):
            entry.verify_run_links(evidence(), profile(), REPOSITORY, fetch)

    def test_run_url_cannot_fetch_other_host(self):
        for url in [
            f"https://github.com@evil.test/{REPOSITORY}/actions/runs/12",
            f"https://github.com/{REPOSITORY}/actions/runs/12?redirect=https://evil.test",
            f"https://github.com/{REPOSITORY}/actions/runs/12\r\nX-Injected: yes",
        ]:
            with self.subTest(url=url):
                value = evidence()
                value["tdd"]["red_run_url"] = url
                calls = []
                with self.assertRaises(ValueError):
                    entry.verify_run_links(value, profile(), REPOSITORY, lambda path: calls.append(path))
                self.assertEqual(calls, [])

    def test_runner_and_python_output_injection_rejected(self):
        for field, malicious in [("runner", "ubuntu-24.04\ntrusted=true"), ("python_version", "3.12\ntrusted=true")]:
            with self.subTest(field=field):
                candidate = {category: {"command": ["python", "test.py"], "report": category + ".xml"} for category in entry.CATEGORIES}
                candidate.update(runner="ubuntu-24.04", python_version="3.12")
                candidate[field] = malicious
                with self.assertRaises(ValueError):
                    entry.select_profile({"schema_version": 1, "repositories": {REPOSITORY: candidate}}, REPOSITORY)

    def test_forged_event_cannot_claim_pr_verification(self):
        for event in ["pull_request_target", "push", "workflow_dispatch", "merge_group", "pull_request\nanything"]:
            with self.subTest(event=event), self.assertRaises(ValueError):
                entry.verify_event(event)


if __name__ == "__main__":
    unittest.main()
