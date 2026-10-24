"""Real-process and hostile-path contracts for centrally approved suite execution."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

POLICY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY))
import run_suite as runner

REPOSITORY = "example-org/example-repo"
VALID = '<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="real-case"/></testsuite>'


class SuiteRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="suite-runner-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "candidate"
        self.root.mkdir()
        self.profiles = self.base / "profiles.json"
        self.output = self.base / "evidence" / "unit.xml"
        self.output.parent.mkdir()
        self.set_profile()

    def set_profile(self, **overrides):
        profile = {
            "command": [sys.executable, "-c", "from pathlib import Path; Path('results').mkdir(exist_ok=True); Path('results/unit.xml').write_text(" + repr(VALID) + "); print('suite stdout retained')"],
            "report": "results/unit.xml",
            "timeout_seconds": 10,
        }
        profile.update(overrides)
        self.profiles.write_text(json.dumps({"schema_version": 1, "repositories": {REPOSITORY: {"unit": profile}}}))
        return profile

    def run_suite(self, **overrides):
        args = dict(repository=REPOSITORY, category="unit", root=self.root,
                    profiles=self.profiles, output=self.output)
        args.update(overrides)
        return runner.run_suite(**args)

    def reject(self, **overrides):
        with self.assertRaises(runner.SuiteError):
            self.run_suite(**overrides)
        self.assertFalse(self.output.exists())

    def test_real_process_runs_in_candidate_and_copies_valid_report(self):
        result = self.run_suite()
        self.assertEqual(result["executed"], 1)
        self.assertEqual(self.output.read_text(), VALID)
        self.assertTrue((self.root / "results/unit.xml").exists())

    def test_unknown_repository_is_rejected_before_running(self):
        self.reject(repository="someone/unregistered")
        self.assertFalse((self.root / "results").exists())

    def test_missing_category_is_rejected(self):
        self.reject(category="security")

    def test_unknown_category_is_rejected(self):
        self.reject(category="lint")

    def test_empty_repositories_cannot_pass(self):
        self.profiles.write_text('{"schema_version":1,"repositories":{}}')
        self.reject()

    def test_missing_profiles_cannot_pass(self):
        self.profiles.unlink()
        self.reject()

    def test_duplicate_profile_keys_are_rejected(self):
        self.profiles.write_text('{"schema_version":1,"schema_version":1,"repositories":{}}')
        self.reject()

    def test_wrong_schema_version_rejected(self):
        data = json.loads(self.profiles.read_text())
        data["schema_version"] = True
        self.profiles.write_text(json.dumps(data))
        self.reject()

    def test_profiles_inside_candidate_rejected(self):
        candidate_profile = self.root / "profiles.json"
        candidate_profile.write_text(self.profiles.read_text())
        self.reject(profiles=candidate_profile)

    def test_command_requires_nonempty_argv_strings(self):
        for value in ["echo good", [], [""], [sys.executable, 1], ["bad\x00command"], ["   "]]:
            with self.subTest(value=value):
                self.set_profile(command=value)
                self.reject()

    def test_no_shell_expansion_of_command_arguments(self):
        marker = self.base / "injected"
        code = "import sys; from pathlib import Path; Path('results').mkdir(); Path('results/unit.xml').write_text(" + repr(VALID) + "); Path('argument.txt').write_text(sys.argv[1])"
        payload = "$(touch " + str(marker) + ")"
        self.set_profile(command=[sys.executable, "-c", code, payload])
        self.run_suite()
        self.assertEqual((self.root / "argument.txt").read_text(), payload)
        self.assertFalse(marker.exists())

    def test_nonzero_exit_cannot_pass_even_with_good_report(self):
        profile = self.set_profile()
        profile["command"][-1] += "; raise SystemExit(7)"
        self.set_profile(**profile)
        self.reject()

    def test_successful_exit_without_report_is_rejected(self):
        self.set_profile(command=[sys.executable, "-c", "print('no report')"])
        self.reject()

    def test_stale_report_is_removed_and_cannot_pass(self):
        (self.root / "results").mkdir()
        stale = self.root / "results/unit.xml"
        stale.write_text(VALID)
        self.set_profile(command=[sys.executable, "-c", "pass"])
        self.reject()
        self.assertFalse(stale.exists())

    def test_stale_cleanup_only_removes_declared_report(self):
        (self.root / "results").mkdir()
        (self.root / "results/unit.xml").write_text("stale")
        other = self.root / "results/other.xml"
        other.write_text("keep")
        self.run_suite()
        self.assertEqual(other.read_text(), "keep")

    def test_unsafe_report_paths_rejected(self):
        for report in ["../outside.xml", "/tmp/outside.xml", "results/../../outside.xml", "results/../unit.xml", "results\\unit.xml", ".git/report.xml", "", "report.txt", "C:/outside.xml"]:
            with self.subTest(report=report):
                self.set_profile(report=report)
                self.reject()

    def test_report_symlink_is_not_followed_or_deleted(self):
        victim = self.base / "victim.xml"
        victim.write_text(VALID)
        (self.root / "results").mkdir()
        link = self.root / "results/unit.xml"
        link.symlink_to(victim)
        self.reject()
        self.assertTrue(link.is_symlink())
        self.assertEqual(victim.read_text(), VALID)

    def test_report_parent_symlink_is_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        victim = outside / "unit.xml"
        victim.write_text(VALID)
        (self.root / "results").symlink_to(outside, target_is_directory=True)
        self.reject()
        self.assertEqual(victim.read_text(), VALID)

    def test_report_hardlink_is_rejected(self):
        victim = self.base / "victim.xml"
        victim.write_text(VALID)
        (self.root / "results").mkdir()
        os.link(victim, self.root / "results/unit.xml")
        self.reject()
        self.assertEqual(victim.read_text(), VALID)

    def test_process_cannot_replace_report_with_symlink(self):
        victim = self.base / "victim.xml"
        victim.write_text(VALID)
        code = "from pathlib import Path; Path('results').mkdir(); Path('results/unit.xml').symlink_to(" + repr(str(victim)) + ")"
        self.set_profile(command=[sys.executable, "-c", code])
        self.reject()

    def test_directory_report_is_rejected(self):
        (self.root / "results/unit.xml").mkdir(parents=True)
        self.reject()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_fifo_report_is_rejected_without_hanging(self):
        (self.root / "results").mkdir()
        os.mkfifo(self.root / "results/unit.xml")
        self.reject()

    def test_timeout_fails_closed(self):
        self.set_profile(command=[sys.executable, "-c", "import time; time.sleep(20)"], timeout_seconds=0.05)
        self.reject()

    def test_invalid_timeouts_are_rejected(self):
        for timeout in [0, -1, True, "5", 3601]:
            with self.subTest(timeout=timeout):
                self.set_profile(timeout_seconds=timeout)
                self.reject()

    def test_bad_reports_fail_even_with_exit_zero(self):
        reports = ["", "not XML", '<testsuite tests="0"/>', '<testsuite tests="1"><testcase name="skip"><skipped/></testcase></testsuite>', '<testsuite tests="1"><testcase name="fail"><failure/></testcase></testsuite>', '<testsuite tests="1"/>']
        for report in reports:
            with self.subTest(report=report):
                self.set_profile(command=[sys.executable, "-c", "from pathlib import Path; Path('results').mkdir(exist_ok=True); Path('results/unit.xml').write_text(" + repr(report) + ")"])
                self.reject()

    def test_output_inside_candidate_is_rejected(self):
        self.reject(output=self.root / "copied.xml")

    def test_existing_output_is_preserved(self):
        self.output.write_text("previous evidence")
        with self.assertRaises(runner.SuiteError):
            self.run_suite()
        self.assertEqual(self.output.read_text(), "previous evidence")

    def test_output_symlink_is_preserved(self):
        victim = self.base / "victim.xml"
        victim.write_text("keep")
        self.output.symlink_to(victim)
        with self.assertRaises(runner.SuiteError):
            self.run_suite()
        self.assertEqual(victim.read_text(), "keep")

    def test_cli_retains_stdout_and_reports_count(self):
        result = subprocess.run([sys.executable, str(POLICY / "run_suite.py"), "--repository", REPOSITORY, "--category", "unit", "--root", str(self.root), "--profiles", str(self.profiles), "--output", str(self.output)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite stdout retained", result.stdout)
        self.assertIn('"executed": 1', result.stdout)

    def test_relative_root_rejected(self):
        self.reject(root=Path("relative-candidate"))

    def test_workflow_command_channels_are_not_inherited(self):
        channels = ["GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE"]
        code = "import os,json; from pathlib import Path; Path('results').mkdir(); Path('results/unit.xml').write_text(" + repr(VALID) + "); Path('seen.json').write_text(json.dumps([k for k in " + repr(channels) + " if k in os.environ]))"
        self.set_profile(command=[sys.executable, "-c", code])
        with mock.patch.dict(os.environ, {key: "do-not-forward" for key in channels}):
            self.run_suite()
        self.assertEqual(json.loads((self.root / "seen.json").read_text()), [])

    def test_candidate_replacing_report_parent_with_symlink_is_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "unit.xml").write_text(VALID)
        code = "from pathlib import Path; Path('results').symlink_to(" + repr(str(outside)) + ", target_is_directory=True)"
        self.set_profile(command=[sys.executable, "-c", code])
        self.reject()

    def test_oversized_report_is_rejected(self):
        code = "from pathlib import Path; Path('results').mkdir(); Path('results/unit.xml').write_bytes(b'x' * (10*1024*1024+1))"
        self.set_profile(command=[sys.executable, "-c", code])
        self.reject()

    def test_entity_payload_cannot_read_external_file(self):
        victim = self.base / "victim.txt"
        victim.write_text("private fixture")
        xml = '<!DOCTYPE testsuite [<!ENTITY leak SYSTEM "' + victim.as_uri() + '">]><testsuite><testcase name="case"><system-out>&leak;</system-out></testcase></testsuite>'
        code = "from pathlib import Path; Path('results').mkdir(); Path('results/unit.xml').write_text(" + repr(xml) + ")"
        self.set_profile(command=[sys.executable, "-c", code])
        self.reject()

    def test_profiles_symlink_is_rejected(self):
        target = self.base / "real-profiles.json"
        self.profiles.rename(target)
        self.profiles.symlink_to(target)
        self.reject()

    def test_output_parent_symlink_is_rejected(self):
        outside = self.base / "output-real"
        outside.mkdir()
        self.output.parent.rmdir()
        self.output.parent.symlink_to(outside, target_is_directory=True)
        self.reject()
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX process groups")
    def test_successful_command_leaving_background_process_is_rejected(self):
        code = "import subprocess,sys; from pathlib import Path; Path('results').mkdir(); Path('results/unit.xml').write_text(" + repr(VALID) + "); subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])"
        self.set_profile(command=[sys.executable, "-c", code])
        self.reject()


if __name__ == "__main__":
    unittest.main()
