"""TDD integration for baseline runs that never grant final merge approval."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import test_changed_tests as fixtures


class BaselineEntryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ChangedTestsGitIntegrationTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.trusted = self.fixture.entry_fixture()

    def invoke(self, mode='baseline', report_name='baseline-reports', **environment):
        report = self.fixture.directory/report_name
        result = subprocess.run([sys.executable, str(self.trusted/'entry.py'), '--mode', mode,
                                 '--root', str(self.fixture.root), '--reports', str(report)],
                                env={**os.environ, 'QUALITY_REPOSITORY': 'example-org/fixture', **environment},
                                capture_output=True, text=True, timeout=30)
        return result, report

    def test_baseline_executes_existing_suites_without_changed_test_or_pr_context(self):
        self.fixture.write('src/app.py', 'value = 2\n')
        self.fixture.commit('candidate still under development')
        result, reports = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.fixture.root/'prepare-ran').exists())
        for kind in fixtures.TEST_PATHS:
            self.assertIn('tests="1"', (reports/(kind+'.xml')).read_text())

    def test_red_assertion_fails_then_green_implementation_passes(self):
        self.fixture.write('src/app.py', 'value = 0\n')
        self.fixture.commit('missing expected behavior')
        red, _ = self.invoke(report_name='red-reports')
        self.assertNotEqual(red.returncode, 0)
        self.assertIn('AssertionError', red.stderr)
        self.fixture.write('src/app.py', 'value = 20\n')
        self.fixture.commit('implement expected behavior')
        green, reports = self.invoke(report_name='green-reports')
        self.assertEqual(green.returncode, 0, green.stderr)
        self.assertEqual(len(list(reports.glob('*.xml'))), 3)

    def test_final_run_still_rejects_missing_changed_tests_before_prepare(self):
        self.fixture.write('src/app.py', 'value = 2\n')
        head = self.fixture.commit('candidate without new assertions')
        result, reports = self.invoke(mode='run', QUALITY_BASE_SHA=self.fixture.base, QUALITY_HEAD_SHA=head)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing added/modified', result.stderr)
        self.assertFalse((self.fixture.root/'prepare-ran').exists())
        self.assertFalse(reports.exists())

    def test_baseline_does_not_skip_full_regression_failure(self):
        path = self.trusted/'profiles.json'
        config = json.loads(path.read_text())
        config['repositories']['example-org/fixture']['regression_commands'] = [[sys.executable, '-c', 'raise SystemExit(3)']]
        path.write_text(json.dumps(config))
        result, reports = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exit status 3', result.stderr)
        self.assertEqual(len(list(reports.glob('*.xml'))), 3)

    def test_baseline_rejects_skips_and_cannot_reuse_success_report(self):
        self.fixture.write('tests/security/test_existing.py', 'import unittest\nclass Skipped(unittest.TestCase):\n    @unittest.skip("must block")\n    def test_security(self): pass\n')
        result, reports = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('skipped', result.stderr)
        self.assertFalse((reports/'security.xml').exists())


if __name__ == '__main__': unittest.main()
