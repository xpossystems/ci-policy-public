"""Real-process and clean-verifier contracts for mandatory full-suite evidence."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import entry

REPOSITORY = 'example-org/example-repo'
SUITES = ('unit', 'integration', 'security', 'regression')
GOOD = '<testsuite tests="1"><testcase name="executed"/></testsuite>'


class RegressionGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.root = self.directory/'candidate'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'CI test')
        self.git('config', 'user.email', 'ci@example.invalid')
        (self.root/'README.md').write_text('before')
        self.base = self.commit()
        (self.root/'README.md').write_text('after')
        self.head = self.commit()
        self.profile = {'runner': 'ubuntu-24.04', 'python_version': '3.12',
                        'test_paths': {kind: [f'tests/{kind}/**/*.py'] for kind in entry.CATEGORIES}}
        for kind in SUITES:
            self.profile[kind] = {'command': [sys.executable, '-c',
                'from pathlib import Path; assert 6*7 == 42; Path('+repr(kind+'.xml')+').write_text('+repr(GOOD)+')'],
                'report': kind+'.xml', 'timeout_seconds': 10}
        for filename in ('run_suite.py', 'quality_gate.py'):
            shutil.copyfile(Path(entry.__file__).parent/filename, self.directory/filename)
        self.reports = self.directory/'reports'
        self.env = {'QUALITY_REPOSITORY': REPOSITORY, 'QUALITY_PR_NUMBER': '7',
                    'QUALITY_EVENT_NAME': 'pull_request', 'QUALITY_BASE_SHA': self.base, 'QUALITY_HEAD_SHA': self.head}

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, text=True,
            capture_output=True, env={**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}, timeout=10).stdout.strip()

    def commit(self):
        self.git('add', '-A')
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def invoke(self, mode='baseline'):
        (self.directory/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {REPOSITORY: self.profile}}))
        pull = {'number': 7, 'state': 'open', 'body': '', 'head': {'sha': self.head},
                'base': {'sha': self.base, 'repo': {'full_name': REPOSITORY}}}
        out, err = io.StringIO(), io.StringIO()
        with patch.object(entry, 'HERE', self.directory), patch.object(entry, '_fetch', return_value=pull), patch.dict(os.environ, self.env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = entry.main(['--mode', mode, '--root', str(self.root), '--reports', str(self.reports)])
        return result, out.getvalue(), err.getvalue()

    def publish(self):
        self.reports.mkdir()
        for kind in SUITES:
            (self.reports/(kind+'.xml')).write_text(GOOD)

    def test_profile_cannot_omit_full_regression_or_keep_exit_only_legacy_commands(self):
        for mutation in ('missing', 'regression_commands', 'regression_reports'):
            profile = copy.deepcopy(self.profile)
            if mutation == 'missing':
                del profile['regression']
            else:
                profile[mutation] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                entry.select_profile({'schema_version': 1, 'repositories': {REPOSITORY: profile}}, REPOSITORY)

    def test_real_unfiltered_regression_runs_and_publishes_fourth_report(self):
        code, _, err = self.invoke()
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(path.name for path in self.reports.iterdir()), sorted(kind+'.xml' for kind in SUITES))
        code, out, err = self.invoke('verify')
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)['regression_executed'], 1)

    def test_old_green_regression_cannot_be_reused_by_exit_zero_command(self):
        (self.root/'regression.xml').write_text(GOOD)
        self.profile['regression']['command'] = [sys.executable, '-c', 'pass']
        self.assertNotEqual(self.invoke()[0], 0)
        self.assertFalse((self.reports/'regression.xml').exists())

    def test_skipped_full_suite_cannot_hide_behind_three_green_categories(self):
        skipped = '<testsuite tests="1" skipped="1"><testcase name="missing"><skipped/></testcase></testsuite>'
        self.profile['regression']['command'][-1] = 'from pathlib import Path; Path("regression.xml").write_text('+repr(skipped)+')'
        self.assertNotEqual(self.invoke()[0], 0)
        self.assertFalse((self.reports/'regression.xml').exists())

    def test_clean_verify_rejects_missing_failed_skipped_empty_and_aliased_regression(self):
        self.publish()
        path = self.reports/'regression.xml'
        for invalid in (None, '<testsuite/>', '<testsuite><testcase name="bad"><failure/></testcase></testsuite>',
                        '<testsuite><testcase name="skip"><skipped/></testcase></testsuite>', 'symlink', 'hardlink'):
            path.unlink(missing_ok=True)
            if invalid == 'symlink':
                path.symlink_to(self.reports/'unit.xml')
            elif invalid == 'hardlink':
                os.link(self.reports/'unit.xml', path)
            elif invalid is not None:
                path.write_text(invalid)
            with self.subTest(invalid=invalid):
                self.assertNotEqual(self.invoke('verify')[0], 0)

    def test_non_test_check_failure_blocks_even_after_all_reports_pass(self):
        self.profile['checks'] = [{'command': [sys.executable, '-c', 'raise SystemExit(7)'], 'timeout_seconds': 10}]
        self.assertNotEqual(self.invoke()[0], 0)

    def test_non_test_check_commands_cannot_use_unbounded_or_invalid_execution(self):
        for check in ([], {'command': 'echo good'}, {'command': ['']}, {'command': ['noop'], 'timeout_seconds': 0},
                      {'command': ['noop'], 'timeout_seconds': True}, {'command': ['noop'], 'timeout_seconds': 3601}):
            profile = copy.deepcopy(self.profile)
            profile['checks'] = [check]
            with self.subTest(check=check), self.assertRaises(ValueError):
                entry.select_profile({'schema_version': 1, 'repositories': {REPOSITORY: profile}}, REPOSITORY)
