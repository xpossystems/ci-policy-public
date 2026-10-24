"""Test-first exact CI rollout approval; real Git trees are the trust boundary."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import entry

REPOSITORY = 'example-org/example-repo'
CONTROL = '.github/workflows/feature-tests.yml'
PATTERNS = {kind: [f'tests/{kind}/**/*.py'] for kind in entry.CATEGORIES}


def load_guard(test):
    path = Path(__file__).resolve().parents[1]/'ci_configuration.py'
    test.assertTrue(path.is_file(), 'exact CI configuration classifier is not implemented')
    spec = importlib.util.spec_from_file_location('configuration_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GitFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.root = self.directory/'candidate'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'CI fixture')
        self.git('config', 'user.email', 'ci@example.invalid')
        self.git('config', 'core.hooksPath', str(self.directory/'no-hooks'))
        self.write('source.py', 'value = 1\n')
        self.write('AGENTS.md', 'Existing instructions\n')
        self.base = self.commit('base')
        self.before = self.git('rev-parse', self.base+':AGENTS.md')
        self.write(CONTROL, 'name: reviewed workflow\n')
        self.write('AGENTS.md', 'Existing instructions\nMandatory real tests\n')
        self.head = self.commit('reviewed CI configuration')
        self.manifest = {'schema_version': 1, 'repositories': {REPOSITORY: {
            CONTROL: {'before': None, 'after': self.git('rev-parse', self.head+':'+CONTROL)},
            'AGENTS.md': {'before': self.before, 'after': self.git('rev-parse', self.head+':AGENTS.md')},
        }}}

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, text=True, env=env, timeout=10).stdout.strip()

    def write(self, path, content):
        target = self.root/path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '--no-gpg-sign', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def check(self, **kwargs):
        values = dict(root=self.root, base_sha=self.base, head_sha=self.head,
                      repository=REPOSITORY, manifest=self.manifest)
        values.update(kwargs)
        return load_guard(self).classify_configuration(**values)


class ConfigurationUnitTests(unittest.TestCase):
    def test_unknown_repository_has_no_approval(self):
        guard = load_guard(self)
        self.assertIsNone(guard.approved_files({'schema_version': 1, 'repositories': {}}, REPOSITORY))

    def test_exact_allowed_control_paths_and_blob_transitions(self):
        guard = load_guard(self)
        files = {CONTROL: {'before': None, 'after': 'a'*40},
                 'CLAUDE.md': {'before': 'b'*40, 'after': 'c'*40}}
        self.assertEqual(guard.approved_files({'schema_version': 1, 'repositories': {REPOSITORY: files}}, REPOSITORY), files)

    def test_invalid_manifest_schema_and_repository_identity(self):
        guard = load_guard(self)
        for manifest in [None, [], {}, {'schema_version': True, 'repositories': {}},
                         {'schema_version': 2, 'repositories': {}}, {'schema_version': 1, 'repositories': []}]:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                guard.approved_files(manifest, REPOSITORY)
        for repo in ['', '../repo', 'org/..', 'org/repo\n', 'org/repo?x=y']:
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                guard.approved_files({'schema_version': 1, 'repositories': {}}, repo)

    def test_source_tests_aliases_and_arbitrary_workflows_cannot_be_approved(self):
        guard = load_guard(self)
        for path in ['source.py', 'tests/test_feature.py', '.github/workflows/deploy.yml',
                     '.github/../source.py', '.github/Workflows/feature-tests.yml',
                     '.github/workflows/feature-tests.yml ', 'АGENTS.md', 'agents.md',
                     '/AGENTS.md', 'AGENTS.md\x00', '.github\\workflows\\feature-tests.yml']:
            manifest = {'schema_version': 1, 'repositories': {REPOSITORY: {path: {'before': None, 'after': 'a'*40}}}}
            with self.subTest(path=path), self.assertRaises(ValueError):
                guard.approved_files(manifest, REPOSITORY)

    def test_deletion_noop_or_malformed_blob_cannot_be_approved(self):
        guard = load_guard(self)
        for change in [None, {}, {'before': None, 'after': None}, {'before': 'a'*40, 'after': 'a'*40},
                       {'before': 'main', 'after': 'b'*40}, {'before': None, 'after': 'b'*39},
                       {'before': None, 'after': 'B'*40}, {'before': None, 'after': 'a'*40, 'mode': '100755'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                guard.approved_files({'schema_version': 1, 'repositories': {REPOSITORY: {CONTROL: change}}}, REPOSITORY)


class ConfigurationGitIntegrationTests(GitFixture, unittest.TestCase):
    def test_accepts_entire_exact_addition_and_modification_from_real_git(self):
        result = self.check()
        self.assertEqual(result['classification'], 'ci_configuration')
        self.assertEqual(result['changed_paths'], [CONTROL, 'AGENTS.md'])
        self.assertEqual(result['head_sha'], self.head)

    def test_worktree_edits_are_not_committed_evidence(self):
        self.write(CONTROL, 'uncommitted attacker text\n')
        self.assertEqual(self.check()['classification'], 'ci_configuration')

    def test_base_branch_advance_uses_actual_merge_base_for_pr_diff(self):
        self.git('checkout', '-q', self.base)
        self.write('independent.py', 'upstream = 1\n')
        advanced_base = self.commit('upstream independent commit')
        self.assertEqual(self.check(base_sha=advanced_base)['classification'], 'ci_configuration')


class ConfigurationSecurityTests(GitFixture, unittest.TestCase):
    def test_ambient_git_overrides_and_external_diff_cannot_execute(self):
        marker = self.directory/'not-executed'
        command = self.directory/'hostile-diff'
        command.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\n')
        command.chmod(0o755)
        self.git('config', 'diff.external', str(command))
        with patch.dict(os.environ, {'GIT_DIR': '/unavailable', 'GIT_WORK_TREE': '/unavailable',
                                     'GIT_EXTERNAL_DIFF': str(command)}):
            self.assertEqual(self.check()['classification'], 'ci_configuration')
        self.assertFalse(marker.exists())

    def test_gitlink_cannot_use_approved_path(self):
        self.git('update-index', '--cacheinfo', '160000,'+self.base+','+CONTROL)
        self.git('commit', '-q', '--no-gpg-sign', '-m', 'hostile gitlink')
        self.assertIsNone(self.check(head_sha=self.git('rev-parse', 'HEAD')))

    def test_deleted_and_readded_executable_control_is_not_regular_modification(self):
        self.git('checkout', '-q', self.base)
        (self.root/'AGENTS.md').chmod(0o755)
        old = self.commit('old executable control')
        self.write(CONTROL, 'name: reviewed workflow\n')
        self.write('AGENTS.md', 'Existing instructions\nMandatory real tests\n')
        (self.root/'AGENTS.md').chmod(0o644)
        self.assertIsNone(self.check(base_sha=old, head_sha=self.commit('new regular control')))

    def test_other_repo_cannot_replay_approved_blobs(self):
        self.assertIsNone(self.check(repository='attacker/other'))

    def test_one_byte_changed_workflow_cannot_use_approval(self):
        self.write(CONTROL, 'name: reviewed workflow!\n')
        self.assertIsNone(self.check(head_sha=self.commit('altered')))

    def test_extra_source_file_cannot_use_approval(self):
        self.write('source.py', 'value = 2\n')
        self.assertIsNone(self.check(head_sha=self.commit('source mutation')))

    def test_missing_control_file_cannot_use_partial_approval(self):
        (self.root/CONTROL).unlink()
        self.assertIsNone(self.check(head_sha=self.commit('missing control')))

    def test_stale_before_blob_cannot_use_approval(self):
        self.manifest['repositories'][REPOSITORY]['AGENTS.md']['before'] = 'f'*40
        self.assertIsNone(self.check())

    def test_executable_mode_cannot_use_approval(self):
        (self.root/CONTROL).chmod(0o755)
        self.assertIsNone(self.check(head_sha=self.commit('executable workflow')))

    def test_symlink_with_approved_blob_content_cannot_use_approval(self):
        (self.root/CONTROL).unlink()
        (self.root/CONTROL).symlink_to('name: reviewed workflow\n')
        self.assertIsNone(self.check(head_sha=self.commit('symlink control')))

    def test_renamed_control_and_deleted_existing_file_cannot_use_approval(self):
        self.git('mv', CONTROL, '.github/workflows/other.yml')
        (self.root/'source.py').unlink()
        self.assertIsNone(self.check(head_sha=self.commit('rename and deletion')))

    def test_candidate_manifest_cannot_approve_extra_source_change(self):
        self.write('ci-configurations.json', json.dumps(self.manifest))
        self.assertIsNone(self.check(head_sha=self.commit('candidate forged manifest')))

    def test_blob_or_symbolic_revision_is_not_a_commit(self):
        for value in ['HEAD', 'main', self.before, 'a'*40, '--help']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(head_sha=value)

    def test_symlink_or_nested_repository_root_is_not_accepted(self):
        alias = self.directory/'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for root in [alias, self.root/'.github']:
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.check(root=root)

    def test_empty_or_unrelated_history_cannot_use_approval(self):
        self.assertIsNone(self.check(head_sha=self.base))
        self.git('checkout', '--orphan', 'unrelated')
        other = self.commit('unrelated')
        with self.assertRaises(ValueError):
            self.check(head_sha=other)


class ConfigurationEntrySecurityTests(GitFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        profile = {kind: {'command': ['never-run'], 'report': kind+'.xml'} for kind in entry.CATEGORIES}
        profile.update(runner='ubuntu-24.04', python_version='3.12', test_paths=PATTERNS)
        (self.directory/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {REPOSITORY: profile}}))
        (self.directory/'ci-configurations.json').write_text(json.dumps(self.manifest))
        self.reports = self.directory/'reports'
        self.reports.mkdir()
        for kind in entry.CATEGORIES:
            (self.reports/(kind+'.xml')).write_text('<testsuite><testcase name="executed"/></testsuite>')

    def verify(self, head=None):
        head = head or self.head
        pull = {'number': 7, 'state': 'open', 'body': '', 'head': {'sha': head},
                'base': {'sha': self.base, 'repo': {'full_name': REPOSITORY}}}
        env = {'QUALITY_REPOSITORY': REPOSITORY, 'QUALITY_PR_NUMBER': '7', 'QUALITY_BASE_SHA': self.base,
               'QUALITY_HEAD_SHA': head, 'QUALITY_EVENT_NAME': 'pull_request'}
        out, err = io.StringIO(), io.StringIO()
        with patch.object(entry, 'HERE', self.directory), patch.object(entry, '_fetch', return_value=pull), patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = entry.main(['--mode', 'verify', '--root', str(self.root), '--reports', str(self.reports)])
        return result, out.getvalue(), err.getvalue()

    def test_exact_configuration_requires_real_reports_without_new_feature_declarations(self):
        result, out, err = self.verify()
        self.assertEqual(result, 0, err)
        self.assertEqual(json.loads(out)['classification'], 'ci_configuration')
        self.assertEqual(json.loads(out)['executed'], {kind: 1 for kind in entry.CATEGORIES})

    def test_missing_or_failed_security_report_still_blocks(self):
        path = self.reports/'security.xml'
        path.unlink()
        self.assertNotEqual(self.verify()[0], 0)
        path.write_text('<testsuite><testcase name="bad"><failure/></testcase></testsuite>')
        self.assertNotEqual(self.verify()[0], 0)

    def test_forged_classification_cannot_bypass_clean_git_recheck(self):
        (self.reports/'classification.json').write_text('{"classification":"ci_configuration"}')
        self.write('source.py', 'value = 2\n')
        self.assertNotEqual(self.verify(self.commit('source mutation'))[0], 0)

    def test_manifest_never_supplies_an_unapproved_execution_profile(self):
        (self.directory/'profiles.json').write_text('{"schema_version":1,"repositories":{}}')
        self.assertNotEqual(self.verify()[0], 0)

    def test_required_run_executes_all_three_real_subprocesses_and_publishes_reports(self):
        policy = Path(entry.__file__).resolve().parent
        for filename in ['run_suite.py', 'quality_gate.py']:
            shutil.copyfile(policy/filename, self.directory/filename)
        config_path = self.directory/'profiles.json'
        config = json.loads(config_path.read_text())
        for kind in entry.CATEGORIES:
            command = [sys.executable, '-c', 'from pathlib import Path; assert 6*7 == 42; '
                       f'Path("{kind}.xml").write_text(\'<testsuite><testcase name="{kind}"/></testsuite>\')']
            config['repositories'][REPOSITORY][kind]['command'] = command
        config_path.write_text(json.dumps(config))
        output = self.directory/'execution-reports'
        env = {'QUALITY_REPOSITORY': REPOSITORY, 'QUALITY_BASE_SHA': self.base, 'QUALITY_HEAD_SHA': self.head}
        with patch.object(entry, 'HERE', self.directory), patch.dict(os.environ, env):
            result = entry.main(['--mode', 'run', '--root', str(self.root), '--reports', str(output)])
        self.assertEqual(result, 0)
        self.assertEqual(sorted(p.name for p in output.glob('*.xml')), ['integration.xml', 'security.xml', 'unit.xml'])


if __name__ == '__main__':
    unittest.main()
