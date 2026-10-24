"""Trusted dependency planning, actual plan-process boundary, and abuse tests."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHA = hashlib.sha1(b'reviewed dependency fixture').hexdigest()
REPOSITORY = 'fixture-org/application'


def dependency(**overrides):
    return dict(repository='fixture-org/library', sha=SHA, path='library', **overrides)


class DependencyUnitTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('trusted_dependencies', ROOT/'trusted_dependencies.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_no_dependencies_produces_two_empty_output_slots(self):
        result = self.module.checkout_outputs({}, REPOSITORY)
        self.assertEqual(result, {f'dependency_{slot}_{field}': '' for slot in (1, 2)
                                 for field in ('repository', 'sha', 'path', 'sparse_checkout')})

    def test_full_and_sparse_checkout_preserve_exact_pins(self):
        second = dict(repository='fixture-org/contract', sha=SHA, path='contract',
                      sparse_checkout='lib/models/permission.dart')
        profile = {'dependencies': [dependency(), second]}
        original = copy.deepcopy(profile)
        result = self.module.checkout_outputs(profile, REPOSITORY)
        self.assertEqual(result['dependency_1_sha'], SHA)
        self.assertEqual(result['dependency_1_sparse_checkout'], '')
        self.assertEqual(result['dependency_2_sparse_checkout'], 'lib/models/permission.dart')
        self.assertEqual(profile, original)

    def test_invalid_schema_and_unknown_fields_fail_closed(self):
        for value in (None, {}, 'library', [None], [dict(dependency(), token='secret')],
                      [dependency(), dependency(), dependency()]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.module.checkout_outputs({'dependencies': value}, REPOSITORY)


class DependencySecurityTests(unittest.TestCase):
    setUp = DependencyUnitTests.setUp

    def test_refs_output_injection_and_untrusted_owners_are_rejected(self):
        for field, values in {
            'repository': ['other-org/library', REPOSITORY, 'fixture-org/../library',
                           'fixture-org/library\nrunner=evil', 'fixture-org/library.git', '${{ secrets.TOKEN }}'],
            'sha': ['main', '0'*40, 'deadbeef'*5, SHA.upper(), SHA+'\n', '${{ github.sha }}'],
            'path': ['candidate', '../library', '/tmp/lib', '.git', 'a/b', 'lib\nrunner=evil',
                     'lib\\x', 'con', 'COM1', 'library.', 'library ', '${{ github.workspace }}'],
            'sparse_checkout': ['../secret', '/tmp/file', '.git/config', 'a/../file',
                                'a//file', '*', 'a\nb', 'a\\b', 'a/./b'],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    item = dependency()
                    item[field] = value
                    self.module.checkout_outputs({'dependencies': [item]}, REPOSITORY)

    def test_duplicate_path_or_repository_is_rejected_case_insensitively(self):
        for second in (dict(dependency(), path='other'),
                       dict(dependency(), repository='fixture-org/other', path='LIBRARY')):
            with self.subTest(second=second), self.assertRaises(ValueError):
                self.module.checkout_outputs({'dependencies': [dependency(), second]}, REPOSITORY)


class DependencyPlanIntegrationTests(unittest.TestCase):
    def run_plan(self, dependencies, candidate_override=False):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            trusted, candidate = base/'trusted', base/'candidate'
            trusted.mkdir()
            candidate.mkdir()
            for source in ROOT.glob('*.py'):
                shutil.copy2(source, trusted/source.name)
            profile = copy.deepcopy(json.loads((ROOT/'profiles.json').read_text())['repositories']['xpossystems/ci-policy-public'])
            profile['dependencies'] = dependencies
            (trusted/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {REPOSITORY: profile}}))
            if candidate_override:
                (candidate/'profiles.json').write_text(json.dumps({'dependencies': [{'repository': 'attacker/leak'}]}))
                (candidate/'trusted_dependencies.py').write_text('raise RuntimeError("candidate injection")')
            result = subprocess.run([sys.executable, str(trusted/'entry.py'), '--mode', 'plan',
                                     '--root', str(candidate), '--reports', str(base/'reports')],
                                    cwd=candidate, env=dict(os.environ, QUALITY_REPOSITORY=REPOSITORY,
                                                          GITHUB_OUTPUT=str(base/'output')),
                                    text=True, capture_output=True, timeout=20)
            output = (base/'output').read_text() if (base/'output').exists() else ''
            return result, output

    def test_real_plan_process_emits_only_trusted_checkout_metadata(self):
        result, output = self.run_plan([dependency()], candidate_override=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(line.split('=', 1) for line in output.splitlines())
        self.assertEqual(fields.get('dependency_1_repository'), 'fixture-org/library')
        self.assertEqual(fields.get('dependency_1_sha'), SHA)
        self.assertNotIn('attacker', output)
        self.assertNotIn('TOKEN', output)

    def test_invalid_dependency_aborts_before_any_workflow_output(self):
        result, output = self.run_plan([dict(dependency(), path='../candidate')])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, '')
