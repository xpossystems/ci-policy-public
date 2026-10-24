"""TDD unit and real CLI integration contracts for visibility-scoped rulesets."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import protection

SHA = hashlib.sha1(b'reviewed visibility policy fixture').hexdigest()


class VisibilityContractTests(unittest.TestCase):
    def payload(self, **overrides):
        args = dict(scope='organization', owner='xpossystems',
                    source_repository_id=123456, source_ref=SHA)
        return protection.generate_ruleset(**dict(args, **overrides))

    def test_visibility_uses_exact_system_property_without_conflicting_name_filter(self):
        baseline = self.payload()
        for visibility in ('public', 'private', 'internal'):
            with self.subTest(visibility=visibility):
                payload = self.payload(visibility=visibility)
                self.assertEqual(set(payload['conditions']), {'repository_property', 'ref_name'})
                self.assertEqual(payload['conditions']['repository_property'], {
                    'include': [{'name': 'visibility', 'source': 'system', 'property_values': [visibility]}],
                    'exclude': [],
                })
                self.assertEqual(payload['conditions']['ref_name'], baseline['conditions']['ref_name'])
                for name in ('rules', 'enforcement', 'bypass_actors', 'target'):
                    self.assertEqual(payload[name], baseline[name])

    def test_omission_preserves_existing_all_repository_behavior(self):
        self.assertEqual(self.payload(), self.payload(visibility=None))
        self.assertEqual(self.payload()['conditions']['repository_name'],
                         {'include': ['~ALL'], 'exclude': [], 'protected': True})

    def test_rejects_invalid_or_ambiguous_values(self):
        for visibility in ('', 'Public', '*', '~ALL', 'private,public', 'private ',
                           ['public'], {}, True, 1, 3.5):
            with self.subTest(visibility=visibility), self.assertRaises(ValueError):
                self.payload(visibility=visibility)

    def test_visibility_cannot_be_used_for_repository_scope(self):
        for owner in ('Rocky-Xpos', 'xpossystems'):
            for visibility in ('public', 'private', 'internal'):
                with self.subTest(owner=owner, visibility=visibility), self.assertRaises(ValueError):
                    self.payload(scope='repository', owner=owner, visibility=visibility)

    def test_mutation_does_not_change_later_policy(self):
        first = self.payload(visibility='public')
        first['conditions']['repository_property']['include'][0]['property_values'].append('private')
        first['conditions']['repository_property']['exclude'].append({'name': 'visibility', 'property_values': ['public']})
        second = self.payload(visibility='public')
        self.assertEqual(second['conditions']['repository_property']['include'][0]['property_values'], ['public'])
        self.assertEqual(second['conditions']['repository_property']['exclude'], [])


class VisibilityCliIntegrationTests(unittest.TestCase):
    def run_cli(self, visibility, *, scope='organization', cwd=None, extra=(), env=None):
        return subprocess.run([
            sys.executable, str(ROOT/'protection.py'), '--scope', scope,
            '--source-repository-id', '123456', '--source-ref', SHA,
            '--visibility', visibility, *extra,
        ], capture_output=True, text=True, cwd=cwd, env=env, timeout=10)

    def test_cli_renders_all_visibility_payloads_without_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            for visibility in ('private', 'public', 'internal'):
                result = self.run_cli(visibility, cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
                payload = json.loads(result.stdout)
                self.assertEqual(payload['conditions']['repository_property']['include'],
                                 [{'source': 'system', 'name': 'visibility', 'property_values': [visibility]}])
                self.assertNotIn('repository_name', payload['conditions'])
                self.assertEqual(payload['bypass_actors'], [])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_rejects_personal_scope_and_malformed_values_without_payload(self):
        for visibility, scope in [('public', 'repository'), ('private\n', 'organization'), ('public,private', 'organization')]:
            with self.subTest(visibility=visibility, scope=scope):
                result = self.run_cli(visibility, scope=scope)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_post_implementation_duplicate_filter_cannot_silently_change_targeting(self):
        for extra in (('--visibility', 'private'), ('--visibility', 'public')):
            result = self.run_cli('public', extra=extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')

    def test_post_implementation_injection_and_control_character_inputs_are_data(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/'injected'
            for value in (f'$(touch {marker})', 'public;true', 'public\r\nprivate', 'publіc',
                          'public\\u0000', 'public"],"exclude":[]', '--bypass'):
                with self.subTest(value=value):
                    result = self.run_cli(value, cwd=directory)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')
                    self.assertFalse(marker.exists())

    def test_post_implementation_filter_does_not_accept_bypass_or_leak_credentials(self):
        env = dict(os.environ, GH_TOKEN='LOCAL_VISIBILITY_SECRET_SENTINEL', GITHUB_TOKEN='LOCAL_VISIBILITY_SECRET_SENTINEL')
        for extra in ((), ('--bypass',), ('--disable',), ('--scope', 'repository')):
            result = self.run_cli('public', extra=extra, env=env)
            self.assertNotIn('LOCAL_VISIBILITY_SECRET_SENTINEL', result.stdout+result.stderr)
            if extra:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
            else:
                payload = json.loads(result.stdout)
                self.assertEqual(payload['bypass_actors'], [])
                self.assertEqual(payload['enforcement'], 'active')


if __name__ == '__main__':
    unittest.main()
