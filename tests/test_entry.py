"""Entry-point contract tests, written before entry.py (TDD red: missing module)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import entry


class EntryTests(unittest.TestCase):
    def test_missing_repo_profile_blocks(self):
        with self.assertRaisesRegex(ValueError, 'approved'):
            entry.select_profile({'schema_version': 1, 'repositories': {}}, 'example-org/example-repo')

    def test_incomplete_categories_block(self):
        config = {'schema_version': 1, 'repositories': {'example-org/example-repo': {'runner': 'ubuntu-24.04'}}}
        with self.assertRaises(ValueError):
            entry.select_profile(config, 'example-org/example-repo')

    def test_runner_output_injection_rejected(self):
        profile = {kind: {'command': ['python3', 'test.py'], 'report': kind+'.xml'} for kind in entry.CATEGORIES}
        profile.update(runner='ubuntu-24.04\nmalicious=true', python_version='3.12')
        with self.assertRaises(ValueError):
            entry.select_profile({'schema_version': 1, 'repositories': {'example-org/example-repo': profile}}, 'example-org/example-repo')

    def test_profile_selects_real_runner(self):
        profile = {kind: {'command': ['python3', 'test.py'], 'report': kind+'.xml'} for kind in entry.CATEGORIES}
        profile.update(runner='macos-15', python_version='3.12')
        self.assertEqual(entry.select_profile({'schema_version': 1, 'repositories': {'example-org/example-repo': profile}}, 'example-org/example-repo')['runner'], 'macos-15')

    def test_evidence_requires_exact_single_markers(self):
        for body in ['', '{}', entry.START+'{}', entry.START+'{}'+entry.END+entry.START+'{}'+entry.END]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                entry.extract_evidence(body)

    def test_evidence_is_json_data(self):
        value = {'commands': ['$(touch /tmp/do-not-run)']}
        self.assertEqual(entry.extract_evidence('prefix'+entry.START+json.dumps(value)+entry.END), value)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            entry.extract_evidence(entry.START+'{"a":1,"a":2}'+entry.END)

    def test_evidence_size_bounded(self):
        with self.assertRaises(ValueError):
            entry.extract_evidence(entry.START+' '*100001+entry.END)

    def test_non_pr_event_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'merge_group'):
            entry.verify_event('merge_group')

    def test_replay_identity_not_only_url_presence(self):
        evidence = {'tdd': {'red_commit': 'a'*40, 'green_commit': 'b'*40, 'red_run_url': 'https://github.com/example-org/example-repo/actions/runs/12', 'green_run_url': 'https://github.com/example-org/example-repo/actions/runs/13'}}
        profiles = {'tdd_workflows': {'red': '.github/workflows/test.yml', 'green': '.github/workflows/test.yml'}}
        def fetch(path):
            red = path.endswith('/12')
            return {'repository': {'full_name': 'example-org/example-repo'}, 'head_sha': ('a' if red else 'b')*40, 'path': '.github/workflows/test.yml', 'status': 'completed', 'conclusion': 'failure' if red else 'success', 'run_started_at': '2026-10-23T12:00:00Z' if red else '2026-10-23T12:10:00Z', 'updated_at': '2026-10-23T12:05:00Z' if red else '2026-10-23T12:15:00Z'}
        entry.verify_run_links(evidence, profiles, 'example-org/example-repo', fetch)
        with self.assertRaises(ValueError):
            entry.verify_run_links(evidence, profiles, 'example-org/example-repo', lambda p: dict(fetch(p), head_sha='c'*40))

    def test_replay_wrong_workflow_or_skipped_rejected(self):
        evidence = {'tdd': {'red_commit': 'a'*40, 'green_commit': 'b'*40, 'red_run_url': 'https://github.com/example-org/example-repo/actions/runs/12', 'green_run_url': 'https://github.com/example-org/example-repo/actions/runs/13'}}
        profile = {'tdd_workflows': {'red': '.github/workflows/test.yml', 'green': '.github/workflows/test.yml'}}
        for override in [{'path': '.github/workflows/deploy.yml'}, {'conclusion': 'skipped'}, {'status': 'in_progress'}]:
            def fetch(path):
                return dict({'repository': {'full_name': 'example-org/example-repo'}, 'head_sha': 'a'*40, 'path': '.github/workflows/test.yml', 'status': 'completed', 'conclusion': 'failure'}, **override)
            with self.subTest(override=override), self.assertRaises(ValueError):
                entry.verify_run_links(evidence, profile, 'example-org/example-repo', fetch)

    def test_cli_missing_profile_is_failure(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, str(Path(entry.__file__)), '--mode', 'plan', '--root', root, '--reports', root+'/reports'], env={**os.environ, 'QUALITY_REPOSITORY': 'unknown/repo'}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('approved', result.stderr)

    def test_api_redirect_cannot_forward_authorization(self):
        request = urllib.request.Request('https://api.github.com/repos/example-org/example-repo', headers={'Authorization': 'Bearer fixture'})
        with self.assertRaises(ValueError):
            entry.NoRedirect().redirect_request(request, None, 302, 'redirect', {}, 'https://attacker.invalid/')

    def test_full_regression_failure_blocks_passing_category_baselines(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            candidate = base/'candidate'
            candidate.mkdir()
            profile = {category: {'command': ['python3', 'test.py'], 'report': category+'.xml'} for category in entry.CATEGORIES}
            profile.update(runner='ubuntu-24.04', python_version='3.12', regression_commands=[[sys.executable, '-c', 'raise SystemExit(1)']])
            (base/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {'example-org/example-repo': profile}}))
            with patch.object(entry, 'HERE', base), patch.dict(os.environ, {'QUALITY_REPOSITORY': 'example-org/example-repo'}), patch.object(entry.changed_tests, 'check_changed_tests', return_value={'classification': 'feature'}), patch.object(entry.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                result = entry.main(['--mode', 'run', '--root', str(candidate), '--reports', str(base/'reports')])
            self.assertNotEqual(result, 0)


if __name__ == '__main__':
    unittest.main()
