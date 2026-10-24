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


class DependencyTransportTests(unittest.TestCase):
    """Real Git export and fresh-workspace restoration, with hostile artifacts."""

    def setUp(self):
        import trusted_dependencies
        self.module = trusted_dependencies
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.export_root = self.base/'broker'
        self.export_root.mkdir()
        self.source = self.export_root/'library'
        self.source.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Transport fixture')
        self.git('config', 'core.hooksPath', os.devnull)
        (self.source/'src').mkdir()
        (self.source/'src'/'library.txt').write_text('reviewed source\n')
        (self.source/'run.sh').write_text('#!/bin/sh\nexit 0\n')
        (self.source/'run.sh').chmod(0o755)
        self.git('add', '.')
        self.git('commit', '-qm', 'reviewed source')
        self.sha = self.git('rev-parse', 'HEAD')
        self.profile = {'dependencies': [dict(repository='fixture-org/library', sha=self.sha, path='library')]}
        self.reports = self.base/'export-artifact'
        self.restore_root = self.base/'consumer'
        self.restore_root.mkdir()
        (self.restore_root/'candidate').mkdir()

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        result = subprocess.run(['git', '-C', str(self.source), *args], env=env,
                                text=True, capture_output=True, check=True)
        return result.stdout.strip()

    def export(self):
        return self.module.export_dependencies(root=self.export_root, profile=self.profile,
                                               repository=REPOSITORY, reports=self.reports)

    def restore(self, reports=None):
        return self.module.restore_dependencies(root=self.restore_root, profile=self.profile,
                                                repository=REPOSITORY, reports=reports or self.reports)

    def mutate_archive(self, entries):
        import io
        import tarfile
        with tarfile.open(self.reports/'dependency-1.tar', 'w') as archive:
            for name, kind, data in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.mode = 0o644
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    item.linkname = data
                    archive.addfile(item)
                else:
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
        path = self.reports/'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['dependencies'][0]['archive_sha256'] = hashlib.sha256((self.reports/'dependency-1.tar').read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))

    def test_actual_git_export_artifact_copy_and_fresh_restore_excludes_credentials(self):
        # Untracked and git-local credential material must never cross the boundary.
        (self.source/'untracked-secret').write_text('local sentinel only')
        self.git('config', 'http.https://github.com/.extraheader', 'AUTHORIZATION: sentinel-not-a-token')
        exported = self.export()
        copied = self.base/'downloaded-artifact'
        shutil.copytree(self.reports, copied)
        restored = self.restore(copied)
        self.assertEqual(exported, restored)
        self.assertEqual((self.restore_root/'library/src/library.txt').read_text(), 'reviewed source\n')
        self.assertTrue((self.restore_root/'library/run.sh').stat().st_mode & 0o111)
        self.assertFalse((self.restore_root/'library/.git').exists())
        self.assertFalse((self.restore_root/'library/untracked-secret').exists())
        self.assertNotIn(b'sentinel-not-a-token', (copied/'dependency-1.tar').read_bytes())

    def test_sparse_export_contains_only_exact_reviewed_file(self):
        self.profile['dependencies'][0]['sparse_checkout'] = 'src/library.txt'
        self.export()
        self.restore()
        files = [p.relative_to(self.restore_root/'library').as_posix()
                 for p in (self.restore_root/'library').rglob('*') if p.is_file()]
        self.assertEqual(files, ['src/library.txt'])

    def test_export_rejects_wrong_head_and_tracked_links(self):
        self.profile['dependencies'][0]['sha'] = SHA
        with self.assertRaises(ValueError): self.export()
        self.profile['dependencies'][0]['sha'] = self.sha
        (self.source/'escape').symlink_to('/outside')
        self.git('add', 'escape')
        self.git('commit', '-qm', 'link must not export')
        self.profile['dependencies'][0]['sha'] = self.git('rev-parse', 'HEAD')
        with self.assertRaises(ValueError): self.export()
        self.assertFalse(self.reports.exists())

    def test_hash_and_manifest_mismatch_fail_without_destination(self):
        self.export()
        archive = self.reports/'dependency-1.tar'
        original = archive.read_bytes()
        archive.write_bytes(original+b'tamper')
        with self.assertRaises(ValueError): self.restore()
        archive.write_bytes(original)
        manifest = json.loads((self.reports/'manifest.json').read_text())
        manifest['dependencies'][0]['sha'] = SHA
        (self.reports/'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError): self.restore()
        self.assertFalse((self.restore_root/'library').exists())

    def test_hostile_paths_links_metadata_and_duplicate_entries_are_rejected(self):
        import tarfile
        self.export()
        attacks = [
            [('../escape', tarfile.REGTYPE, b'bad')],
            [('/absolute', tarfile.REGTYPE, b'bad')],
            [('C:/windows', tarfile.REGTYPE, b'bad')],
            [('src\\escape', tarfile.REGTYPE, b'bad')],
            [('.git/config', tarfile.REGTYPE, b'bad')],
            [('a/.GiT/config', tarfile.REGTYPE, b'bad')],
            [('alias', tarfile.SYMTYPE, '../outside')],
            [('alias', tarfile.LNKTYPE, '../outside')],
            [('pipe', tarfile.FIFOTYPE, b'')],
            [('dup', tarfile.REGTYPE, b'a'), ('dup', tarfile.REGTYPE, b'b')],
            [('Case', tarfile.REGTYPE, b'a'), ('case', tarfile.REGTYPE, b'b')],
            [('file', tarfile.REGTYPE, b'a'), ('file/child', tarfile.REGTYPE, b'b')],
        ]
        for entries in attacks:
            with self.subTest(path=entries[0][0]):
                self.mutate_archive(entries)
                with self.assertRaises(ValueError): self.restore()
                self.assertFalse((self.restore_root/'library').exists())

    def test_existing_destination_symlink_report_and_extra_artifact_are_rejected(self):
        self.export()
        (self.restore_root/'library').mkdir()
        with self.assertRaises(ValueError): self.restore()
        (self.restore_root/'library').rmdir()
        extra = self.reports/'unexpected'
        extra.write_text('unreviewed')
        with self.assertRaises(ValueError): self.restore()
        extra.unlink()
        original = self.reports/'dependency-1.tar'
        original.rename(self.base/'outside.tar')
        original.symlink_to(self.base/'outside.tar')
        with self.assertRaises(ValueError): self.restore()

    def test_archive_manifest_and_member_limits_fail_closed(self):
        from unittest.mock import patch
        self.export()
        for name, value in [('MAX_ARCHIVE_BYTES', 1), ('MAX_MEMBERS', 1), ('MAX_FILE_BYTES', 1), ('MAX_MANIFEST_BYTES', 1)]:
            with self.subTest(limit=name), patch.object(self.module, name, value), self.assertRaises(ValueError):
                self.restore()
        self.assertFalse((self.restore_root/'library').exists())

    def test_sparse_scope_cannot_be_expanded_by_a_rehashed_artifact(self):
        import tarfile
        self.profile['dependencies'][0]['sparse_checkout'] = 'src/library.txt'
        self.export()
        self.mutate_archive([('src/library.txt', tarfile.REGTYPE, b'reviewed'), ('extra.txt', tarfile.REGTYPE, b'bad')])
        with self.assertRaises(ValueError): self.restore()
        self.assertFalse((self.restore_root/'library').exists())
