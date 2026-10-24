"""Entry boundary for credential-free dependency transport jobs."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import entry
import trusted_dependencies


class EntryDependencyModesTests(unittest.TestCase):
    def test_each_mode_dispatches_only_approved_profile_and_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            candidate = root/'candidate'
            candidate.mkdir()
            (candidate/'profiles.json').write_text('{"repository":"attacker/override"}')
            profile = {kind: {'command': ['unused'], 'report': kind+'.xml'} for kind in entry.EXECUTION_SUITES}
            profile.update(runner='ubuntu-24.04', python_version='3.12')
            (root/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {'example-org/example-repo': profile}}))
            for mode, name in [('dependencies-export', 'export_dependencies'), ('dependencies-restore', 'restore_dependencies')]:
                output = io.StringIO()
                with self.subTest(mode=mode), patch.object(entry, 'HERE', root), patch.dict(os.environ, {'QUALITY_REPOSITORY': 'example-org/example-repo'}), patch.object(trusted_dependencies, name, create=True, return_value={'status': 'validated'}) as call, contextlib.redirect_stdout(output):
                    code = entry.main(['--mode', mode, '--root', str(root), '--reports', str(root/'reports')])
                self.assertEqual(code, 0)
                call.assert_called_once_with(root=str(root), profile=profile, repository='example-org/example-repo', reports=root/'reports')
                self.assertEqual(json.loads(output.getvalue()), {'status': 'validated'})

    def test_transport_rejection_cannot_become_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            profile = {kind: {'command': ['unused'], 'report': kind+'.xml'} for kind in entry.EXECUTION_SUITES}
            profile.update(runner='ubuntu-24.04', python_version='3.12')
            (root/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {'example-org/example-repo': profile}}))
            err = io.StringIO()
            with patch.object(entry, 'HERE', root), patch.dict(os.environ, {'QUALITY_REPOSITORY': 'example-org/example-repo'}), patch.object(trusted_dependencies, 'restore_dependencies', create=True, side_effect=ValueError('wrong source pin')), contextlib.redirect_stderr(err):
                code = entry.main(['--mode', 'dependencies-restore', '--root', str(root), '--reports', str(root/'reports')])
            self.assertEqual(code, 1)
            self.assertIn('wrong source pin', err.getvalue())
