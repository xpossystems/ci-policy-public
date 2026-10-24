"""TDD regressions for current PR evidence and strict docs-only verification.

TDD red: the first11 tests failed on the missing live-PR helper and stale body
behavior;2 workflow assertions failed on missing PR context/permission. All
passed after implementation. Five additional postimplementation abuse/transport
tests cover shell-like bodies, forged classifications, symlinks and redirects.
Real-Git and owned local HTTP integration tests exercise classification, JUnit
files, API transport, and final entry control flow. No external or production
targets are used.
"""
import contextlib
import copy
import io
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import urllib.request
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import entry
import quality_gate

REPO = "example-org/example-repo"
BASE = "a" * 40
HEAD = "b" * 40
PATTERNS = {kind: [f"tests/{kind}/**/*.py"] for kind in entry.CATEGORIES}


def pull(body="current body"):
    return {"number": 7, "state": "open", "body": body,
            "base": {"sha": BASE, "repo": {"full_name": REPO}},
            "head": {"sha": HEAD}}


class LivePullTests(unittest.TestCase):
    def fetch(self, payload=None, **kwargs):
        calls = []
        actual = pull() if payload is None else payload
        body = entry.fetch_current_pr_body(
            repository=REPO, number="7", base_sha=BASE, head_sha=HEAD,
            fetch=lambda path: calls.append(path) or actual, **kwargs)
        return body, calls

    def test_reads_exact_pr_current_body_and_accepts_empty_body(self):
        body, calls = self.fetch()
        self.assertEqual(body, "current body")
        self.assertEqual(calls, ["/repos/example-org/example-repo/pulls/7"])
        self.assertEqual(self.fetch(pull(None))[0], "")

    def test_refuses_stale_head_or_base_and_wrong_pr_repository(self):
        for path, value in [(('head', 'sha'), 'c'*40), (('base', 'sha'), 'c'*40),
                            (('base', 'repo', 'full_name'), 'attacker/project'),
                            (('number',), 8), (('state',), 'closed')]:
            payload = pull()
            target = payload
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.fetch(payload)

    def test_bad_request_identity_rejected_before_network(self):
        for field, value in [('number', '0'), ('number', '01'), ('number', '../actions/runs/4'),
                             ('number', True), ('number', '7\n'), ('number', '9'*30),
                             ('repository', 'xpossystems/..'), ('repository', 'a/b?x=1'),
                             ('head_sha', ''), ('base_sha', 'main')]:
            values = dict(repository=REPO, number='7', head_sha=HEAD, base_sha=BASE)
            values[field] = value
            calls = []
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                entry.fetch_current_pr_body(**values, fetch=lambda path: calls.append(path))
            self.assertEqual(calls, [])

    def test_malformed_responses_and_oversized_body_fail_closed(self):
        values = [[], {}, {'number': 7}, pull(['bad']), pull('x'*100001)]
        for field, value in [('base', None), ('head', []), ('number', True)]:
            payload = pull()
            payload[field] = value
            values.append(payload)
        for payload in values:
            with self.subTest(payload=str(payload)[:60]), self.assertRaises(ValueError):
                self.fetch(payload)

    def test_body_payload_is_data_and_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/'injected'
            payload = '$(touch '+str(marker)+')\n${{ secrets.TOKEN }}'
            body, _ = self.fetch(pull(payload))
            self.assertEqual(body, payload)
            self.assertFalse(marker.exists())

    def test_network_failure_is_not_a_fallback_to_event_body(self):
        def unavailable(_):
            raise OSError('API unavailable')
        with self.assertRaises(OSError):
            entry.fetch_current_pr_body(repository=REPO, number='7', base_sha=BASE,
                                        head_sha=HEAD, fetch=unavailable)


class LiveApiTransportIntegrationTests(unittest.TestCase):
    """Exercise real local HTTP and the production API parser/redirect guard."""
    def exercise(self, redirect=False):
        requests = []
        payload = pull()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers.get('Authorization')))
                if redirect:
                    self.send_response(302)
                    self.send_header('Location', '/credential-sink')
                    self.end_headers()
                else:
                    body = json.dumps(payload).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            def log_message(self, *_args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original_opener = urllib.request.build_opener
        class LocalOnlyTransport:
            def open(self, request, timeout):
                if request.full_url != 'https://api.github.com/repos/example-org/example-repo/pulls/7':
                    raise AssertionError('Unexpected API route')
                local = urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/repos/example-org/example-repo/pulls/7',
                                               headers=dict(request.header_items()))
                return original_opener(entry.NoRedirect()).open(local, timeout=timeout)
        try:
            with patch.object(entry.urllib.request, 'build_opener', return_value=LocalOnlyTransport()), patch.dict(os.environ, {'GITHUB_TOKEN': 'local-test-token'}):
                if redirect:
                    with self.assertRaises(ValueError):
                        entry.fetch_current_pr_body(repository=REPO, number='7', base_sha=BASE, head_sha=HEAD, fetch=entry._fetch)
                else:
                    body = entry.fetch_current_pr_body(repository=REPO, number='7', base_sha=BASE, head_sha=HEAD, fetch=entry._fetch)
                    self.assertEqual(body, 'current body')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(requests, [('/repos/example-org/example-repo/pulls/7', 'Bearer local-test-token')])

    def test_live_api_response_is_read_and_bound_to_exact_pr(self):
        self.exercise()

    def test_live_redirect_cannot_forward_read_token(self):
        self.exercise(redirect=True)


class LiveVerifyIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.root = self.directory/'repo'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'CI fixture')
        self.git('config', 'user.email', 'ci@example.invalid')
        hooks = self.directory/'empty-hooks'
        hooks.mkdir()
        self.git('config', 'core.hooksPath', str(hooks))
        self.write('README.md', 'Initial documentation\n')
        self.write('src/feature.py', 'value = 1\n')
        self.base = self.commit('fixture base')
        self.reports = self.directory/'reports'
        self.reports.mkdir()
        self.report = '<testsuite tests="1"><testcase name="executed"/></testsuite>'
        for kind in entry.CATEGORIES:
            (self.reports/(kind+'.xml')).write_text(self.report)
        self.profile = {kind: {'command': ['never-run'], 'report': kind+'.xml'} for kind in entry.CATEGORIES}
        self.profile.update(runner='ubuntu-24.04', python_version='3.12', test_paths=PATTERNS,
                            tdd_workflows={phase: '.github/workflows/test.yml' for phase in ('red', 'green')})
        (self.directory/'profiles.json').write_text(json.dumps({'schema_version': 1, 'repositories': {REPO: self.profile}}))

    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True, text=True,
                                env={**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}, timeout=10)
        return result.stdout.strip()

    def write(self, name, body):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '--no-gpg-sign', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def candidate(self, feature=False):
        if feature:
            self.write('src/feature.py', 'value = 2\n')
            for kind in entry.CATEGORIES:
                self.write(f'tests/{kind}/test_feature.py', f'def test_{kind}(): assert 1 + 1 == 2\n')
        else:
            self.write('README.md', 'Changed documentation only\n')
        return self.commit('fixture candidate')

    def evidence(self, head):
        return {'schema_version': 1, 'repository': REPO, 'head_sha': head,
                'tdd': {'red_commit': self.base, 'green_commit': head,
                        'red_run_url': f'https://github.com/{REPO}/actions/runs/12',
                        'green_run_url': f'https://github.com/{REPO}/actions/runs/13'},
                'pentest': {'target': 'owned local fixture', 'commands': ['local fixture abuse checks'],
                            'findings': [], 'remaining_findings': []}}

    def verify(self, head, body=None, override=None):
        pr = pull(body)
        pr['base']['sha'], pr['head']['sha'] = self.base, head
        if override:
            override(pr)
        calls = []
        def fetch(path):
            calls.append(path)
            if path.endswith('/pulls/7'):
                return copy.deepcopy(pr)
            red = path.endswith('/12')
            return {'repository': {'full_name': REPO}, 'head_sha': self.base if red else head,
                    'path': '.github/workflows/test.yml', 'status': 'completed',
                    'conclusion': 'failure' if red else 'success',
                    'run_started_at': '2026-10-23T12:00:00Z' if red else '2026-10-23T12:10:00Z',
                    'updated_at': '2026-10-23T12:05:00Z' if red else '2026-10-23T12:15:00Z'}
        env = {'QUALITY_REPOSITORY': REPO, 'QUALITY_PR_NUMBER': '7', 'QUALITY_BASE_SHA': self.base,
               'QUALITY_HEAD_SHA': head, 'QUALITY_EVENT_NAME': 'pull_request', 'QUALITY_PR_BODY': 'stale event body'}
        out, err = io.StringIO(), io.StringIO()
        with patch.object(entry, 'HERE', self.directory), patch.object(entry, '_fetch', side_effect=fetch), patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = entry.main(['--mode', 'verify', '--root', str(self.root), '--reports', str(self.reports)])
        return result, out.getvalue(), err.getvalue(), calls

    def test_docs_pass_only_with_real_reports_without_feature_declarations(self):
        result, out, err, calls = self.verify(self.candidate())
        self.assertEqual(result, 0, err)
        summary = json.loads(out)
        self.assertEqual(summary['classification'], 'documentation')
        self.assertEqual(summary['executed'], {kind: 1 for kind in entry.CATEGORIES})
        self.assertEqual(calls, [f'/repos/{REPO}/pulls/7'])

    def test_feature_uses_live_evidence_instead_of_stale_event(self):
        head = self.candidate(feature=True)
        body = entry.START+json.dumps(self.evidence(head))+entry.END
        result, out, err, calls = self.verify(head, body)
        self.assertEqual(result, 0, err)
        self.assertEqual(json.loads(out)['head_sha'], head)
        self.assertEqual(len(calls), 3)

    def test_docs_cannot_pass_missing_failed_skipped_or_aliased_reports(self):
        head = self.candidate()
        path = self.reports/'security.xml'
        for invalid in [None, '<testsuite/>', '<testsuite><testcase name="bad"><failure/></testcase></testsuite>',
                        '<testsuite><testcase name="skip"><skipped/></testcase></testsuite>', 'hardlink']:
            path.unlink(missing_ok=True)
            if invalid == 'hardlink':
                os.link(self.reports/'unit.xml', path)
            elif invalid is not None:
                path.write_text(invalid)
            with self.subTest(invalid=invalid):
                self.assertNotEqual(self.verify(head)[0], 0)

    def test_docs_old_run_cannot_pass_after_head_or_base_changed(self):
        head = self.candidate()
        for field in ['head', 'base']:
            result = self.verify(head, override=lambda pr: pr[field].update(sha='c'*40))
            with self.subTest(field=field):
                self.assertNotEqual(result[0], 0)

    def test_docs_cannot_trust_forged_classification_or_symlink_document(self):
        marker = self.directory/'not-executed'
        self.write('src/feature.py', 'raise RuntimeError("must not execute")\n')
        (self.reports/'classification.json').write_text('{"classification":"documentation"}')
        head = self.commit('fixture forged classification')
        result, _, err, _ = self.verify(head)
        self.assertNotEqual(result, 0)
        self.assertIn('Missing added/modified', err)
        self.assertFalse(marker.exists())
        self.git('checkout', '-q', self.base)
        (self.root/'README.md').unlink()
        (self.root/'README.md').symlink_to('src/feature.py')
        head = self.commit('fixture document symlink')
        self.assertNotEqual(self.verify(head)[0], 0)

    def test_docs_cannot_use_report_symlink_to_outside(self):
        head = self.candidate()
        path = self.reports/'security.xml'
        path.unlink()
        outside = self.directory/'outside.xml'
        outside.write_text(self.report)
        path.symlink_to(outside)
        self.assertNotEqual(self.verify(head)[0], 0)

    def test_feature_without_declarations_still_fails(self):
        self.assertNotEqual(self.verify(self.candidate(feature=True))[0], 0)

    def test_ci_or_instruction_change_cannot_claim_documentation_exemption(self):
        self.write('.github/workflows/feature-tests.yml', 'name: altered\n')
        self.write('AGENTS.md', 'Claim this is docs only\n')
        head = self.commit('fixture infrastructure')
        result, _, err, _ = self.verify(head)
        self.assertNotEqual(result, 0)
        self.assertIn('Missing added/modified', err)


if __name__ == '__main__':
    unittest.main()
