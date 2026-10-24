#!/usr/bin/env python3
"""Trusted composite-action entry point. Unknown repositories fail closed.

Profiles ship with the pinned action, not the candidate PR. Candidate code runs
only in the run job. Verification runs in a fresh job with read-only API access.
Run identity/status checks support review; they do not prove test relevance.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

import quality_gate
import run_suite
import changed_tests

CATEGORIES = ('unit', 'integration', 'security')
START = '<!-- ci-evidence:start -->'
END = '<!-- ci-evidence:end -->'
HERE = Path(__file__).resolve().parent


def select_profile(config, repository):
    if config.get('schema_version') != 1 or repository not in config.get('repositories', {}):
        raise ValueError('No approved execution profile for this repository; missing tests cannot pass')
    profile = config['repositories'][repository]
    if not isinstance(profile, dict):
        raise ValueError('Invalid approved profile')
    if profile.get('runner') not in ('ubuntu-24.04', 'macos-15', 'windows-2025'):
        raise ValueError('Unapproved runner')
    if not re.fullmatch(r'3\.(10|11|12|13)', str(profile.get('python_version', ''))):
        raise ValueError('Unapproved Python version')
    if profile.get('kind') == 'artifact_data':
        if (profile.get('repository') != repository
                or not isinstance(profile.get('allowed_patterns'), list)
                or not profile['allowed_patterns']
                or not isinstance(profile.get('control_sha256'), dict)
                or any(key in profile for key in (*CATEGORIES, 'prepare', 'regression_commands', 'test_paths', 'tdd_workflows'))):
            raise ValueError('Invalid repository-bound data profile; executable suites are forbidden')
        return profile
    if profile.get('kind', 'feature') != 'feature':
        raise ValueError('Unknown approved profile kind')
    for category in CATEGORIES:
        suite = profile.get(category)
        if not isinstance(suite, dict) or not suite.get('command') or not suite.get('report'):
            raise ValueError('Missing approved '+category+' suite')
    return profile


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate evidence key')
        result[key] = value
    return result


def extract_evidence(body):
    if not isinstance(body, str) or len(body) > 100000:
        raise ValueError('Evidence body missing or oversized')
    if body.count(START) != 1 or body.count(END) != 1:
        raise ValueError('PR body must contain exactly one CI evidence block')
    start = body.index(START)+len(START)
    end = body.index(END)
    if start >= end:
        raise ValueError('Invalid evidence block order')
    value = json.loads(body[start:end].strip(), object_pairs_hook=_object)
    if not isinstance(value, dict):
        raise ValueError('Evidence must be a JSON object')
    return value


def verify_event(event_name):
    if event_name != 'pull_request':
        raise ValueError('Unsupported evidence association for '+event_name+'; merge_group must remain blocked until each PR evidence is verified')


def fetch_current_pr_body(*, repository, number, base_sha, head_sha, fetch):
    """Read current evidence only while the PR still identifies the tested diff.

    Ruleset workflows ignore ``edited`` activity filters, and reruns retain the
    original event. Fetching the live body makes evidence edits usable without
    accepting a successful rerun for a newer, untested revision.
    """
    if (not isinstance(repository, str)
            or quality_gate.REPOSITORY_PATTERN.fullmatch(repository) is None
            or repository.split('/', 1)[1] in ('.', '..')
            or not isinstance(number, str)
            or re.fullmatch(r'[1-9][0-9]{0,18}', number) is None):
        raise ValueError('Invalid pull request identity')
    for sha in (base_sha, head_sha):
        if not isinstance(sha, str) or quality_gate.SHA_PATTERN.fullmatch(sha) is None:
            raise ValueError('Pull request verification requires full base and head SHAs')
    pull = fetch('/repos/'+repository+'/pulls/'+number)
    if not isinstance(pull, dict):
        raise ValueError('Invalid pull request response')
    base, head = pull.get('base'), pull.get('head')
    if (type(pull.get('number')) is not int or pull['number'] != int(number)
            or pull.get('state') != 'open'
            or not isinstance(base, dict) or not isinstance(head, dict)
            or not isinstance(base.get('repo'), dict)
            or base['repo'].get('full_name') != repository
            or base.get('sha') != base_sha or head.get('sha') != head_sha):
        raise ValueError('Pull request identity, base, or head changed; run checks for the current revision')
    body = pull.get('body')
    if body is None:
        body = ''
    if not isinstance(body, str) or len(body) > 100000:
        raise ValueError('Evidence body missing or oversized')
    return body


def verify_run_links(evidence, profile, repository, fetch):
    paths = profile.get('tdd_workflows', {})
    chronology = {}
    for phase, conclusion in [('red', 'failure'), ('green', 'success')]:
        expected_path = paths.get(phase)
        if not isinstance(expected_path, str) or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml', expected_path):
            raise ValueError('Missing approved TDD workflow path')
        url = evidence['tdd'][phase+'_run_url']
        match = re.fullmatch(r'https://github\.com/'+re.escape(repository)+r'/actions/runs/([1-9][0-9]*)', url)
        if match is None:
            raise ValueError('TDD run URL does not belong to this repository')
        run = fetch('/repos/'+repository+'/actions/runs/'+match.group(1))
        if (run.get('repository', {}).get('full_name') != repository
                or run.get('head_sha') != evidence['tdd'][phase+'_commit']
                or run.get('path') != expected_path
                or run.get('status') != 'completed'
                or run.get('conclusion') != conclusion):
            raise ValueError('TDD '+phase+' run identity or result is invalid')
        try:
            started = datetime.strptime(run['run_started_at'], '%Y-%m-%dT%H:%M:%SZ')
            finished = datetime.strptime(run['updated_at'], '%Y-%m-%dT%H:%M:%SZ')
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError('TDD run chronology is missing or invalid') from error
        if started > finished:
            raise ValueError('TDD run chronology is invalid')
        chronology[phase] = (started, finished)
    if chronology['red'][1] >= chronology['green'][0]:
        raise ValueError('TDD red run must finish before the green run starts')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('GitHub API redirects are refused to protect credentials')


def _fetch(path):
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        raise ValueError('Read-only GitHub token required for run verification')
    request = urllib.request.Request('https://api.github.com'+path, headers={
        'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    })
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        payload = response.read(5*1024*1024+1)
    if len(payload) > 5*1024*1024:
        raise ValueError('GitHub response too large')
    return json.loads(payload)


def artifact_summary(root, commit, repository, profile):
    # Public distribution deliberately omits this private corpus adapter. Only
    # an explicitly bound profile in the pinned private policy can activate it.
    import artifact_data
    return artifact_data.validate_artifact_tree(root, commit, repository, profile)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--mode', required=True, choices=['plan', 'baseline', 'run', 'verify'])
    parser.add_argument('--root', required=True)
    parser.add_argument('--reports', required=True)
    args = parser.parse_args(argv)
    try:
        repository = os.environ.get('QUALITY_REPOSITORY', '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('Repository identity is missing')
        config = json.loads((HERE/'profiles.json').read_text())
        profile = select_profile(config, repository)
        if args.mode == 'plan':
            output = os.environ.get('GITHUB_OUTPUT')
            if not output:
                raise ValueError('GITHUB_OUTPUT is required')
            with open(output, 'a') as stream:
                stream.write('runner='+profile['runner']+'\npython_version='+profile['python_version']+'\n')
            return 0
        reports = Path(args.reports)
        if not reports.is_absolute() or any(p.is_symlink() for p in [reports, *reports.parents]):
            raise ValueError('Report directory must be absolute without symlinks')
        if args.mode in ('baseline', 'run'):
            root = Path(args.root).resolve(strict=True)
            if profile.get('kind') == 'artifact_data':
                if reports == root or root in reports.parents:
                    raise ValueError('Artifact summary must be outside the candidate repository')
                result = artifact_summary(root, os.environ.get('QUALITY_HEAD_SHA', ''), repository, profile)
                reports.mkdir(parents=True, exist_ok=True)
                with (reports/'artifact-data.json').open('x') as output:
                    json.dump(result, output, sort_keys=True)
                print(json.dumps(result, sort_keys=True))
                return 0
            # Baseline supplies honest red/green execution during development;
            # only the separate required workflow can grant merge approval.
            if args.mode == 'run':
                changed_tests.check_changed_tests(
                    args.root,
                    os.environ.get('QUALITY_BASE_SHA', ''),
                    os.environ.get('QUALITY_HEAD_SHA', ''),
                    profile.get('test_paths'),
                )
            reports.mkdir(parents=True, exist_ok=True)
            for command in profile.get('prepare', []):
                if not isinstance(command, list) or not command or not all(isinstance(v, str) and v for v in command):
                    raise ValueError('Invalid approved setup command')
                run_suite._execute(command, root, 1200)
            for category in CATEGORIES:
                subprocess.run([sys.executable, str(HERE/'run_suite.py'), '--repository', repository,
                    '--category', category, '--root', str(root), '--profiles', str(HERE/'profiles.json'),
                    '--output', str(reports/(category+'.xml'))], check=True, timeout=3600)
            for command in profile.get('regression_commands', []):
                if not isinstance(command, list) or not command or not all(isinstance(v, str) and v for v in command):
                    raise ValueError('Invalid approved full-regression command')
                run_suite._execute(command, root, 3600)
            return 0
        verify_event(os.environ.get('QUALITY_EVENT_NAME', ''))
        head_sha, base_sha = os.environ.get('QUALITY_HEAD_SHA', ''), os.environ.get('QUALITY_BASE_SHA', '')
        body = fetch_current_pr_body(repository=repository,
            number=os.environ.get('QUALITY_PR_NUMBER', ''), base_sha=base_sha,
            head_sha=head_sha, fetch=_fetch)
        if profile.get('kind') == 'artifact_data':
            result = artifact_summary(args.root, head_sha, repository, profile)
            raw, _identity = quality_gate._read_file(reports/'artifact-data.json', 'artifact summary')
            recorded = json.loads(raw, object_pairs_hook=_object)
            if recorded != result:
                raise ValueError('Artifact summary does not match the independently verified candidate tree')
            print(json.dumps(result, sort_keys=True))
            return 0
        # Recompute from the clean verifier checkout. Never trust a classification
        # artifact produced in the job that executed candidate test code.
        change = changed_tests.check_changed_tests(args.root, base_sha, head_sha, profile.get('test_paths'))
        if change['classification'] == 'documentation':
            counts = quality_gate.validate_reports(unit_report=reports/'unit.xml',
                integration_report=reports/'integration.xml', security_report=reports/'security.xml')
            print(json.dumps({'status': 'validated', 'classification': 'documentation',
                'repository': repository, 'head_sha': head_sha, 'executed': counts,
                'feature_declarations_required': False}, sort_keys=True))
            return 0
        evidence = extract_evidence(body)
        with tempfile.TemporaryDirectory() as temporary:
            evidence_path = Path(temporary)/'evidence.json'
            evidence_path.write_text(json.dumps(evidence))
            result = quality_gate.validate(unit_report=reports/'unit.xml', integration_report=reports/'integration.xml',
                security_report=reports/'security.xml', evidence=evidence_path,
                head_sha=head_sha, repository=repository)
        verify_run_links(evidence, profile, repository, _fetch)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        # Never print the untrusted PR body or credentials on rejection.
        print('Feature quality blocked: '+str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
