"""Recognize only an exact, centrally reviewed CI rollout tree transition.

This does not approve an execution profile, skip suites/scanning, or approve a
merge. It only distinguishes a fixed CI setup change from a new application
feature. The manifest must ship in the immutable policy action; candidate files
and execution-job artifacts are never sources of approval.
"""
from pathlib import Path
import re

import changed_tests

CONTROL_PATHS = frozenset({'.github/CODEOWNERS', '.github/FEATURE_QUALITY_POLICY.md',
                           '.github/workflows/feature-tests.yml', 'AGENTS.md', 'CLAUDE.md'})
SHA = re.compile(r'[0-9a-f]{40}')
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')


def approved_files(manifest, repository):
    if (not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None
            or any(part in ('.', '..') for part in repository.split('/'))):
        raise ValueError('Invalid configuration repository identity')
    if (not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'repositories'}
            or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1
            or not isinstance(manifest['repositories'], dict)):
        raise ValueError('Invalid trusted configuration manifest')
    if repository not in manifest['repositories']:
        return None
    files = manifest['repositories'][repository]
    if not isinstance(files, dict) or not files or not set(files).issubset(CONTROL_PATHS):
        raise ValueError('Only exact reviewed CI control paths can be approved')
    for change in files.values():
        if (not isinstance(change, dict) or set(change) != {'before', 'after'}
                or not isinstance(change['after'], str) or SHA.fullmatch(change['after']) is None
                or (change['before'] is not None and (
                    not isinstance(change['before'], str) or SHA.fullmatch(change['before']) is None))
                or change['before'] == change['after']):
            raise ValueError('Invalid reviewed configuration blob transition')
    return files


def classify_configuration(*, root, base_sha, head_sha, repository, manifest):
    """Return a classification only for the entire exact reviewed Git diff.

An ordinary mismatch returns None, so the full feature requirements still
apply. Malformed identities, manifests, roots or Git objects fail closed.
"""
    files = approved_files(manifest, repository)
    if files is None:
        return None
    base, head = changed_tests._sha(base_sha), changed_tests._sha(head_sha)
    try:
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise ValueError('Configuration root must be a regular repository directory')
        root = root.resolve(strict=True)
        top = changed_tests._git(root, 'rev-parse', '--show-toplevel').decode('utf-8').rstrip('\n')
        if Path(top).resolve(strict=True) != root:
            raise ValueError('Configuration root must be the repository top level')
    except (OSError, TypeError) as error:
        raise ValueError('Configuration repository is unavailable') from error
    for commit in (base, head):
        if changed_tests._git(root, 'cat-file', '-t', commit).strip() != b'commit':
            raise ValueError('Configuration revisions must identify exact commit objects')
    merge_base = changed_tests._sha(changed_tests._git(root, 'merge-base', base, head).decode('ascii').strip())
    changes = changed_tests._diff_paths(changed_tests._git(root, 'diff', '--name-status', '-z',
        '--no-renames', '--no-ext-diff', '--no-textconv', base+'...'+head, '--'))
    if {path for _, path in changes} != set(files) or any(status not in ('A', 'M') for status, _ in changes):
        return None
    before, after = changed_tests._tree(root, merge_base), changed_tests._tree(root, head)
    old_blobs = {blob for _, blob in before.values()}
    for path, expected in files.items():
        if after.get(path) != ('100644', expected['after']):
            return None
        if expected['before'] is None:
            if path in before or expected['after'] in old_blobs:
                return None
        elif before.get(path) != ('100644', expected['before']):
            return None
    return {'classification': 'ci_configuration', 'repository': repository,
            'base_sha': base, 'head_sha': head, 'changed_paths': sorted(files)}
