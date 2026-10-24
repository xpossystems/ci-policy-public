"""Require changed test files for each category when a PR changes functionality.

Profiles and test globs must come from the trusted central policy, never from
the candidate PR. This is a structural guard: it cannot prove new assertions
test the feature. Runtime tests, TDD evidence, and independent review remain
mandatory. Documentation classification only exempts this changed-files guard;
it must never skip the unit, integration, or security execution jobs.

All Git calls use argument arrays, exact commit IDs, NUL-delimited filenames,
and disabled external diff/textconv programs. Modes are read from commit trees
so symlinks and submodules cannot masquerade as regular test files.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from pathlib import Path
import re
import subprocess


CATEGORIES = ("unit", "integration", "security")
EMPTY_BLOB_SHA = hashlib.sha1(b"blob 0\x00").hexdigest()
ROOT_DOCUMENTS = frozenset(
    name + suffix
    for name in ("README", "CHANGELOG", "CONTRIBUTING", "LICENSE")
    for suffix in (".md", ".rst")
)


def matches_path(path: str, pattern: str) -> bool:
    """Match shell-style components; ** spans zero or more path components.

    Unlike shell expansion, dotfiles are included. No filesystem lookup occurs.
    """
    parts = pattern.split("/")
    previous = [True] + [False] * len(parts)
    for index, part in enumerate(parts, 1):
        previous[index] = previous[index - 1] and part == "**"
    for component in path.split("/"):
        current = [False] * (len(parts) + 1)
        for index, part in enumerate(parts, 1):
            if part == "**":
                current[index] = current[index - 1] or previous[index]
            else:
                current[index] = previous[index - 1] and fnmatch.fnmatchcase(component, part)
        previous = current
    return previous[-1]


def _patterns(value):
    if not isinstance(value, dict) or set(value) != set(CATEGORIES):
        raise ValueError("Trusted test_paths must define unit, integration, and security")
    for category in CATEGORIES:
        patterns = value[category]
        if not isinstance(patterns, list) or not patterns or len(patterns) > 100:
            raise ValueError("Missing or invalid trusted test patterns for " + category)
        for pattern in patterns:
            if (not isinstance(pattern, str) or not pattern or len(pattern) > 1024
                    or pattern.startswith("/") or "\\" in pattern or "\x00" in pattern
                    or any(part in ("", ".", "..") for part in pattern.split("/"))):
                raise ValueError("Test patterns must be relative repository globs without escapes")
    return value


def _sha(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
        raise ValueError("Base and head must be exact 40-hex commit SHAs")
    return value.lower()


def _git(root, *arguments):
    # Ambient Git overrides must not redirect the operation to a different repo.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "-c", "core.fsmonitor=false", *arguments],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Unable to inspect candidate Git history") from error
    if result.returncode != 0:
        raise ValueError("Git history unavailable, commit missing, or diff failed")
    if len(result.stdout) > 64 * 1024 * 1024:
        raise ValueError("Git history response exceeds the inspection limit")
    return result.stdout


def _safe_path(raw):
    path = raw.decode("utf-8", errors="surrogateescape")
    if not path or path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("Git returned an invalid repository-relative path")
    return path


def _diff_paths(raw):
    if not raw:
        return []
    if not raw.endswith(b"\x00"):
        raise ValueError("Incomplete Git diff response")
    fields = raw[:-1].split(b"\x00")
    if len(fields) % 2:
        raise ValueError("Malformed Git diff response")
    result = []
    for index in range(0, len(fields), 2):
        status = fields[index].decode("ascii")
        if status not in ("A", "M", "D", "T"):
            raise ValueError("Unexpected Git diff status")
        result.append((status, _safe_path(fields[index + 1])))
    return result


def _tree(root, sha):
    raw = _git(root, "ls-tree", "-r", "-z", "--full-tree", sha)
    result = {}
    for entry in raw.split(b"\x00"):
        if not entry:
            continue
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise ValueError("Malformed Git tree response")
        result[_safe_path(raw_path)] = (fields[0].decode("ascii"), fields[2].decode("ascii"))
    return result


def _is_documentation(path, before, after):
    doc_path = path in ROOT_DOCUMENTS or (
        path.startswith("docs/") and (path.endswith(".md") or path.endswith(".rst"))
    )
    if not doc_path:
        return False
    modes = [tree[path][0] for tree in (before, after) if path in tree]
    return bool(modes) and all(mode == "100644" for mode in modes)


def check_changed_tests(root, base_sha, head_sha, test_paths):
    """Return changed-file coverage or raise ValueError; never modify the repo."""
    patterns = _patterns(test_paths)
    base = _sha(base_sha)
    head = _sha(head_sha)
    try:
        root_path = Path(root)
        if root_path.is_symlink() or not root_path.is_dir():
            raise ValueError("Candidate root must be a directory, not a symlink")
        root_path = root_path.resolve(strict=True)
    except (TypeError, OSError) as error:
        raise ValueError("Candidate repository root is unavailable") from error
    top_level = _git(root_path, "rev-parse", "--show-toplevel").decode("utf-8", "surrogateescape").rstrip("\n")
    if Path(top_level).resolve(strict=True) != root_path:
        raise ValueError("Candidate root must be the Git repository top level")
    for commit in (base, head):
        if _git(root_path, "cat-file", "-t", commit).strip() != b"commit":
            raise ValueError("Base and head must identify commit objects")
    merge_base = _sha(_git(root_path, "merge-base", base, head).decode("ascii").strip())
    flags = ("--name-status", "-z", "--no-renames", "--no-ext-diff", "--no-textconv")
    revision_range = base + "..." + head
    changes = _diff_paths(_git(root_path, "diff", *flags, revision_range, "--"))
    if not changes:
        raise ValueError("No candidate changes were found; empty feature diff cannot pass")
    eligible = _diff_paths(_git(root_path, "diff", *flags, "--diff-filter=AM", revision_range, "--"))
    before = _tree(root_path, merge_base)
    after = _tree(root_path, head)
    matched = {category: [] for category in CATEGORIES}
    result = {"base_sha": base, "head_sha": head,
              "changed_paths": sorted(path for _, path in changes), "tests": matched}
    if all(_is_documentation(path, before, after) for _, path in changes):
        result["classification"] = "documentation"
        return result
    old_blobs = {blob for mode, blob in before.values() if mode in ("100644", "100755")}
    for _, path in eligible:
        if after.get(path, (None, None))[0] not in ("100644", "100755"):
            continue
        # Empty files, chmod-only changes, copies, and renames of old test
        # content cannot establish new feature coverage.
        if after[path][1] == EMPTY_BLOB_SHA or after[path][1] in old_blobs:
            continue
        for category in CATEGORIES:
            if any(matches_path(path, pattern) for pattern in patterns[category]):
                matched[category].append(path)
    missing = [category for category in CATEGORIES if not matched[category]]
    if missing:
        raise ValueError("Missing added/modified regular test files for: " + ", ".join(missing))
    for paths in matched.values():
        paths.sort()
    result["classification"] = "feature"
    return result
