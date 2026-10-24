#!/usr/bin/env python3
"""Run one centrally approved test suite and publish validated fresh JUnit evidence.

Profiles and output live outside the candidate checkout. No profile is inferred
from repository contents. Outside-checkout paths are not a security sandbox:
same-user candidate code can still alter files or fabricate JUnit. Callers must
provide process/filesystem isolation, read-only policy, and no administrative or
production credentials. This validates execution/report mechanics, not test
relevance, report authenticity against malicious code, or pentest breadth.
"""

import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

import quality_gate


MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_PROFILES_BYTES = 2 * 1024 * 1024
CATEGORIES = {"unit", "integration", "security"}
WORKFLOW_COMMAND_CHANNELS = {
    "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE",
}


class SuiteError(ValueError):
    """The suite could not produce fresh, successful execution evidence."""


def _require(condition, message):
    if not condition:
        raise SuiteError(message)


def _inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _regular(path, label):
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
             f"{label}: expected a regular file without symbolic or hard links")
    return info


def _read_regular(path, label, limit):
    before = _regular(path, label)
    _require(before.st_size <= limit, f"{label}: file exceeds size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
                 f"{label}: not a safe regular file")
        _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                 f"{label}: changed while opening")
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    _require(len(data) <= limit, f"{label}: file exceeds size limit")
    _require((opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
             f"{label}: changed while reading")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "profiles: duplicate JSON key")
        result[key] = value
    return result


def _profile(path, repository, category, root):
    path = Path(path)
    _require(path.is_absolute(), "profiles: absolute trusted path required")
    _require(not _inside(path.resolve(), root), "profiles: must live outside candidate checkout")
    data = json.loads(_read_regular(path, "profiles", MAX_PROFILES_BYTES), object_pairs_hook=_unique_object)
    _require(isinstance(data, dict) and type(data.get("schema_version")) is int
             and data["schema_version"] == 1, "profiles: unsupported schema version")
    repos = data.get("repositories")
    _require(isinstance(repos, dict), "profiles: repositories object required")
    config = repos.get(repository)
    _require(isinstance(config, dict), "profiles: repository has no approved suites")
    profile = config.get(category)
    _require(isinstance(profile, dict), f"profiles: missing approved {category} suite")
    command = profile.get("command")
    _require(isinstance(command, list) and len(command) > 0
             and all(isinstance(arg, str) and arg.strip() and "\x00" not in arg for arg in command),
             "profiles: command must be a nonempty argv list of nonempty strings")
    timeout = profile.get("timeout_seconds", 1800)
    _require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 3600,
             "profiles: timeout_seconds must be greater than zero and at most 3600")
    return command, profile.get("report"), timeout


def _report_path(root, relative):
    _require(isinstance(relative, str) and relative and "\\" not in relative
             and "\x00" not in relative and not re.match(r"^[A-Za-z]:", relative),
             "report: a safe relative XML path is required")
    parts = relative.split("/")
    _require(all(part and part not in (".", "..", ".git") for part in parts)
             and not Path(relative).is_absolute() and Path(relative).suffix.lower() == ".xml",
             "report: traversal, absolute paths, .git paths, and non-XML reports are forbidden")
    _require(root.is_dir() and not root.is_symlink(), "candidate root changed or is not a directory")
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.exists() or current.is_symlink():
            info = current.lstat()
            _require(stat.S_ISDIR(info.st_mode), "report: parent must be a real directory, not a symlink")
    result = root.joinpath(*parts)
    if result.exists() or result.is_symlink():
        _regular(result, "report")
    return result


def _output_path(output, root):
    output = Path(output)
    _require(output.is_absolute(), "output: absolute path required")
    _require(".." not in output.parts and not _inside(output, root)
             and not _inside(output.resolve(), root), "output: must live outside candidate checkout")
    _require(not output.exists() and not output.is_symlink(), "output: existing evidence will not be overwritten")
    for parent in reversed(output.parents):
        if parent.exists() or parent.is_symlink():
            _require(stat.S_ISDIR(parent.lstat().st_mode), "output: parent must be a real directory, not a symlink")
        else:
            parent.mkdir()
    return output


def _stop_process(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    process.wait()


def _execute(command, root, timeout):
    # Inherit stdout/stderr so the CI log retains actual test output without an
    # in-memory log buffer or any automatic environment dump. Never use a shell.
    # A test must not write outputs/environment for later workflow steps through
    # inherited command files. This reduction is not a substitute for isolation.
    environment = {key: value for key, value in os.environ.items()
                   if key not in WORKFLOW_COMMAND_CHANNELS}
    process = subprocess.Popen(command, cwd=root, shell=False, env=environment,
                               start_new_session=os.name == "posix")
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        _stop_process(process)
        raise SuiteError("suite command timed out") from error
    except BaseException:
        _stop_process(process)
        raise
    if os.name == "posix":
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            _stop_process(process)
            raise SuiteError("suite left background processes running")
    _require(returncode == 0, f"suite command failed with exit status {returncode}")


def run_suite(*, repository, category, root, profiles, output):
    """Return an executed test count only after a fresh safe report validates."""
    snapshot = None
    try:
        root = Path(root)
        _require(root.is_absolute() and root.is_dir() and not root.is_symlink(),
                 "root: an absolute real candidate directory is required")
        root = root.resolve()
        _require(isinstance(repository, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository),
                 "repository: owner/name is required")
        _require(category in CATEGORIES, "category: expected unit, integration, or security")
        command, relative, timeout = _profile(profiles, repository, category, root)
        report = _report_path(root, relative)
        output = _output_path(output, root)
        # Delete exactly the declared safe report; no directory cleanup and no
        # globbing. This makes an exit-zero command unable to reuse stale green.
        if report.exists():
            report.unlink()
        _execute(command, root, timeout)
        report = _report_path(root, relative)
        data = _read_regular(report, "report", MAX_REPORT_BYTES)
        output = _output_path(output, root)
        with tempfile.NamedTemporaryFile(prefix=".suite-snapshot-", suffix=".xml", dir=output.parent, delete=False) as handle:
            snapshot = Path(handle.name)
            handle.write(data)
        executed = quality_gate.validate_junit(snapshot, category)
        # Atomic no-overwrite publication: a concurrent/precreated output cannot
        # be replaced. The snapshot is the exact bytes the validator inspected.
        os.link(snapshot, output)
        return {"repository": repository, "category": category, "executed": executed}
    except SuiteError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, quality_gate.GateError) as error:
        raise SuiteError(f"suite rejected: {type(error).__name__}: {error}") from error
    finally:
        if snapshot is not None:
            snapshot.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--category", choices=sorted(CATEGORIES), required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--profiles", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = run_suite(**vars(args))
    except SuiteError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
