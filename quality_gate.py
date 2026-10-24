#!/usr/bin/env python3
"""Validate CI-produced JUnit reports and declared feature evidence, fail closed.

This validates report contents and evidence structure. It does not execute declared
commands, fetch run URLs, prove TDD ordering, or establish pentest authenticity.
The caller must obtain reports from trusted runs and independently verify/replay
the declared red/green runs for the exact candidate revision.
"""

import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET


MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_DEPTH = 128
MAX_ELEMENTS = 200000
SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")


class GateError(ValueError):
    """A required report or evidence input was missing or invalid."""


def _require(condition, message):
    if not condition:
        raise GateError(message)


def _read_file(path, label):
    """Read a bounded regular file without following a final symlink or FIFO."""
    path = Path(path)
    descriptor = None
    try:
        before = path.lstat()
        _require(stat.S_ISREG(before.st_mode), f"{label}: expected a regular, non-symlink file")
        _require(before.st_size <= MAX_FILE_BYTES, f"{label}: input exceeds {MAX_FILE_BYTES} bytes")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode), f"{label}: input is not a regular file")
        _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), f"{label}: input changed while opening")
        _require(opened.st_size <= MAX_FILE_BYTES, f"{label}: input exceeds size limit")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(MAX_FILE_BYTES + 1)
            after = os.fstat(handle.fileno())
        _require(len(data) <= MAX_FILE_BYTES, f"{label}: input exceeds size limit")
        _require((opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns), f"{label}: input changed while reading")
        text = data.decode("utf-8-sig", errors="strict")
        _require("\x00" not in text, f"{label}: NUL bytes are not allowed")
        return text, (opened.st_dev, opened.st_ino)
    except (OSError, UnicodeError) as error:
        raise GateError(f"{label}: cannot read a valid UTF-8 file ({type(error).__name__})") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _counter(value, label):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9]+", value) is not None, f"{label}: counter must be a nonnegative integer")
    _require(len(value) <= 10, f"{label}: counter is too large")
    return int(value)


def _junit(text, label):
    _require(re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, re.IGNORECASE) is None, f"{label}: DOCTYPE and ENTITY declarations are forbidden")
    declaration = re.match(r"\s*<\?xml\b[^?]*\?>", text)
    if declaration:
        encoding = re.search(r"encoding\s*=\s*['\"]([^'\"]+)['\"]", declaration.group(), re.IGNORECASE)
        if encoding:
            _require(encoding.group(1).lower() in ("utf-8", "utf8"), f"{label}: XML must use UTF-8")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError) as error:
        raise GateError(f"{label}: malformed XML") from error
    _require(root.tag in ("testsuite", "testsuites"), f"{label}: expected JUnit testsuite or testsuites root")

    # Iterative traversal bounds nesting and disallows fake cases hidden inside
    # properties, output, or other testcase elements. No recursive tree walk.
    stack = [(root, None, 1)]
    suites = []
    cases = []
    count = 0
    while stack:
        element, parent, depth = stack.pop()
        count += 1
        _require(depth <= MAX_DEPTH and count <= MAX_ELEMENTS, f"{label}: XML structure exceeds limits")
        _require(element.tag in {"testsuites", "testsuite", "testcase", "failure", "error", "skipped", "properties", "property", "system-out", "system-err"}, f"{label}: unknown or namespaced JUnit element")
        _require(not any("{" in attribute for attribute in element.attrib), f"{label}: namespaced JUnit attributes are forbidden")
        if element.tag in ("testsuite", "testsuites"):
            _require(element is root or (element.tag == "testsuite" and parent.tag in ("testsuite", "testsuites")), f"{label}: invalid nested suite")
            suites.append(element)
        elif element.tag == "testcase":
            _require(parent is not None and parent.tag == "testsuite", f"{label}: testcase must be directly inside testsuite")
            _require(bool(element.get("name", "").strip()), f"{label}: testcase must have a name")
            for attribute, allowed in [("status", {"run", "passed", "success"}), ("result", {"completed", "passed", "success"})]:
                if attribute in element.attrib:
                    _require(element.attrib[attribute] in allowed, f"{label}: testcase is not an executed success")
            cases.append(element)
        elif element.tag in ("failure", "error", "skipped"):
            _require(parent is not None and parent.tag == "testcase", f"{label}: invalid outcome element")
        elif element.tag == "property":
            _require(parent is not None and parent.tag == "properties", f"{label}: invalid property element")
        elif element.tag in ("properties", "system-out", "system-err"):
            _require(parent is not None and parent.tag in ("testsuites", "testsuite", "testcase"), f"{label}: invalid report metadata element")
        stack.extend((child, element, depth + 1) for child in element)

    _require(bool(cases), f"{label}: no executed testcases; counters alone are not execution evidence")
    for suite in suites:
        actual = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        for case in suite.iter("testcase"):
            actual["tests"] += 1
            for tag, attribute in [("failure", "failures"), ("error", "errors"), ("skipped", "skipped")]:
                actual[attribute] += int(any(child.tag == tag for child in case))
        for attribute, expected in actual.items():
            if attribute in suite.attrib:
                _require(_counter(suite.attrib[attribute], f"{label}.{attribute}") == expected, f"{label}: {attribute} counter contradicts testcase results")
        if "disabled" in suite.attrib:
            _require(_counter(suite.attrib["disabled"], f"{label}.disabled") == 0, f"{label}: disabled tests are not allowed")
    for case in cases:
        _require(not any(child.tag in ("failure", "error", "skipped") for child in case), f"{label}: failures, errors, and skipped tests are forbidden")
    return len(cases)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "evidence: duplicate JSON object key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise GateError("evidence: nonfinite JSON numbers are forbidden")


def _json_integer(value):
    _require(len(value) <= 20, "evidence: JSON integer exceeds size limit")
    return int(value)


def _json_float(value):
    _require(len(value) <= 100, "evidence: JSON number exceeds size limit")
    number = float(value)
    _require(math.isfinite(number), "evidence: nonfinite JSON numbers are forbidden")
    return number


def _nonempty(value, label):
    _require(isinstance(value, str) and bool(value.strip()), f"{label}: expected a nonempty string")
    return value


def _sha(value, label):
    _require(isinstance(value, str) and SHA_PATTERN.fullmatch(value) is not None, f"{label}: expected a full 40-character hexadecimal commit SHA")
    return value


def _evidence(text, repository, head_sha):
    try:
        data = json.loads(text, object_pairs_hook=_json_object, parse_constant=_nonfinite, parse_int=_json_integer, parse_float=_json_float)
    except (json.JSONDecodeError, RecursionError) as error:
        raise GateError("evidence: malformed JSON") from error
    _require(isinstance(data, dict), "evidence: expected an object")
    _require(type(data.get("schema_version")) is int and data["schema_version"] == 1, "evidence: schema_version must be integer 1")
    _require(data.get("repository") == repository, "evidence: repository does not match candidate")
    _require(data.get("head_sha") == head_sha, "evidence: head_sha does not match candidate")
    tdd = data.get("tdd")
    _require(isinstance(tdd, dict), "evidence.tdd: expected an object")
    red = _sha(tdd.get("red_commit"), "evidence.tdd.red_commit")
    green = _sha(tdd.get("green_commit"), "evidence.tdd.green_commit")
    _require(green == head_sha, "evidence.tdd: green commit must equal candidate head_sha")
    _require(red.lower() != green.lower(), "evidence.tdd: red and green commits must differ")
    pattern = re.compile(r"https://github\.com/" + re.escape(repository) + r"/actions/runs/([1-9][0-9]*)\Z")
    run_ids = []
    for key in ("red_run_url", "green_run_url"):
        url = _nonempty(tdd.get(key), f"evidence.tdd.{key}")
        match = pattern.fullmatch(url)
        _require(match is not None, f"evidence.tdd.{key}: expected canonical HTTPS GitHub Actions run URL for the candidate repository")
        run_ids.append(match.group(1))
    _require(run_ids[0] != run_ids[1], "evidence.tdd: red and green run IDs must differ")

    pentest = data.get("pentest")
    _require(isinstance(pentest, dict), "evidence.pentest: expected an object")
    _nonempty(pentest.get("target"), "evidence.pentest.target")
    commands = pentest.get("commands")
    _require(isinstance(commands, list) and bool(commands), "evidence.pentest.commands: expected a nonempty list")
    for command in commands:
        _nonempty(command, "evidence.pentest.commands[]")
    remaining = pentest.get("remaining_findings")
    _require(isinstance(remaining, list) and not remaining, "evidence.pentest: remaining_findings must be an empty list")
    findings = pentest.get("findings")
    _require(isinstance(findings, list), "evidence.pentest.findings: expected a list")
    identifiers = set()
    for finding in findings:
        _require(isinstance(finding, dict), "evidence.pentest.findings[]: expected an object")
        _require(finding.get("status") == "fixed", "evidence.pentest: every finding must be fixed")
        for key in ("id", "summary", "regression_test"):
            _nonempty(finding.get(key), f"evidence.pentest.findings[].{key}")
        _require(finding["id"] not in identifiers, "evidence.pentest: duplicate finding ID")
        identifiers.add(finding["id"])
    return len(findings)


def validate_junit(path, label="suite"):
    """Return executed testcase count from a valid report, or raise GateError.

    Reports must be generated by a trusted test invocation; validation alone
    cannot prove their provenance or the meaning of their test assertions.
    """
    text, _identity = _read_file(path, label)
    return _junit(text, label)


def validate_reports(*, unit_report, integration_report, security_report):
    """Validate all three distinct reports, including counts and skip/fail states."""
    executed = {}
    identities = set()
    for label, path in [("unit", unit_report), ("integration", integration_report), ("security", security_report)]:
        text, identity = _read_file(path, label)
        _require(identity not in identities, f"{label}: each required category must have a distinct report file")
        identities.add(identity)
        executed[label] = _junit(text, label)
    return executed


def validate(*, unit_report, integration_report, security_report, evidence, head_sha, repository):
    """Return a JSON-serializable summary; raise GateError for any rejection."""
    _sha(head_sha, "head_sha")
    _require(isinstance(repository, str) and REPOSITORY_PATTERN.fullmatch(repository) is not None and repository.split("/", 1)[1] not in (".", ".."), "repository: expected owner/repository")
    executed = validate_reports(unit_report=unit_report, integration_report=integration_report,
                                security_report=security_report)
    evidence_text, _identity = _read_file(evidence, "evidence")
    fixed = _evidence(evidence_text, repository, head_sha)
    return {
        "status": "validated",
        "repository": repository,
        "head_sha": head_sha,
        "executed": executed,
        "declared_fixed_findings": fixed,
        "declarations_prove_execution": False,
        "limitation": "Reports require trusted CI provenance. Declared run URLs and pentest commands do not prove execution or TDD ordering; independent verification/replay is required.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("unit-report", "integration-report", "security-report", "evidence", "head-sha", "repository"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    try:
        result = validate(**vars(args))
    except GateError as error:
        print(f"Quality gate rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
