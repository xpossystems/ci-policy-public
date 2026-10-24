"""Unit and real-Git integration tests for required changed test coverage.

TDD/break-test record (2026-10-23): the first 11 tests failed before the guard
existed, then all 11 passed. Post-implementation attacks exposed 2 bypasses:
empty added test files and renamed unchanged tests. Both were reproduced and
fixed; all 15 tests passed. The entry integration test then demonstrated three
old suites passing without changed coverage; after wiring the guard before
prepare, the negative case blocks and the positive case executes real unittest
assertions and publishes JUnit. Final changed-test suite: 17 tests passing.
Run: python3 -m unittest discover -s tests -p test_changed_tests.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


POLICY_ROOT = Path(__file__).resolve().parents[1]
TEST_PATHS = {
    "unit": ["tests/unit/**/*.py"],
    "integration": ["tests/integration/**/*.py"],
    "security": ["tests/security/**/*.py"],
}


def load_guard(test):
    path = POLICY_ROOT / "changed_tests.py"
    test.assertTrue(path.is_file(), "the changed-test coverage guard is not implemented")
    spec = importlib.util.spec_from_file_location("changed_tests_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChangedTestsUnitTests(unittest.TestCase):
    def setUp(self):
        self.guard = load_guard(self)

    def test_globs_are_path_aware_recursive_and_include_dotfiles(self):
        cases = [
            ("tests/unit/test_a.py", "tests/unit/**/*.py", True),
            ("tests/unit/deep/test_a.py", "tests/unit/**/*.py", True),
            ("tests/unit/deep/test_a.py", "tests/unit/*.py", False),
            (".ci/tests/.hidden.py", ".ci/tests/*.py", True),
            ("tests/unit/a.py", "tests/unit/[ab].py", True),
            ("tests/unit/a.py", "tests/integration/**/*.py", False),
        ]
        for path, pattern, expected in cases:
            with self.subTest(path=path, pattern=pattern):
                self.assertEqual(self.guard.matches_path(path, pattern), expected)

    def test_invalid_test_patterns_fail_before_any_git_operation(self):
        invalids = [None, {}, {"unit": []}, {**TEST_PATHS, "security": []},
                    {**TEST_PATHS, "unit": ["../tests/*.py"]},
                    {**TEST_PATHS, "unit": ["/tests/*.py"]},
                    {**TEST_PATHS, "unit": ["C:\\tests\\*.py"]},
                    {**TEST_PATHS, "unit": ["tests\x00/unit/*"]},
                    {**TEST_PATHS, "unit": "tests/*"},
                    {**TEST_PATHS, "unit": [""]}]
        for patterns in invalids:
            with self.subTest(patterns=patterns), self.assertRaises(ValueError):
                self.guard.check_changed_tests("/nonexistent/repository", "a" * 40, "b" * 40, patterns)


class ChangedTestsGitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.guard = load_guard(self)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.root = self.directory / "repo"
        self.root.mkdir()
        self.git_env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-q")
        self.git("config", "user.name", "CI test fixture")
        self.git("config", "user.email", "ci@example.invalid")
        hooks = self.directory / "empty-hooks"
        hooks.mkdir()
        self.git("config", "core.hooksPath", str(hooks))
        self.write("src/app.py", "value = 1\n")
        self.write("docs/guide.md", "Original docs\n")
        for category in TEST_PATHS:
            self.write(f"tests/{category}/test_existing.py", "def test_old(): assert True\n")
        self.base = self.commit("fixture base")

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.root), *args], env=self.git_env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write(self, name, content="def test_new(): assert True\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--no-gpg-sign", "-m", message)
        return self.git("rev-parse", "HEAD")

    def add_all_tests(self):
        for category in TEST_PATHS:
            self.write(f"tests/{category}/test_new.py")

    def check(self, head, **overrides):
        args = {"root": self.root, "base_sha": self.base, "head_sha": head, "test_paths": TEST_PATHS}
        args.update(overrides)
        return self.guard.check_changed_tests(**args)

    def test_feature_with_only_old_passing_tests_is_blocked(self):
        self.write("src/app.py", "value = 2\n")
        with self.assertRaisesRegex(ValueError, "unit.*integration.*security"):
            self.check(self.commit("feature without new tests"))

    def test_feature_requires_each_category_and_accepts_added_or_modified_tests(self):
        self.write("src/app.py", "value = 2\n")
        self.write("tests/unit/test_existing.py", "def test_old(): assert 2 == 2\n")
        self.write("tests/integration/test_new.py")
        missing_security = self.commit("feature without security test")
        with self.assertRaisesRegex(ValueError, "security"):
            self.check(missing_security)
        self.write("tests/security/test_new.py")
        result = self.check(self.commit("complete feature tests"))
        self.assertEqual(result["classification"], "feature")
        self.assertEqual(result["tests"]["unit"], ["tests/unit/test_existing.py"])
        self.assertTrue(all(result["tests"][category] for category in TEST_PATHS))

    def test_deleted_tests_never_count_and_source_deletion_is_not_docs_only(self):
        (self.root / "src/app.py").unlink()
        for category in TEST_PATHS:
            (self.root / f"tests/{category}/test_existing.py").unlink()
        with self.assertRaisesRegex(ValueError, "unit.*integration.*security"):
            self.check(self.commit("delete source and old tests"))

    def test_docs_only_changes_use_narrow_exemption(self):
        self.write("docs/deep/readme.md", "Documentation\n")
        self.write("README.rst", "Documentation\n")
        (self.root / "docs/guide.md").unlink()
        result = self.check(self.commit("documentation only"))
        self.assertEqual(result["classification"], "documentation")
        self.assertEqual(result["tests"], {category: [] for category in TEST_PATHS})

    def test_markdown_outside_doc_paths_and_executable_docs_are_not_exempt(self):
        self.write(".github/pull_request_template.md", "Evidence\n")
        with self.assertRaisesRegex(ValueError, "unit"):
            self.check(self.commit("change workflow evidence template"))
        self.git("reset", "-q", "--hard", self.base)
        script = self.write("docs/run.md", "#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "unit"):
            self.check(self.commit("executable masquerading as docs"))

    def test_spaces_newlines_and_dotfiles_are_parsed_without_quote_confusion(self):
        self.write("src/app.py", "value = 2\n")
        names = {"unit": "tests/unit/test with spaces.py", "integration": "tests/integration/test\nnewline.py", "security": ".ci/tests/.hidden.py"}
        for name in names.values():
            self.write(name)
        patterns = {**TEST_PATHS, "security": [".ci/tests/*.py"]}
        result = self.check(self.commit("unusual filenames"), test_paths=patterns)
        self.assertEqual(result["tests"], {category: [name] for category, name in names.items()})

    def test_symlink_cannot_count_as_a_changed_test(self):
        self.write("src/app.py", "value = 2\n")
        self.add_all_tests()
        outside = self.directory / "outside.py"
        outside.write_text("def test_external(): assert True\n")
        security = self.root / "tests/security/test_new.py"
        security.unlink()
        security.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "security"):
            self.check(self.commit("symlink test escape"))

    def test_root_cannot_escape_to_parent_repository_or_through_symlink(self):
        self.add_all_tests()
        head = self.commit("new tests")
        with self.assertRaises(ValueError):
            self.check(head, root=self.root / "tests")
        link = self.directory / "repo-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.check(head, root=link)

    def test_missing_commits_empty_diff_and_injected_refs_fail_closed(self):
        self.add_all_tests()
        head = self.commit("new tests")
        with self.assertRaises(ValueError):
            self.check(head, base_sha="0" * 40)
        with self.assertRaisesRegex(ValueError, "changes"):
            self.check(self.base)
        marker = self.directory / "injected"
        for value in ["main", "--help", "HEAD", head + ";touch " + str(marker), head + "\n", None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(head, base_sha=value)
        self.assertFalse(marker.exists())

    def test_post_implementation_renaming_old_tests_cannot_fake_new_coverage(self):
        self.write("src/app.py", "value = 2\n")
        for category in TEST_PATHS:
            original = self.root / f"tests/{category}/test_existing.py"
            original.rename(original.with_name("test_renamed.py"))
        with self.assertRaisesRegex(ValueError, "unit.*integration.*security"):
            self.check(self.commit("rename old passing tests without new assertions"))

    def test_post_implementation_empty_test_files_cannot_fake_new_coverage(self):
        self.write("src/app.py", "value = 2\n")
        for category in TEST_PATHS:
            self.write(f"tests/{category}/test_empty.py", "")
        with self.assertRaisesRegex(ValueError, "unit.*integration.*security"):
            self.check(self.commit("empty placeholder test files"))

    def test_post_implementation_chmod_only_tests_are_not_new_coverage(self):
        self.write("src/app.py", "value = 2\n")
        for category in TEST_PATHS:
            (self.root / f"tests/{category}/test_existing.py").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "unit.*integration.*security"):
            self.check(self.commit("chmod old tests"))

    def test_post_implementation_external_diff_and_git_environment_are_ignored(self):
        self.write("src/app.py", "value = 2\n")
        self.add_all_tests()
        marker = self.directory / "executed"
        external = self.directory / "external-diff.sh"
        external.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
        external.chmod(0o755)
        self.write(".gitattributes", "*.py diff=attacker\n")
        self.git("config", "diff.attacker.command", str(external))
        self.git("config", "diff.attacker.textconv", str(external))
        head = self.commit("new tests with hostile diff configuration")
        with patch.dict(os.environ, {"GIT_EXTERNAL_DIFF": str(external), "GIT_DIR": str(self.directory / "wrong-repo"), "GIT_WORK_TREE": str(self.directory)}):
            result = self.check(head)
        self.assertEqual(result["classification"], "feature")
        self.assertFalse(marker.exists())

    def entry_fixture(self):
        trusted = self.directory / "trusted-policy"
        trusted.mkdir()
        for name in ("entry.py", "run_suite.py", "quality_gate.py", "changed_tests.py", "ci_configuration.py"):
            shutil.copyfile(POLICY_ROOT / name, trusted / name)
        runner = '''import os, sys, unittest, xml.etree.ElementTree as ET
sys.path.insert(0, os.getcwd())
category = sys.argv[1]
suite = unittest.defaultTestLoader.discover('tests/' + category)
def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test
cases = list(flatten(suite))
result = unittest.TextTestRunner().run(suite)
root = ET.Element('testsuite', tests=str(result.testsRun), failures=str(len(result.failures)), errors=str(len(result.errors)), skipped=str(len(result.skipped)))
failures = dict(result.failures + result.errors)
skipped = dict(result.skipped)
for test in cases:
    element = ET.SubElement(root, 'testcase', name=test.id(), classname=category)
    if test in failures:
        ET.SubElement(element, 'failure').text = failures[test]
    if test in skipped:
        ET.SubElement(element, 'skipped').text = skipped[test]
ET.ElementTree(root).write(category + '.xml')
raise SystemExit(0 if result.wasSuccessful() else 1)
'''
        self.write("tools/run_tests.py", runner)
        for category in TEST_PATHS:
            self.write(f"tests/{category}/test_existing.py", "import unittest\nfrom src.app import value\nclass Existing(unittest.TestCase):\n    def test_existing(self): self.assertGreaterEqual(value, 1)\n")
        self.base = self.commit("existing tested behavior and real JUnit runner")
        profile = {category: {"command": [sys.executable, "tools/run_tests.py", category], "report": category + ".xml", "timeout_seconds": 10} for category in TEST_PATHS}
        profile.update(runner="ubuntu-24.04", python_version="3.12", test_paths=TEST_PATHS,
                       prepare=[[sys.executable, "-c", "from pathlib import Path; Path('prepare-ran').write_text('ran')"]])
        (trusted / "profiles.json").write_text(json.dumps({"schema_version": 1, "repositories": {"example-org/fixture": profile}}))
        return trusted

    def run_entry(self, trusted, head):
        reports = self.directory / "published-reports"
        result = subprocess.run([sys.executable, str(trusted / "entry.py"), "--mode", "run", "--root", str(self.root), "--reports", str(reports)],
                                env=dict(os.environ, QUALITY_REPOSITORY="example-org/fixture", QUALITY_BASE_SHA=self.base, QUALITY_HEAD_SHA=head),
                                capture_output=True, text=True, timeout=30)
        return result, reports

    def test_entry_runs_real_suites_and_publishes_junit_when_each_category_changed(self):
        trusted = self.entry_fixture()
        self.write("src/app.py", "value = 2\n")
        for category in TEST_PATHS:
            self.write(f"tests/{category}/test_feature.py", "import unittest\nfrom src.app import value\nclass Feature(unittest.TestCase):\n    def test_feature(self): self.assertEqual(value, 2)\n")
        result, reports = self.run_entry(trusted, self.commit("new feature with new regression assertions"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for category in TEST_PATHS:
            self.assertTrue((reports / (category + ".xml")).is_file())
            self.assertIn('tests="2"', (reports / (category + ".xml")).read_text())

    def test_entry_blocks_missing_changed_tests_before_any_prepare_command(self):
        trusted = self.entry_fixture()
        self.write("src/app.py", "value = 2\n")
        result, reports = self.run_entry(trusted, self.commit("feature passes old tests but adds no new coverage"))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Missing added/modified", result.stderr)
        self.assertFalse((self.root / "prepare-ran").exists())
        self.assertFalse(reports.exists())


if __name__ == "__main__":
    unittest.main()
