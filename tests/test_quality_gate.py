"""Contract and hostile-input tests for the shared CI evidence validator."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

POLICY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY))

import quality_gate as gate


HEAD = "a" * 40
RED = "b" * 40
REPOSITORY = "example-org/example-repo"


def valid_evidence():
    return {
        "schema_version": 1,
        "repository": REPOSITORY,
        "head_sha": HEAD,
        "tdd": {
            "red_commit": RED,
            "green_commit": HEAD,
            "red_run_url": f"https://github.com/{REPOSITORY}/actions/runs/101",
            "green_run_url": f"https://github.com/{REPOSITORY}/actions/runs/102",
        },
        "pentest": {
            "target": "http://127.0.0.1:8765 (ephemeral CI test instance)",
            "commands": ["python -m pytest tests/security"],
            "findings": [],
            "remaining_findings": [],
        },
    }


def suite(name="example", count=1):
    cases = "".join(f'<testcase classname="Example" name="case_{i}"/>' for i in range(count))
    return f'<testsuite name="{name}" tests="{count}" failures="0" errors="0" skipped="0">{cases}</testsuite>'


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="quality-gate-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.unit = self.write("unit.xml", suite())
        self.integration = self.write("integration.xml", suite(count=2))
        self.security = self.write("security.xml", suite(count=3))
        self.evidence = self.write("evidence.json", json.dumps(valid_evidence()))

    def write(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def validate(self):
        return gate.validate(
            unit_report=self.unit,
            integration_report=self.integration,
            security_report=self.security,
            evidence=self.evidence,
            head_sha=HEAD,
            repository=REPOSITORY,
        )

    def save_evidence(self, data):
        self.evidence.write_text(json.dumps(data), encoding="utf-8")

    def reject(self):
        with self.assertRaises(gate.GateError):
            self.validate()


class ReportTests(Fixture):
    def test_public_validate_junit_returns_executed_count(self):
        self.assertEqual(gate.validate_junit(self.integration), 2)

    def test_public_validate_junit_preserves_custom_label_on_rejection(self):
        self.unit.write_text(suite(count=0))
        with self.assertRaisesRegex(gate.GateError, "custom-security"):
            gate.validate_junit(self.unit, label="custom-security")

    def test_valid_reports_count_actual_executed_cases(self):
        self.assertEqual(self.validate()["executed"], {"unit": 1, "integration": 2, "security": 3})

    def test_nested_suites_do_not_double_count(self):
        self.unit.write_text('<testsuites tests="3" failures="0" errors="0" skipped="0">' + suite(count=1) + '<testsuite tests="2">' + suite(count=2) + '</testsuite></testsuites>')
        self.assertEqual(self.validate()["executed"]["unit"], 3)

    def test_actual_cases_do_not_need_optional_counters(self):
        self.unit.write_text('<testsuite><testcase name="works"/></testsuite>')
        self.assertEqual(self.validate()["executed"]["unit"], 1)

    def test_missing_report(self):
        self.unit.unlink()
        self.reject()

    def test_missing_each_category_is_rejected(self):
        for field in ["unit", "integration", "security"]:
            with self.subTest(field=field):
                old = getattr(self, field)
                setattr(self, field, self.root / "missing.xml")
                self.reject()
                setattr(self, field, old)

    def test_empty_suite(self):
        self.unit.write_text(suite(count=0))
        self.reject()

    def test_counters_without_testcases_do_not_prove_execution(self):
        self.unit.write_text('<testsuite tests="10"/>')
        self.reject()

    def test_any_failure_error_or_skip_rejects(self):
        for outcome in ["failure", "error", "skipped"]:
            with self.subTest(outcome=outcome):
                self.unit.write_text(f'<testsuite><testcase name="bad"><{outcome}/></testcase><testcase name="good"/></testsuite>')
                self.reject()

    def test_contradictory_counters(self):
        for attribute, value in [("tests", "2"), ("tests", "0"), ("failures", "1"), ("errors", "1"), ("skipped", "1")]:
            with self.subTest(attribute=attribute, value=value):
                self.unit.write_text(f'<testsuite {attribute}="{value}"><testcase name="good"/></testsuite>')
                self.reject()

    def test_invalid_counter_types(self):
        for value in ["-1", "1.0", "NaN", "true", " 1", ""]:
            with self.subTest(value=value):
                self.unit.write_text(f'<testsuite tests="{value}"><testcase name="good"/></testsuite>')
                self.reject()

    def test_contradictory_parent_aggregate(self):
        self.unit.write_text('<testsuites tests="1">' + suite(count=2) + '</testsuites>')
        self.reject()

    def test_malformed_and_wrong_root(self):
        for content in ["", "not xml", "<testsuite>", "<report><testcase name='x'/></report>"]:
            with self.subTest(content=content):
                self.unit.write_text(content)
                self.reject()

    def test_unnamed_case(self):
        self.unit.write_text('<testsuite><testcase/></testsuite>')
        self.reject()

    def test_testcases_hidden_inside_properties_are_rejected(self):
        self.unit.write_text('<testsuite><properties><testcase name="fake"/></properties></testsuite>')
        self.reject()

    def test_nested_testcases_are_rejected(self):
        self.unit.write_text('<testsuite><testcase name="outer"><testcase name="inner"/></testcase></testsuite>')
        self.reject()

    def test_external_entity_and_doctype_are_rejected(self):
        secret = self.write("secret.txt", "do-not-read-this")
        malicious = f'<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM "file://{secret}">]><testsuite><testcase name="bad">&xxe;</testcase></testsuite>'
        self.unit.write_text(malicious)
        self.reject()

    def test_entity_expansion_is_rejected(self):
        self.unit.write_text('<!DOCTYPE testsuite [<!ENTITY a "explosion"><!ENTITY b "&a;&a;">]><testsuite><testcase name="bad">&b;</testcase></testsuite>')
        self.reject()

    def test_utf16_xml_cannot_hide_doctype(self):
        self.unit.write_bytes('<!DOCTYPE testsuite><testsuite><testcase name="x"/></testsuite>'.encode("utf-16"))
        self.reject()

    def test_symlink_report(self):
        real = self.unit.rename(self.root / "real.xml")
        self.unit.symlink_to(real)
        self.reject()

    def test_directory_report(self):
        self.unit.unlink()
        self.unit.mkdir()
        self.reject()

    def test_oversized_report(self):
        with self.unit.open("wb") as handle:
            handle.truncate(gate.MAX_FILE_BYTES + 1)
        self.reject()

    def test_deep_xml_is_rejected(self):
        self.unit.write_text("<testsuite>" * 140 + '<testcase name="x"/>' + "</testsuite>" * 140)
        self.reject()

    def test_same_file_cannot_supply_all_categories(self):
        self.security = self.unit
        self.reject()

    def test_hardlinked_report_cannot_supply_two_categories(self):
        self.security.unlink()
        os.link(self.unit, self.security)
        self.reject()

    def test_namespaced_outcomes_cannot_hide_skips_or_failures(self):
        for outcome in ["failure", "error", "skipped"]:
            with self.subTest(outcome=outcome):
                self.unit.write_text(f'<testsuite xmlns:x="urn:spoof"><testcase name="bad"><x:{outcome}/></testcase></testsuite>')
                self.reject()

    def test_nonexecuted_testcase_statuses(self):
        for attribute, value in [("status", "notrun"), ("status", "disabled"), ("result", "suppressed"), ("result", "skipped")]:
            with self.subTest(attribute=attribute, value=value):
                self.unit.write_text(f'<testsuite><testcase name="bad" {attribute}="{value}"/></testsuite>')
                self.reject()

    def test_disabled_counter_rejected(self):
        self.unit.write_text('<testsuite disabled="1"><testcase name="x"/></testsuite>')
        self.reject()

    def test_unknown_report_elements_are_not_execution_evidence(self):
        self.unit.write_text('<testsuite><testcase name="bad"><outcome value="failed"/></testcase></testsuite>')
        self.reject()


class EvidenceTests(Fixture):
    def test_missing_evidence(self):
        self.evidence.unlink()
        self.reject()

    def test_bad_json(self):
        self.evidence.write_text("{")
        self.reject()

    def test_duplicate_json_keys(self):
        self.evidence.write_text(self.evidence.read_text().replace('"schema_version": 1', '"schema_version": 2, "schema_version": 1'))
        self.reject()

    def test_nonfinite_json(self):
        self.evidence.write_text(self.evidence.read_text().replace('"schema_version": 1', '"schema_version": NaN'))
        self.reject()

    def test_overflowed_json_number_in_metadata(self):
        self.evidence.write_text(self.evidence.read_text().replace('"schema_version": 1', '"schema_version": 1, "metadata": 1e999'))
        self.reject()

    def test_extremely_long_json_integer_is_rejected_before_conversion(self):
        self.evidence.write_text(self.evidence.read_text().replace('"schema_version": 1', '"schema_version": 1, "metadata": ' + "9" * 1000))
        self.reject()

    def test_schema_version_type_and_value(self):
        for version in [True, "1", 1.0, 0, 2, None]:
            with self.subTest(version=version):
                data = valid_evidence()
                data["schema_version"] = version
                self.save_evidence(data)
                self.reject()

    def test_repository_and_head_must_match(self):
        for field, value in [("repository", "attacker/example"), ("head_sha", "c" * 40)]:
            with self.subTest(field=field):
                data = valid_evidence()
                data[field] = value
                self.save_evidence(data)
                self.reject()

    def test_commits_require_full_hex(self):
        for field in ["red_commit", "green_commit"]:
            for value in ["abc123", "z" * 40, None, True, "a" * 41]:
                with self.subTest(field=field, value=value):
                    data = valid_evidence()
                    data["tdd"][field] = value
                    self.save_evidence(data)
                    self.reject()

    def test_green_commit_must_match_candidate(self):
        data = valid_evidence()
        data["tdd"]["green_commit"] = "c" * 40
        self.save_evidence(data)
        self.reject()

    def test_red_and_green_commits_must_differ(self):
        data = valid_evidence()
        data["tdd"]["red_commit"] = HEAD
        self.save_evidence(data)
        self.reject()

    def test_run_urls_require_same_repo_and_canonical_github(self):
        bad_urls = [
            f"http://github.com/{REPOSITORY}/actions/runs/101",
            f"https://github.com.attacker.test/{REPOSITORY}/actions/runs/101",
            f"https://github.com@attacker.test/{REPOSITORY}/actions/runs/101",
            f"https://github.com:443/{REPOSITORY}/actions/runs/101",
            "https://github.com/attacker/example/actions/runs/101",
            f"https://github.com/{REPOSITORY}/actions/runs/101?head={HEAD}",
            f"https://github.com/{REPOSITORY}/actions/runs/101#proof",
            f"https://github.com/{REPOSITORY}/actions/runs/0",
            f"https://github.com/{REPOSITORY}/actions/runs/../101",
            f"https://github.com/{REPOSITORY}/actions/runs/%31%30%31",
            "file:///tmp/evidence", "", None,
        ]
        for value in bad_urls:
            with self.subTest(value=value):
                data = valid_evidence()
                data["tdd"]["red_run_url"] = value
                self.save_evidence(data)
                self.reject()

    def test_same_red_and_green_run_rejected(self):
        data = valid_evidence()
        data["tdd"]["green_run_url"] = data["tdd"]["red_run_url"]
        self.save_evidence(data)
        self.reject()

    def test_required_fields_cannot_be_omitted(self):
        paths = [(key,) for key in valid_evidence()]
        paths += [("tdd", key) for key in valid_evidence()["tdd"]]
        paths += [("pentest", key) for key in valid_evidence()["pentest"]]
        for path in paths:
            with self.subTest(path=path):
                data = valid_evidence()
                parent = data if len(path) == 1 else data[path[0]]
                del parent[path[-1]]
                self.save_evidence(data)
                self.reject()

    def test_pentest_target_and_commands_nonempty(self):
        for key, value in [("target", ""), ("target", "  "), ("commands", []), ("commands", [""]), ("commands", ["  "]), ("commands", "pytest"), ("commands", [1])]:
            with self.subTest(key=key, value=value):
                data = valid_evidence()
                data["pentest"][key] = value
                self.save_evidence(data)
                self.reject()

    def test_remaining_findings_must_be_empty_list(self):
        for value in [["open finding"], {}, "", None, False]:
            with self.subTest(value=value):
                data = valid_evidence()
                data["pentest"]["remaining_findings"] = value
                self.save_evidence(data)
                self.reject()

    def test_findings_must_be_resolved_with_regression_evidence(self):
        for value in [None, "none", ["fixed"], [{"status": "open"}], [{"id": "F1", "summary": "test", "status": "fixed"}]]:
            with self.subTest(value=value):
                data = valid_evidence()
                data["pentest"]["findings"] = value
                self.save_evidence(data)
                self.reject()

    def test_fixed_finding_is_valid(self):
        data = valid_evidence()
        data["pentest"]["findings"] = [{"id": "F1", "summary": "Cross-tenant read blocked", "status": "fixed", "regression_test": "tests/security/test_tenant.py::test_other_tenant"}]
        self.save_evidence(data)
        self.validate()

    def test_duplicate_findings_are_rejected(self):
        data = valid_evidence()
        finding = {"id": "F1", "summary": "fixed", "status": "fixed", "regression_test": "tests/test_security.py"}
        data["pentest"]["findings"] = [finding, finding]
        self.save_evidence(data)
        self.reject()

    def test_symlink_evidence(self):
        real = self.evidence.rename(self.root / "real.json")
        self.evidence.symlink_to(real)
        self.reject()

    def test_oversized_evidence(self):
        with self.evidence.open("wb") as handle:
            handle.truncate(gate.MAX_FILE_BYTES + 1)
        self.reject()


class CliIntegrationTests(Fixture):
    def command(self):
        return [sys.executable, str(POLICY / "quality_gate.py"), "--unit-report", str(self.unit), "--integration-report", str(self.integration), "--security-report", str(self.security), "--evidence", str(self.evidence), "--head-sha", HEAD, "--repository", REPOSITORY]

    def run_cli(self):
        return subprocess.run(self.command(), capture_output=True, text=True, timeout=10)

    def test_cli_valid_reports_and_discloses_evidence_limit(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["executed"]["security"], 3)
        self.assertFalse(payload["declarations_prove_execution"])

    def test_cli_missing_security_report_fails(self):
        self.security.unlink()
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertIn("security", result.stderr.lower())

    def test_cli_failure_result_cannot_pass(self):
        self.integration.write_text('<testsuite><testcase name="x"><failure/></testcase></testsuite>')
        self.assertEqual(self.run_cli().returncode, 1)

    def test_cli_does_not_execute_declared_commands(self):
        marker = self.root / "SHOULD_NOT_EXIST"
        data = valid_evidence()
        data["pentest"]["commands"] = [f"touch {marker}"]
        self.save_evidence(data)
        self.assertEqual(self.run_cli().returncode, 0)
        self.assertFalse(marker.exists())

    def test_cli_fifo_does_not_hang(self):
        self.security.unlink()
        os.mkfifo(self.security)
        self.assertEqual(self.run_cli().returncode, 1)

    def test_cli_bad_repository_and_sha(self):
        for argument, value in [("--repository", "../escape"), ("--head-sha", "not-a-sha")]:
            with self.subTest(argument=argument):
                command = self.command()
                command[command.index(argument) + 1] = value
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
