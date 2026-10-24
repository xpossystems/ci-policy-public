"""Behavioral checks for the additive GitHub merge-protection payload.

Validation notes (2026-10-23): tests were written before protection.py.
RED: the first 6 contract tests failed because the generator was absent;
the expanded 14-test suite then had 11 failures before implementation.
GREEN: all 14 passed after implementation. Post-implementation break checks
then covered parser abbreviations, control characters, and credential leakage.
FINAL: all 17 unit, CLI integration, and adversarial tests passed.
Independent-review follow-up: a new test failed with 0 approvals in both scopes;
after enabling 1 approval, code owners, and last-push approval, all 18 passed.
Run: python3 -m unittest discover -s tests -p test_protection.py -v
These are local generator/API-payload checks, not live GitHub enforcement tests.
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


POLICY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = hashlib.sha1(b"trusted policy fixture").hexdigest()


class ProtectionContractTests(unittest.TestCase):
    def setUp(self):
        path = POLICY_ROOT / "protection.py"
        self.assertTrue(path.is_file(), "the required ruleset generator is not implemented")
        spec = importlib.util.spec_from_file_location("policy_protection", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def payload(self, **overrides):
        values = {
            "scope": "organization",
            "owner": "xpossystems",
            "source_repository_id": 123456,
            "source_ref": SOURCE_SHA,
        }
        values.update(overrides)
        return self.module.generate_ruleset(**values)

    def rules(self, payload):
        return {rule["type"]: rule for rule in payload["rules"]}

    def test_organization_covers_current_and_future_repositories_without_bypass(self):
        payload = self.payload()
        self.assertEqual(payload["enforcement"], "active")
        self.assertEqual(payload["target"], "branch")
        self.assertEqual(payload["bypass_actors"], [])
        self.assertEqual(payload["conditions"]["repository_name"]["include"], ["~ALL"])
        self.assertEqual(payload["conditions"]["repository_name"]["exclude"], [])
        refs = payload["conditions"]["ref_name"]
        self.assertEqual(refs["exclude"], [])
        self.assertTrue({"~DEFAULT_BRANCH", "refs/heads/main", "refs/heads/master", "refs/heads/release/**"}.issubset(refs["include"]))
        self.assertNotIn("~ALL", refs["include"], "development branches must remain pushable")

    def test_required_workflow_is_pinned_to_immutable_source_commit(self):
        rule = self.rules(self.payload())["workflows"]["parameters"]
        self.assertFalse(rule["do_not_enforce_on_create"])
        self.assertEqual(rule["workflows"], [{
            "path": ".github/workflows/feature-quality.yml",
            "repository_id": 123456,
            "sha": SOURCE_SHA,
        }])

    def test_missing_checks_cannot_be_waived_by_branch_creation_or_any_source(self):
        rules = self.rules(self.payload())
        self.assertIn("pull_request", rules)
        self.assertIn("non_fast_forward", rules)
        self.assertIn("deletion", rules)
        checks = rules["required_status_checks"]["parameters"]
        self.assertTrue(checks["strict_required_status_checks_policy"])
        self.assertFalse(checks["do_not_enforce_on_create"])
        self.assertEqual(checks["required_status_checks"], [{
            "context": "Feature quality / required", "integration_id": 15368,
        }])

    def test_repository_scope_uses_only_supported_repository_rules(self):
        payload = self.payload(scope="repository", owner="Rocky-Xpos")
        self.assertEqual(set(payload["conditions"]), {"ref_name"})
        self.assertNotIn("workflows", self.rules(payload))
        self.assertEqual(payload["bypass_actors"], [])
        self.assertIn("required_status_checks", self.rules(payload))

    def test_payload_cannot_replace_existing_ruleset(self):
        payload = self.payload()
        self.assertNotIn("id", payload)
        self.assertNotIn("ruleset_id", payload)
        self.assertNotIn("source", payload)
        self.assertEqual(set(payload), {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"})

    def test_independent_review_is_mandatory_for_tdd_and_pentest_evidence(self):
        for scope, owner in [("organization", "xpossystems"), ("repository", "Rocky-Xpos")]:
            with self.subTest(scope=scope):
                pull_request = self.rules(self.payload(scope=scope, owner=owner))["pull_request"]["parameters"]
                self.assertEqual(pull_request["required_approving_review_count"], 1)
                self.assertTrue(pull_request["require_last_push_approval"])
                self.assertTrue(pull_request["require_code_owner_review"])
                self.assertTrue(pull_request["dismiss_stale_reviews_on_push"])

    def test_mutating_one_payload_does_not_weaken_later_payloads(self):
        first = self.payload()
        first["bypass_actors"].append({"actor_type": "OrganizationAdmin"})
        first["conditions"]["ref_name"]["exclude"].append("~ALL")
        second = self.payload()
        self.assertEqual(second["bypass_actors"], [])
        self.assertEqual(second["conditions"]["ref_name"]["exclude"], [])

    def test_rejects_untrusted_owners_and_personal_organization_scope(self):
        for owner in ["someone-else", "xpossystems/ci-policy-public", "xpossystems\n", "", None, "$(touch /tmp/not-authorized)"]:
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                self.payload(owner=owner)
        with self.assertRaises(ValueError):
            self.payload(owner="Rocky-Xpos", scope="organization")
        self.assertEqual(self.payload(owner="XPOSSYSTEMS"), self.payload())

    def test_rejects_mutable_malformed_and_placeholder_refs(self):
        refs = ["main", "refs/heads/main", "v1", "<SOURCE_SHA>", "REPLACE_WITH_40_CHARACTER_COMMIT_SHA", "0" * 40, "f" * 40, "a" * 39, "a" * 41, "g" * 40, SOURCE_SHA + "\n", None, 42]
        for ref in refs:
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.payload(source_ref=ref)
        self.assertEqual(self.payload(source_ref=SOURCE_SHA.upper()), self.payload())

    def test_rejects_invalid_ids_and_scopes(self):
        for value in [0, -1, True, False, None, "123456", 1.5, 2 ** 63]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.payload(source_repository_id=value)
        for scope in ["repo", "Organization", "all", "", None]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                self.payload(scope=scope)

    def test_post_implementation_control_character_and_homoglyph_attacks(self):
        for ref in [SOURCE_SHA + "\x00", SOURCE_SHA + "\r", "\t" + SOURCE_SHA, "ａ" * 40, "deadbeef" * 5, "0123456789" * 4]:
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.payload(source_ref=ref)
        for owner in ["хpossystems", "xpossystems\x00", "xpossystems ", "../xpossystems", "xpossystems\r\nRocky-Xpos"]:
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                self.payload(owner=owner)


class ProtectionCliIntegrationTests(unittest.TestCase):
    def run_cli(self, *arguments, cwd=None, env=None):
        return subprocess.run(
            [sys.executable, str(POLICY_ROOT / "protection.py"), *arguments],
            text=True, capture_output=True, cwd=cwd, env=env, timeout=10,
        )

    def common_arguments(self):
        return ["--source-repository-id", "123456", "--source-ref", SOURCE_SHA]

    def test_organization_cli_is_deterministic_pure_json(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments = ["--scope", "organization", *self.common_arguments()]
            first = self.run_cli(*arguments, cwd=directory)
            second = self.run_cli(*arguments, cwd=directory)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(first.stderr, "")
            payload = json.loads(first.stdout)
            self.assertEqual(payload["enforcement"], "active")
            self.assertEqual(payload["conditions"]["repository_name"]["include"], ["~ALL"])
            self.assertEqual(list(Path(directory).iterdir()), [], "generator must not write files or apply rules")

    def test_repository_cli_emits_warning_separately_from_valid_payload(self):
        result = self.run_cli("--scope", "repository", "--owner", "Rocky-Xpos", *self.common_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(json.loads(result.stdout)["conditions"]), {"ref_name"})
        self.assertIn("workflow identity", result.stderr)
        self.assertIn("administration", result.stderr)

    def test_missing_required_argument_fails_with_no_payload(self):
        result = self.run_cli("--scope", "organization")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_untrusted_arguments_are_data_and_emit_no_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            injected = f"$(touch {marker})"
            for field, value in [("--owner", injected), ("--source-ref", injected), ("--source-repository-id", "1;touch " + str(marker))]:
                with self.subTest(field=field):
                    arguments = ["--scope", "organization", *self.common_arguments(), field, value]
                    result = self.run_cli(*arguments, cwd=directory)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse(marker.exists())

    def test_no_apply_or_ruleset_replacement_option(self):
        for argument in ["--apply", "--ruleset-id", "--bypass", "--disable"]:
            with self.subTest(argument=argument):
                result = self.run_cli("--scope", "organization", *self.common_arguments(), argument)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_post_implementation_abbreviations_cannot_select_policy_scope(self):
        result = self.run_cli("--sco", "organization", *self.common_arguments())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_post_implementation_ambient_credentials_are_never_exposed(self):
        env = dict(os.environ, GH_TOKEN="LOCAL_TEST_CREDENTIAL_SENTINEL", GITHUB_TOKEN="LOCAL_TEST_CREDENTIAL_SENTINEL")
        result = self.run_cli("--scope", "organization", *self.common_arguments(), env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("LOCAL_TEST_CREDENTIAL_SENTINEL", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
