"""Test the generated workflow's actual YAML and dependency barrier behavior.

TDD notes (2026-10-23): 11 tests were written before workflow.py; 10 failed
because the generator was missing. The first implementation made all 11 pass.
Scanner isolation, checkout-ref, and verifier-token regression tests then had
4 failures before the hardening changes; all 14 passed after those changes.
Post-implementation adversarial checks exercise malformed dependency states
and attempts to substitute scanner configuration using a filesystem symlink.
The changed-test follow-up first failed 2 history/base-context assertions;
adding full checkout history and the trusted base SHA made all 16 tests pass.
Baseline follow-up: new generator/CLI tests failed before implementation
(3 failures and 3 missing-method errors). Shared plan/run fragments and the
pinned repository caller made the expanded 21-test suite pass.
Docker ignore parser follow-up: four contract assertions failed before splitting
the scans; all 24 workflow tests then passed. Trivy 0.70.0 also executed the
generated scanner options against a local Dockerfile.dockerignore containing a
synthetic credential and a Dockerfile with a root user. Both passes returned
exit 1 despite candidate-controlled suppression files; the parser error was
gone and the API's 14 existing high/critical findings remained visible.
Pip discovery follow-up: one new assertion failed before the environment flag
was added; all 25 tests passed afterward. The actual generated environment was
run through Trivy: vulnerable default, suffixed and split requirements files
were found, along with the synthetic ignore-file secret, despite candidate
suppression files. The scan returned exit 1.
Run: python3 -m unittest discover -s tests -p test_workflow.py -v
No live Actions run or external pentest is claimed by these local checks.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


POLICY_ROOT = Path(__file__).resolve().parents[1]
ACTION_SHA = hashlib.sha1(b"trusted central action fixture").hexdigest()


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        path = POLICY_ROOT / "workflow.py"
        self.assertTrue(path.is_file(), "trusted workflow generator is not implemented")
        spec = importlib.util.spec_from_file_location("policy_workflow", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.rendered = self.module.generate_workflow(action_sha=ACTION_SHA)
        self.workflow = yaml.safe_load(self.rendered)

    def test_always_runs_for_pull_requests_and_merge_queue_with_read_only_token(self):
        self.assertEqual(self.workflow["name"], "Feature quality")
        self.assertEqual(set(self.workflow["on"]), {"pull_request", "merge_group"})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotIn("pull_request_target", self.rendered)
        self.assertNotIn("paths-ignore", self.rendered)
        self.assertNotIn("cancel-in-progress", self.rendered)
        for event in self.workflow["on"].values():
            self.assertIn(event, (None, {}))

    def test_cross_repository_ruleset_workflow_has_explicit_unconditional_job(self):
        self.assertEqual(self.workflow['jobs']['plan'].get('if'), '${{ true }}')

    def test_every_action_is_immutable_and_checkout_credentials_are_not_persisted(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(step["uses"], "actions/checkout@11d5960a326750d5838078e36cf38b85af677262")
                    self.assertIs(step["with"]["persist-credentials"], False)
                    self.assertEqual(step["with"]["ref"], "${{ github.sha }}")
                    self.assertEqual(step["with"]["fetch-depth"], 0)
        self.assertNotIn("secrets.", self.rendered)
        self.assertNotIn("continue-on-error", self.rendered)

    def test_central_action_modes_and_runner_outputs_are_wired(self):
        jobs = self.workflow["jobs"]
        self.assertEqual(set(jobs), {"plan", "run", "scan", "required"})
        self.assertEqual(jobs["plan"]["outputs"], {
            "runner": "${{ steps.plan.outputs.runner }}",
            "python_version": "${{ steps.plan.outputs.python_version }}",
        })
        self.assertEqual(jobs["run"]["needs"], ["plan"])
        self.assertEqual(jobs["run"]["runs-on"], "${{ needs.plan.outputs.runner }}")
        central_steps = []
        for job in jobs.values():
            central_steps.extend(step for step in job["steps"] if step.get("uses", "").startswith("xpossystems/ci-policy-public@"))
        self.assertEqual({step["with"]["mode"] for step in central_steps}, {"plan", "run", "verify"})
        for step in central_steps:
            self.assertEqual(step["uses"], "xpossystems/ci-policy-public@" + ACTION_SHA)
            self.assertEqual(step["with"]["root"], "${{ github.workspace }}")
            self.assertEqual(step["with"]["reports"], "${{ runner.temp }}/quality-reports")
        setup = [step for step in jobs["run"]["steps"] if step.get("uses", "").startswith("actions/setup-python@")]
        self.assertEqual(len(setup), 1)
        self.assertEqual(setup[0]["uses"], "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065")
        self.assertEqual(setup[0]["with"]["python-version"], "${{ needs.plan.outputs.python_version }}")

    def test_reports_are_uploaded_even_on_failure_and_downloaded_before_verification(self):
        jobs = self.workflow["jobs"]
        uploads = [step for step in jobs["run"]["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        self.assertEqual(upload["uses"], "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02")
        self.assertEqual(upload["if"], "${{ always() }}")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertEqual(upload["with"]["name"], "feature-quality-evidence")
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/quality-reports")
        steps = jobs["required"]["steps"]
        download_index = next(i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/download-artifact@"))
        verify_index = next(i for i, step in enumerate(steps) if step.get("with", {}).get("mode") == "verify")
        self.assertLess(download_index, verify_index)
        download = steps[download_index]
        self.assertEqual(download["uses"], "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093")
        self.assertEqual(download["with"], {"name": "feature-quality-evidence", "path": "${{ runner.temp }}/quality-reports"})

    def test_security_scanner_fails_on_high_critical_findings_in_all_required_categories(self):
        scan = self.workflow["jobs"]["scan"]
        scanners = [step for step in scan["steps"] if step.get("uses", "").startswith("aquasecurity/trivy-action@")]
        self.assertEqual([step["with"]["scanners"] for step in scanners], ["vuln,secret", "misconfig"])
        for step in scanners:
            self.assertEqual(step["uses"], "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25")
            self.assertEqual(step["with"]["scan-type"], "fs")
            self.assertEqual(step["with"]["scan-ref"], ".")
            self.assertEqual(step["with"]["severity"], "HIGH,CRITICAL")
            self.assertEqual(str(step["with"]["exit-code"]), "1")
            self.assertNotIn("ignore-unfixed", step["with"])
            self.assertEqual(step["env"]["TRIVY_IGNORE_UNFIXED"], "false")

    def test_dockerignore_parser_exclusion_never_skips_vulnerability_or_secret_scanning(self):
        scanners = [step for step in self.workflow["jobs"]["scan"]["steps"] if step.get("uses", "").startswith("aquasecurity/trivy-action@")]
        self.assertEqual(len(scanners), 2)
        dependency_scan, configuration_scan = scanners
        self.assertNotIn("skip-files", dependency_scan["with"])
        self.assertNotIn("skip-dirs", dependency_scan["with"])
        self.assertNotIn("TRIVY_SKIP_FILES", dependency_scan.get("env", {}))
        self.assertNotIn("TRIVY_SKIP_DIRS", dependency_scan.get("env", {}))
        self.assertEqual(configuration_scan["with"]["skip-files"], "**/*.dockerignore")
        self.assertNotIn("skip-dirs", configuration_scan["with"])

    def test_configuration_scan_still_runs_after_dependency_findings_without_waiving_failure(self):
        scanners = [step for step in self.workflow["jobs"]["scan"]["steps"] if step.get("uses", "").startswith("aquasecurity/trivy-action@")]
        self.assertEqual(len(scanners), 2)
        self.assertEqual(scanners[1]["if"], "${{ !cancelled() }}")
        self.assertNotIn("continue-on-error", self.rendered)

    def test_dependency_scan_discovers_split_and_suffixed_pip_requirements(self):
        scanners = [step for step in self.workflow["jobs"]["scan"]["steps"] if step.get("uses", "").startswith("aquasecurity/trivy-action@")]
        self.assertEqual(scanners[0]["with"]["scanners"], "vuln,secret")
        self.assertEqual(scanners[0]["env"].get("TRIVY_FILE_PATTERNS"),
                         r"pip:(^|/)(requirements/[^/]+\.(txt|lock)|requirements[^/]*\.txt)$")
        # The pinned action has no file-patterns input; Trivy's supported env
        # flag is additive and must not alter the separate configuration pass.
        self.assertNotIn("file-patterns", scanners[0]["with"])
        self.assertNotIn("TRIVY_FILE_PATTERNS", scanners[1]["env"])

    def test_scan_uses_trusted_external_configuration_and_no_mutable_cache(self):
        scan = self.workflow["jobs"]["scan"]
        scanners = [step for step in scan["steps"] if step.get("uses", "").startswith("aquasecurity/trivy-action@")]
        self.assertEqual(len(scanners), 2)
        for step in scanners:
            self.assertEqual(str(step["with"]["cache"]).lower(), "false")
            self.assertEqual(step["with"]["cache-dir"], "${{ runner.temp }}/feature-quality-trivy/cache")
            self.assertEqual(step["with"]["trivy-config"], "${{ runner.temp }}/feature-quality-trivy/trivy.yaml")
            self.assertEqual(step["env"]["TRIVY_IGNOREFILE"], "${{ runner.temp }}/feature-quality-trivy/ignore")
            self.assertEqual(step["env"]["TRIVY_SECRET_CONFIG"], "${{ runner.temp }}/feature-quality-trivy/secret.yaml")
            self.assertEqual(step["with"]["version"], "v0.70.0")
            self.assertNotIn("trivyignores", step["with"])

    def test_scanner_config_creation_ignores_candidate_suppressions(self):
        steps = self.workflow["jobs"]["scan"]["steps"]
        prepare = next(step for step in steps if step.get("name") == "Prepare trusted scanner configuration")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            candidate = base / "candidate"
            runner_temp = base / "runner"
            candidate.mkdir()
            runner_temp.mkdir()
            for filename in ("trivy.yaml", "trivy-secret.yaml", ".trivyignore", ".trivyignore.yaml"):
                (candidate / filename).write_text("MALICIOUS_CANDIDATE_SUPPRESSION")
            result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", prepare["run"]], cwd=candidate, env=dict(os.environ, RUNNER_TEMP=str(runner_temp)), text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            trusted = runner_temp / "feature-quality-trivy"
            self.assertEqual(yaml.safe_load((trusted / "trivy.yaml").read_text()), {})
            self.assertEqual(yaml.safe_load((trusted / "secret.yaml").read_text()), {})
            self.assertEqual((trusted / "ignore").read_text(), "")
            self.assertEqual((candidate / ".trivyignore").read_text(), "MALICIOUS_CANDIDATE_SUPPRESSION")

    def test_api_read_token_is_only_exposed_to_trusted_verifier(self):
        required = self.workflow["jobs"]["required"]
        self.assertEqual(required["permissions"], {"contents": "read", "actions": "read", "pull-requests": "read"})
        for name, job in self.workflow["jobs"].items():
            for step in job["steps"]:
                if step.get("with", {}).get("mode") == "verify":
                    self.assertEqual(step["env"]["GITHUB_TOKEN"], "${{ github.token }}")
                else:
                    self.assertNotIn("GITHUB_TOKEN", step.get("env", {}))
            if name != "required":
                self.assertNotIn("actions", job.get("permissions", {}))
                self.assertNotIn("pull-requests", job.get("permissions", {}))

    def test_required_check_name_and_always_barrier_match_ruleset(self):
        required = self.workflow["jobs"]["required"]
        self.assertEqual(required["name"], "Feature quality / required")
        self.assertEqual(required["if"], "${{ always() }}")
        self.assertEqual(set(required["needs"]), {"plan", "run", "scan"})
        self.assertIn("run", required["steps"][0])
        self.assertEqual(required["steps"][0]["env"]["NEEDS_JSON"], "${{ toJSON(needs) }}")

    def test_untrusted_event_data_is_passed_in_environment_only(self):
        env = self.workflow["env"]
        self.assertEqual(env["QUALITY_REPOSITORY"], "${{ github.repository }}")
        self.assertIn("github.event.pull_request.head.sha", env["QUALITY_HEAD_SHA"])
        self.assertIn("github.event.merge_group.head_sha", env["QUALITY_HEAD_SHA"])
        self.assertEqual(env["QUALITY_PR_NUMBER"], "${{ github.event.pull_request.number || '' }}")
        self.assertNotIn("QUALITY_PR_BODY", env)
        self.assertEqual(env["QUALITY_EVENT_NAME"], "${{ github.event_name }}")
        self.assertEqual(env["QUALITY_BASE_SHA"], "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || '' }}")
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if "run" in step:
                    self.assertNotIn("${{", step["run"])

    def test_rejects_mutable_placeholder_and_injected_action_references(self):
        for invalid in ["main", "v1", "<ACTION_SHA>", "0" * 40, "f" * 40, "deadbeef" * 5, "a" * 39, ACTION_SHA + "\n", ACTION_SHA + ";echo unsafe", None, 42]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.module.generate_workflow(action_sha=invalid)
        self.assertEqual(self.module.generate_workflow(action_sha=ACTION_SHA.upper()), self.rendered)

    def test_dependency_barrier_executes_and_only_accepts_all_success(self):
        script = self.workflow["jobs"]["required"]["steps"][0]["run"]
        passing = {name: {"result": "success"} for name in ("plan", "run", "scan")}
        result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], env=dict(os.environ, NEEDS_JSON=json.dumps(passing)), text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in passing:
            for conclusion in ["failure", "cancelled", "skipped", "neutral", "", None]:
                with self.subTest(job=name, conclusion=conclusion):
                    failing = {key: dict(value) for key, value in passing.items()}
                    failing[name]["result"] = conclusion
                    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], env=dict(os.environ, NEEDS_JSON=json.dumps(failing)), text=True, capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)

    def test_post_implementation_barrier_rejects_missing_or_malformed_dependencies(self):
        script = self.workflow["jobs"]["required"]["steps"][0]["run"]
        cases = ["{}", "[]", "null", "not-json", '{"plan":{"result":"success"}}',
                 '{"plan":"success","run":{"result":"success"},"scan":{"result":"success"}}',
                 '{"plan":{},"run":{"result":"success"},"scan":{"result":"success"}}']
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            cases.append("__import__('os').system('touch " + str(marker) + "')")
            for value in cases:
                with self.subTest(value=value):
                    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], env=dict(os.environ, NEEDS_JSON=value), text=True, capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_post_implementation_scanner_config_symlink_attack_is_blocked(self):
        prepare = next(step for step in self.workflow["jobs"]["scan"]["steps"] if step.get("name") == "Prepare trusted scanner configuration")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            candidate = base / "candidate"
            runner_temp = base / "runner"
            candidate.mkdir()
            runner_temp.mkdir()
            (candidate / "trivy.yaml").write_text("malicious existing config")
            (runner_temp / "feature-quality-trivy").symlink_to(candidate, target_is_directory=True)
            result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", prepare["run"]], cwd=candidate, env=dict(os.environ, RUNNER_TEMP=str(runner_temp)), text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((candidate / "trivy.yaml").read_text(), "malicious existing config")
            self.assertEqual({path.name for path in candidate.iterdir()}, {"trivy.yaml"})


class WorkflowCliIntegrationTests(unittest.TestCase):
    def test_cli_returns_valid_yaml_without_mutating_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments = [sys.executable, str(POLICY_ROOT / "workflow.py"), "--action-sha", ACTION_SHA]
            first = subprocess.run(arguments, cwd=directory, text=True, capture_output=True, timeout=10)
            second = subprocess.run(arguments, cwd=directory, text=True, capture_output=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(first.stderr, "")
            self.assertEqual(yaml.safe_load(first.stdout)["name"], "Feature quality")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_invalid_action_sha_emits_no_partial_workflow(self):
        result = subprocess.run([sys.executable, str(POLICY_ROOT / "workflow.py"), "--action-sha", "refs/heads/main"], text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


class BaselineWorkflowTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("baseline_workflow", POLICY_ROOT / "workflow.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_baseline_reuses_all_category_execution_without_circular_verification(self):
        required = yaml.safe_load(self.module.generate_workflow(action_sha=ACTION_SHA))
        text = self.module.generate_baseline_workflow(ACTION_SHA)
        baseline = yaml.safe_load(text)
        self.assertEqual(set(baseline["on"]), {"workflow_call"})
        self.assertEqual(baseline["permissions"], {"contents": "read"})
        self.assertEqual(baseline["env"], required["env"])
        expected = copy.deepcopy({name: required["jobs"][name] for name in ("plan", "run")})
        step = next(step for step in expected['run']['steps'] if step.get('with', {}).get('mode') == 'run')
        step['with']['mode'] = 'baseline'
        self.assertEqual(baseline["jobs"], expected)
        self.assertNotIn('mode: run', text)
        self.assertIn('mode: baseline', text)
        self.assertNotIn("mode: verify", text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("aquasecurity/trivy-action", text)

    def test_repository_workflow_calls_only_pinned_central_baseline(self):
        text = self.module.generate_repository_workflow(ACTION_SHA)
        repository = yaml.safe_load(text)
        self.assertEqual(set(repository["on"]), {"pull_request", "workflow_dispatch"})
        self.assertEqual(repository["permissions"], {"contents": "read"})
        self.assertEqual(set(repository["jobs"]), {"tests"})
        self.assertEqual(repository["jobs"]["tests"]["uses"], "xpossystems/ci-policy-public/.github/workflows/category-tests.yml@" + ACTION_SHA)
        self.assertNotIn("secrets", repository["jobs"]["tests"])
        self.assertNotIn("secrets: inherit", text)
        self.assertNotIn("pull_request_target", text)

    def test_both_generators_refuse_mutable_placeholder_or_injected_refs(self):
        invalid_refs = ["main", "refs/heads/main", "0" * 40, "f" * 40, "deadbeef" * 5, "<POLICY_SHA>", ACTION_SHA + "\n", ACTION_SHA + ";echo hacked", None]
        for name in ("generate_baseline_workflow", "generate_repository_workflow"):
            generate = getattr(self.module, name)
            for invalid in invalid_refs:
                with self.subTest(generator=name, invalid=invalid), self.assertRaises(ValueError):
                    generate(invalid)
            self.assertEqual(generate(ACTION_SHA.upper()), generate(ACTION_SHA))

    def test_cli_selects_each_kind_without_changing_existing_default(self):
        with tempfile.TemporaryDirectory() as directory:
            for kind, flag, expected in [("required", "--action-sha", "Feature quality"), ("baseline", "--action-sha", "Feature category tests"), ("repository", "--policy-sha", "Feature tests")]:
                with self.subTest(kind=kind):
                    command = [sys.executable, str(POLICY_ROOT / "workflow.py"), "--kind", kind, flag, ACTION_SHA]
                    result = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(yaml.safe_load(result.stdout)["name"], expected)
                    self.assertEqual(result.stderr, "")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_rejects_wrong_or_ambiguous_pin_parameters_without_output(self):
        cases = [
            ["--kind", "repository", "--action-sha", ACTION_SHA],
            ["--kind", "baseline", "--policy-sha", ACTION_SHA],
            ["--policy-sha", ACTION_SHA],
            ["--kind", "required", "--action-sha", ACTION_SHA, "--policy-sha", ACTION_SHA],
            ["--kind", "repository"],
            ["--kind", "baseline", "--action-sha", "main"],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(POLICY_ROOT / "workflow.py"), *arguments], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
