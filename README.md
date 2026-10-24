# Public feature quality policy

This repository provides a pinned CI action, workflow generators, and tests.
Every new feature or function requires TDD, unit and integration coverage,
hands-on break and security testing, remediation, and successful retesting.
Missing, failed, skipped, or unapproved evidence blocks the gate.

`ci-configurations.json` records the exact reviewed CI setup file transitions
for the public rollout. The clean verifier recomputes the entire Git diff and
requires every before/after blob and regular-file mode to match. This only
omits declarations for new application functionality when the change is exactly
that approved setup. Approved real suites, security scanning, and independent
review remain required. Added source files or even a one-byte workflow edit
return to the normal feature gate; a manifest never grants an execution profile.

`profiles.json` approves only this policy repository. The application repositories
in `public-repositories.json` have no approved test execution profiles yet and
must fail the planning gate. This is enforcement, not a claim that application
test coverage has been implemented. A reviewer must approve meaningful native
unit, integration, and security suites before an application profile is added.

## Distribution

1. Commit and review the action source to establish an immutable public SHA.
2. Generate `feature-quality.yml` and `category-tests.yml` with
   `python workflow.py --kind required --action-sha <reviewed-action-sha>` and
   `python workflow.py --kind baseline --action-sha <reviewed-action-sha>`.
   Save both under `.github/workflows/`, then commit them separately.
3. Generate application `feature-tests.yml` using `--kind repository
   --policy-sha <reviewed-workflow-sha>`.
4. Organization rules should require the public `feature-quality.yml` workflow
   by its repository ID and immutable workflow commit. Personal public repositories
   need the full generated required workflow copied locally so its terminal check
   stays exactly `Feature quality / required`.
5. Require a human code owner review, dismiss stale reviews, require approval of
   the latest push, and leave no bypass actors. Preserve existing protections.

Use `protection.py --scope organization --visibility public` with the verified
source repository ID and workflow SHA to target current and future public
repositories using GitHub's system visibility property. Private and internal
repositories need their own visibility filters with a compatible source workflow.
The filter is invalid at repository scope; duplicate filters are rejected.

GitHub repository status checks bind the Actions app, not a specific workflow.
Independent review of workflow and configuration changes remains necessary.
An administrator can change repository protections; administration credentials
must not be available to coding agents if protection against them is required.
The author cannot approve their own pull request. No merge-queue verification
is claimed; unsupported merge-group evidence fails closed.

GitHub documents public workflow visibility and required-workflow constraints:
https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules

## Verification

Install `requirements-dev.txt` and run `python -m unittest discover -s tests -v`.
The approved profile separately runs unit, integration, and adversarial security
suites. Tests use temporary local files, repositories and test data. No production
or third-party attack targets are authorized by this policy.
`distribution-manifest.json` records the exported file hashes at packaging time;
new commits and generated workflow pins must receive their own review.
