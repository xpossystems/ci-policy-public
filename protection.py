#!/usr/bin/env python3
"""Generate a new, additive GitHub ruleset; never contact GitHub or apply it.

Submit the JSON only with POST /orgs/xpossystems/rulesets or
POST /repos/{known-owner}/{repo}/rulesets. Do not PUT over, delete, or weaken
existing rulesets. Before applying, independently verify that the source ID is
xpossystems/ci-policy-public, its supplied SHA exists and contains the trusted workflow,
the required check name matches actual runs, and the plan supports the rules.

Organization scope pins the trusted workflow by ``sha`` (the API's ``ref`` field
is for a branch or tag). Repository scope cannot require a specific workflow:
GitHub Actions app identity does not distinguish workflows with the same job
name. It needs independent protection of the workflow/configuration or a trusted
external verifier. Neither scope prevents an administration credential from
editing/deleting the ruleset; agents must not possess that credential.
The independent review requirement also needs distinct author/pusher and human
reviewer identities: agents using Rocky's account cannot self-approve a PR.

Optional organization visibility targeting uses GitHub's system property rather
than a repository name list. Pair the visibility with a compatible trusted source:
private source workflows can serve only private repositories; public sources can
serve every visibility. A visibility filter is invalid at repository scope.

Schema references, checked 2026-10-23:
https://docs.github.com/en/rest/orgs/rules#create-an-organization-repository-ruleset
https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset
GitHub Actions app ID was verified using GET /apps/github-actions on 2026-10-23.
"""

from __future__ import annotations

import argparse
import json
import re
import sys


ORGANIZATION = "xpossystems"
KNOWN_OWNERS = frozenset({ORGANIZATION, "rocky-xpos"})
GITHUB_ACTIONS_APP_ID = 15368
WORKFLOW_PATH = ".github/workflows/feature-quality.yml"
REQUIRED_CHECK = "Feature quality / required"
REPOSITORY_LIMITATION = (
    "WARNING: Repository rules bind the GitHub Actions app, not workflow identity; "
    "protect CI configuration independently or use a trusted verifier. Agents "
    "with administration access can change or delete rulesets. This command "
    "generates a new ruleset only; preserve all existing rulesets."
)


def generate_ruleset(*, scope: str, owner: str, source_repository_id: int, source_ref: str,
                     visibility: str | None = None) -> dict:
    """Return a fresh POST request body, rejecting ambiguous or unsafe inputs."""
    if scope not in ("organization", "repository"):
        raise ValueError("scope must be organization or repository")
    if not isinstance(owner, str) or owner.lower() not in KNOWN_OWNERS:
        raise ValueError("owner must be xpossystems or Rocky-Xpos")
    if scope == "organization" and owner.lower() != ORGANIZATION:
        raise ValueError("organization scope is only supported for xpossystems")
    if visibility is not None:
        if not isinstance(visibility, str) or visibility not in ("private", "public", "internal"):
            raise ValueError("visibility must be private, public, or internal")
        if scope != "organization":
            raise ValueError("visibility targeting is only supported for organization scope")
    if type(source_repository_id) is not int or not 0 < source_repository_id < 2 ** 63:
        raise ValueError("source repository ID must be a positive 64-bit integer")
    if not isinstance(source_ref, str) or re.fullmatch(r"[0-9a-fA-F]{40}", source_ref) is None:
        raise ValueError("source ref must be an immutable 40-hex commit SHA")
    source_sha = source_ref.lower()
    if len(set(source_sha)) == 1 or source_sha in {"deadbeef" * 5, "0123456789" * 4, "1234567890" * 4}:
        raise ValueError("source ref must be a verified commit SHA, not a placeholder")

    conditions = {
        "ref_name": {
            "include": [
                "~DEFAULT_BRANCH", "refs/heads/main", "refs/heads/master",
                "refs/heads/release/**", "refs/heads/release/**/*",
            ],
            "exclude": [],
        },
    }
    rules = [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {
            "type": "pull_request",
            "parameters": {
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": True,
                "require_last_push_approval": True,
                "required_approving_review_count": 1,
                "required_review_thread_resolution": True,
            },
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"context": REQUIRED_CHECK, "integration_id": GITHUB_ACTIONS_APP_ID},
                ],
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
            },
        },
    ]
    if scope == "organization":
        if visibility is None:
            conditions["repository_name"] = {"include": ["~ALL"], "exclude": [], "protected": True}
        else:
            conditions["repository_property"] = {
                "include": [{"name": "visibility", "source": "system", "property_values": [visibility]}],
                "exclude": [],
            }
        rules.append({
            "type": "workflows",
            "parameters": {
                "do_not_enforce_on_create": False,
                "workflows": [{"path": WORKFLOW_PATH, "repository_id": source_repository_id, "sha": source_sha}],
            },
        })
    return {
        "name": "Mandatory feature quality gates",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": conditions,
        "rules": rules,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate an additive active ruleset JSON payload; never applies changes.",
        epilog="Use POST to create a separate ruleset; never replace existing rulesets. Verify source ownership and SHA before applying.",
        allow_abbrev=False,
    )
    parser.add_argument("--scope", required=True, choices=("organization", "repository"))
    parser.add_argument("--owner", help="Known owner; defaults to xpossystems for organization, Rocky-Xpos for repository")
    parser.add_argument("--visibility", choices=("private", "public", "internal"), action="append",
                        help="Organization-only system visibility filter; omission preserves all-repository targeting")
    parser.add_argument("--source-repository-id", required=True, type=int, help="Verified numeric ID of xpossystems/ci-policy-public")
    parser.add_argument("--source-ref", required=True, help="Verified immutable 40-hex commit SHA of xpossystems/ci-policy-public")
    args = parser.parse_args(argv)
    if args.visibility is not None and len(args.visibility) != 1:
        parser.error("--visibility must be specified at most once")
    owner = args.owner if args.owner is not None else (ORGANIZATION if args.scope == "organization" else "Rocky-Xpos")
    try:
        payload = generate_ruleset(
            scope=args.scope, owner=owner,
            source_repository_id=args.source_repository_id, source_ref=args.source_ref,
            visibility=args.visibility[0] if args.visibility else None,
        )
    except ValueError as error:
        parser.error(str(error))
    if args.scope == "repository":
        print(REPOSITORY_LIMITATION, file=sys.stderr)
    print(json.dumps(payload, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
