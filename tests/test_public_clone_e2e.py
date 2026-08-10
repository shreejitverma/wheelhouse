#!/usr/bin/env python3
"""Bounded network E2E for anonymous public HTTPS Git cloning.

The second scenario is the axi community-catalog acceptance case: a real
contributed package is inspected at a pinned revision and the trusted
post-turn verifier must let the VISION-alignment verdict stand.
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import auto_merge as am  # noqa: E402
import nl_readonly_search as nls  # noqa: E402
import render_card  # noqa: E402

URL = "https://github.com/octocat/Hello-World.git"
CATALOG_PACKAGE_URL = "https://github.com/laizhenyoong/supabase-axi.git"
CATALOG_PACKAGE_REF = "main"
CATALOG_PACKAGE_COMMIT = "55d92773fc4a48dd859340777c7410b547e9a8f2"
CATALOG_PACKAGE_OBSERVATIONS = 51
SECRET_MARKERS = {
    "GH_TOKEN": "e2e-gh-secret-marker",
    "GITHUB_TOKEN": "e2e-github-secret-marker",
    "CLAUDE_CODE_OAUTH_TOKEN": "e2e-model-secret-marker",
    "ACTIONS_RUNTIME_TOKEN": "e2e-runner-secret-marker",
    "AWS_SECRET_ACCESS_KEY": "e2e-cloud-secret-marker",
}


VISION_CRITERION = (
    "Every new package proposed for either catalog may receive a positive "
    "admission verdict only after independent source review of the package "
    "itself."
)
VISION_BODY = """# Vision

## Catalog

%s
The reviewer must inspect the actual package source at an exact pinned revision or release.

<!-- wheelhouse-vision-source-dependencies: %s -->
""" % (
    VISION_CRITERION,
    json.dumps(
        {
            "version": 1,
            "complete": True,
            "criteria": [
                {
                    "id": "catalog-source-review",
                    "quote_sha256": hashlib.sha256(
                        VISION_CRITERION.encode("utf-8")
                    ).hexdigest(),
                    "external_source_required": True,
                    "selector": {"changed_paths_any": ["catalog.yaml"]},
                }
            ],
        },
        separators=(",", ":"),
    ),
)


def catalog_source_review_e2e(parent):
    """axi#130 class: inspect a real contributed package at a pinned revision
    and prove the VISION-alignment verdict survives trusted admission."""
    owner, repo, number = "kunchenguid", "axi", 130
    head_sha, base_sha, vision_sha = "a" * 40, "b" * 40, "c" * 40
    event_key = "d" * 64
    changed_paths = ["README.md", "catalog.yaml", "docs/index.html"]

    runner_temp = os.path.join(parent, "runner-temp")
    os.makedirs(runner_temp, exist_ok=True)
    claims_file = os.path.join(parent, "claims.json")

    # 1. The model's turn: an unprivileged in-turn clone that records only an
    #    untrusted claim. This is the exact step that used to die with
    #    "trusted public clone provenance recording failed".
    request = os.path.join(parent, "search-request.json")
    with open(request, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "op": "public_clone",
                "url": CATALOG_PACKAGE_URL,
                "ref": CATALOG_PACKAGE_REF,
            },
            handle,
        )
    turn = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "nl_readonly_search.py")],
        cwd=ROOT,
        env=dict(
            os.environ,
            GITHUB_WORKSPACE=ROOT,
            RUNNER_TEMP=runner_temp,
            WHEELHOUSE_SEARCH_ACTION="triage.pr.search",
            WHEELHOUSE_SEARCH_ALLOWED_REPOS="[]",
            WHEELHOUSE_SEARCH_REQUEST=request,
            WHEELHOUSE_PUBLIC_CLONE_CLAIMS=claims_file,
        ),
        text=True,
        capture_output=True,
        timeout=nls.PUBLIC_CLONE_TIMEOUT_SECONDS + 120,
    )
    if turn.returncode != 0:
        raise SystemExit("in-turn catalog clone failed: %s" % turn.stderr.strip())
    inspected = json.loads(turn.stdout)
    commit = inspected["commit"]
    if commit != CATALOG_PACKAGE_COMMIT:
        raise SystemExit(
            "catalog package main did not resolve pinned revision %s (got %s)"
            % (CATALOG_PACKAGE_COMMIT, commit)
        )

    # 2. The trusted post-turn step: re-clone and derive every recorded fact.
    #    The task carries the exact source-review binding production binds.
    vision_file = os.path.join(parent, "vision.md")
    with open(vision_file, "w", encoding="utf-8") as handle:
        handle.write(VISION_BODY)
    vision_digest = hashlib.sha256(VISION_BODY.encode("utf-8")).hexdigest()
    snapshot = {
        "number": number,
        "changed_files": len(changed_paths),
        "base": {"sha": base_sha, "repo": {"full_name": "%s/%s" % (owner, repo)}},
        "head": {"sha": head_sha},
    }
    facts = render_card.build_triage_target_facts(
        snapshot,
        {
            "base_commit": {"sha": base_sha},
            "total_commits": 1,
            "commits": [{"sha": head_sha}],
            "files": [{"filename": path} for path in changed_paths],
        },
        json.loads(json.dumps(snapshot)),
        owner=owner,
        repo=repo,
        number=number,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    payload = render_card.serialize_triage_target_facts(facts)
    facts_file = os.path.join(parent, "target-facts.json")
    with open(facts_file, "wb") as handle:
        handle.write(payload)
    facts_digest = hashlib.sha256(payload).hexdigest()
    task = {
        "metadata": {
            "action": "triage.pr.search",
            "idempotencyKey": event_key,
            "target": {
                "owner": owner,
                "repo": repo,
                "number": number,
                "kind": "pr-review",
                "revision": head_sha,
            },
            "sourceReview": {
                "baseSha": base_sha,
                "visionSha": vision_sha,
                "visionContentSha256": vision_digest,
                "targetFactsSha256": facts_digest,
                "targetRepositoryCommit": head_sha,
            },
        }
    }
    task_path = os.path.join(parent, "task.json")
    with open(task_path, "w", encoding="utf-8") as handle:
        json.dump(task, handle)
    provenance_file = os.path.join(parent, "public-clone-provenance.json")
    if not nls.verify_public_clone_claims(
        task_path,
        claims_file,
        provenance_file,
        clone_root=os.path.join(parent, "verify", nls.PUBLIC_CLONE_DIR),
    ):
        raise SystemExit("trusted post-turn verification produced no provenance")
    records = json.load(open(provenance_file, encoding="utf-8"))
    if len(records) != 1 or records[0]["status"] != "succeeded":
        raise SystemExit("verified provenance is not a single successful record")
    if records[0]["source"]["resolvedCommit"] != CATALOG_PACKAGE_COMMIT:
        raise SystemExit(
            "verifier did not reproduce pinned revision %s"
            % CATALOG_PACKAGE_COMMIT
        )
    observations = records[0]["manifest"]["observations"]
    if len(observations) != CATALOG_PACKAGE_OBSERVATIONS:
        raise SystemExit(
            "pinned revision %s produced %d observations, expected %d"
            % (
                CATALOG_PACKAGE_COMMIT,
                len(observations),
                CATALOG_PACKAGE_OBSERVATIONS,
            )
        )

    # 3. Trusted admission of a model-shaped verdict citing that inspection.
    binding = {
        "action": "triage.pr.search",
        "event_key": event_key,
        "owner": owner,
        "repo": repo,
        "number": number,
        "revision": head_sha,
        "base_sha": base_sha,
        "vision_sha": vision_sha,
        "vision_content_sha256": vision_digest,
        "target_facts_sha256": facts_digest,
    }
    candidate = {
        "summary": "Adds supabase-axi to the community catalog.",
        "product_implications": "Pinned source review satisfies the catalog policy.",
        "recommended_action": "merge",
        "recommended_reason": "Independent pinned-source inspection supports admission.",
        "evidence": "target.txt: inspected the package at %s" % commit,
        "vision_evidence": {
            "target_owner": owner,
            "target_repo": repo,
            "target_number": number,
            "target_facts_sha256": binding["target_facts_sha256"],
            "vision_sha": vision_sha,
            "vision_content_sha256": vision_digest,
            "base_sha": base_sha,
            "target_head_sha": head_sha,
            "applicable_criteria": [
                {
                    "id": "catalog-source-review",
                    "quote": VISION_CRITERION,
                    "external_source_required": True,
                }
            ],
        },
        "source_provenance": {
            "url": records[0]["source"]["url"],
            "requested_ref": CATALOG_PACKAGE_REF,
            "resolved_commit": commit,
            "inspected_files": [
                {"path": row["path"], "sha256": row["sha256"]}
                for row in observations[:3]
            ],
        },
        "automerge": {
            "behavior_class": "A",
            "behavior_assertions": [],
            "changes_existing_or_default_behavior": False,
            "optin_default_off": False,
            "aligns_with_vision": True,
            "recommend_merge": True,
            "external_source_required": True,
        },
    }
    admitted = render_card.enforce_triage_source_provenance(
        candidate, provenance_file, vision_file, facts_file, **binding
    )
    if not (
        admitted["automerge"].get("aligns_with_vision") is True
        and admitted["automerge"].get("recommend_merge") is True
    ):
        raise SystemExit("verified pinned-source inspection did not clear VISION")
    if not am.verdict_eligible(
        render_card.normalize_triage(admitted)["automerge_verdict"]
    )[0]:
        raise SystemExit("admitted source-reviewed verdict is not auto-merge eligible")

    # Negative control: the pre-fix state, where no provenance was ever
    # produced, must still strip the VISION-positive fields.
    unverified = render_card.enforce_triage_source_provenance(
        candidate,
        os.path.join(parent, "absent-provenance.json"),
        vision_file,
        facts_file,
        **binding,
    )
    if "aligns_with_vision" in unverified["automerge"]:
        raise SystemExit("missing provenance must strip the VISION-positive fields")
    print(
        "catalog source-review E2E passed: %s@%s (%d observed files)"
        % (CATALOG_PACKAGE_URL, commit[:12], len(observations))
    )


def main():
    original = {key: os.environ.get(key) for key in SECRET_MARKERS}
    os.environ.update(SECRET_MARKERS)
    try:
        with tempfile.TemporaryDirectory() as parent:
            runner_temp = os.path.join(parent, "runner-temp")
            os.makedirs(runner_temp)
            clone_root = os.path.realpath(
                os.path.join(runner_temp, nls.PUBLIC_CLONE_DIR)
            )
            request = os.path.join(parent, "search-request.json")
            with open(request, "w", encoding="utf-8") as handle:
                json.dump({"op": "public_clone", "url": URL}, handle)
            child_env = dict(os.environ)
            child_env.update(
                {
                    "GITHUB_WORKSPACE": ROOT,
                    "RUNNER_TEMP": runner_temp,
                    "WHEELHOUSE_SEARCH_ACTION": "nl-decision.search",
                    "WHEELHOUSE_SEARCH_ALLOWED_REPOS": "[]",
                    "WHEELHOUSE_SEARCH_REQUEST": request,
                }
            )
            clone = subprocess.run(
                [
                    sys.executable,
                    os.path.join(ROOT, "scripts", "nl_readonly_search.py"),
                ],
                cwd=ROOT,
                env=child_env,
                text=True,
                capture_output=True,
                timeout=(
                    nls.PUBLIC_CLONE_TIMEOUT_SECONDS
                    + nls.PUBLIC_DNS_TIMEOUT_SECONDS
                    + nls.PUBLIC_GIT_LOCAL_TIMEOUT_SECONDS
                    + 60
                ),
            )
            if clone.returncode != 0:
                raise SystemExit("wheelhouse-search failed: %s" % clone.stderr.strip())
            result = json.loads(clone.stdout)
            readme = os.path.join(result["location"], "README")
            if result["url"] != URL:
                raise SystemExit("canonical URL mismatch")
            if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", result["commit"]):
                raise SystemExit("resolved commit SHA missing")
            if (
                not os.path.isfile(readme)
                or "Hello World" not in open(readme, encoding="utf-8").read()
            ):
                raise SystemExit("cloned source is not inspectable")
            if os.path.lexists(os.path.join(result["location"], ".git")):
                raise SystemExit("Git administration reached retained source")
            for directory, _, names in os.walk(result["location"]):
                for name in names:
                    path = os.path.join(directory, name)
                    if os.path.islink(path) or os.path.getsize(path) > 1024 * 1024:
                        continue
                    with open(path, "rb") as handle:
                        data = handle.read()
                    if any(
                        marker.encode() in data for marker in SECRET_MARKERS.values()
                    ):
                        raise SystemExit(
                            "credential marker reached retained clone data"
                        )
            cleanup = subprocess.run(
                [
                    sys.executable,
                    os.path.join(ROOT, "scripts", "nl_readonly_search.py"),
                    "cleanup",
                ],
                cwd=ROOT,
                env=child_env,
                text=True,
                capture_output=True,
                timeout=10,
            )
            if cleanup.returncode != 0 or os.path.lexists(clone_root):
                raise SystemExit("deterministic clone cleanup failed")
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    print("public clone E2E passed: %s" % URL)
    with tempfile.TemporaryDirectory() as parent:
        catalog_source_review_e2e(parent)


if __name__ == "__main__":
    main()
