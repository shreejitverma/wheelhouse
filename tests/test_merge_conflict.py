#!/usr/bin/env python3
"""Exercise Phase 0 conflict readiness and source-permission policy, offline."""

import io
import os
import sys
from contextlib import redirect_stderr

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import render_card  # noqa: E402
import wheelhouse_core as core  # noqa: E402

_failures = []


def check(name, condition):
    print(("ok   " if condition else "FAIL ") + name)
    if not condition:
        _failures.append(name)


def run_check(name, fn):
    try:
        fn()
    except Exception as error:
        check(name, False)
        print("       %s" % error)


def rollup():
    nodes = [
        {"__typename": "CheckRun", "name": "Gate", "conclusion": "SUCCESS", "status": "COMPLETED"},
        {"__typename": "CheckRun", "name": "test", "conclusion": "SUCCESS", "status": "COMPLETED"},
    ]
    return {"state": "SUCCESS", "contexts": {"totalCount": 2, "pageInfo": {"hasNextPage": False}, "nodes": nodes}}


def pr(number, *, mergeable="MERGEABLE", source="same", maintainer_can_modify=True):
    head = {"name": "demo", "nameWithOwner": "owner/demo", "isFork": False, "owner": {"login": "owner", "__typename": "User"}}
    cross = False
    if source == "personal":
        cross = True
        head = {"name": "fork", "nameWithOwner": "contributor/fork", "isFork": True, "owner": {"login": "contributor", "__typename": "User"}}
    elif source == "org":
        cross = True
        head = {"name": "fork", "nameWithOwner": "org/fork", "isFork": True, "owner": {"login": "org", "__typename": "Organization"}}
    elif source == "missing":
        cross = True
        head = {"name": "fork", "nameWithOwner": "contributor/fork", "isFork": True, "owner": {"login": "contributor"}}
    elif source == "nullable":
        cross = True
        head = None
    return {
        "number": number,
        "title": "PR %d" % number,
        "body": "",
        "isDraft": False,
        "isCrossRepository": cross,
        "mergeable": mergeable,
        "maintainerCanModify": maintainer_can_modify,
        "updatedAt": "2026-08-10T00:00:00Z",
        "changedFiles": 1,
        "author": {"login": "contributor", "__typename": "User"},
        "headRefName": "feature-%d" % number,
        "headRefOid": "sha%d" % number,
        "baseRefName": "main",
        "baseRefOid": "base",
        "headRepository": head,
        "baseRepository": {"name": "demo", "owner": {"login": "owner"}},
        "labels": {"totalCount": 0, "pageInfo": {"hasNextPage": False}, "nodes": []},
        "closingIssuesReferences": {"totalCount": 0, "pageInfo": {"hasNextPage": False}, "nodes": []},
        "commits": {"nodes": [{"commit": {"statusCheckRollup": rollup()}}]},
    }


def scan(nodes, *, action_runs=None):
    cfg = {"name": "demo", "compliance_check": "Gate", "test_check_patterns": ["test"]}
    data = {"defaultBranchRef": {"name": "main"}, "pullRequests": {"totalCount": len(nodes), "pageInfo": {"hasNextPage": False}, "nodes": nodes}, "issues": {"totalCount": 0, "pageInfo": {"hasNextPage": False}, "nodes": []}}
    calls = {"action_runs": [], "target_writes": []}
    save = (core.gh_graphql, core.immutable_compare_files, core._list_action_required_runs, core.gh_rest, core.load_config, os.environ.get("OWNER"), os.environ.get("GITHUB_REPOSITORY_OWNER"))
    core.gh_graphql = lambda _owner, _repo: data
    core.immutable_compare_files = lambda *_args: (["src/main.py"], True, True)
    core._list_action_required_runs = lambda _slug, ref, sha: (calls["action_runs"].append((ref, sha)) or (action_runs or ([], "")))
    core.gh_rest = lambda path, method=None, fields=None, **_kwargs: calls["target_writes"].append((path, method, fields)) or []
    core.load_config = lambda: {"repos": {"demo": cfg}, "maintainer": ""}
    os.environ["OWNER"] = "owner"
    os.environ["GITHUB_REPOSITORY_OWNER"] = "owner"
    try:
        with redirect_stderr(io.StringIO()):
            result, items = core.build_repo("owner", cfg, False, auto_approve_ci=False)
    finally:
        core.gh_graphql, core.immutable_compare_files, core._list_action_required_runs, core.gh_rest, core.load_config, old_owner, old_repo_owner = save
        if old_owner is None: os.environ.pop("OWNER", None)
        else: os.environ["OWNER"] = old_owner
        if old_repo_owner is None: os.environ.pop("GITHUB_REPOSITORY_OWNER", None)
        else: os.environ["GITHUB_REPOSITORY_OWNER"] = old_repo_owner
    return result, items, calls


def test_readiness_ignores_mergeability():
    check("conflicting green PR is merge-ready", core.classify(False, "pass", "green", True, False, "CONFLICTING") == "merge-ready")
    check("unknown green PR is merge-ready", core.classify(False, "pass", "green", True, False, "UNKNOWN") == "merge-ready")
    check("conflicting missing-test PR is review-needed", core.classify(False, "pass", "none", True, False, "CONFLICTING") == "review-needed")


def test_conflict_cards_without_nudge_or_poll():
    result, items, calls = scan([pr(42, mergeable="CONFLICTING")])
    check("conflict scan is healthy", result["ok"] is True)
    check("conflict emits normal PR card", len(items) == 1 and items[0]["bucket"] == "merge-ready")
    check("merge state stays informational on item", items and items[0]["mergeable"] == "CONFLICTING")
    check("conflict does not list CI runs for same-repo PR", calls["action_runs"] == [])
    check(
        "conflict posts no contributor rebase nudge",
        not any(method == "POST" and "/comments" in path for path, method, _fields in calls["target_writes"]),
    )


def test_pushability_policy_before_ci():
    rejected = core.derive_pushability(pr(7, source="org"))
    editable = core.derive_pushability(pr(8, source="personal"))
    uncertain = core.derive_pushability(pr(9, source="missing"))
    nullable = core.derive_pushability(pr(10, source="nullable"))
    check("organization fork deterministically rejects", rejected["mode"] == core.PUSHABILITY_FORK_REJECT)
    check("personal editable fork is eligible for later assist", editable["mode"] == core.PUSHABILITY_PERSONAL_FORK_EDITABLE)
    check("incomplete source facts remain non-destructive", uncertain["mode"] == core.PUSHABILITY_UNVERIFIED)
    check("nullable source repository remains non-destructive", nullable["mode"] == core.PUSHABILITY_UNVERIFIED)
    result, items, calls = scan([pr(7, source="org"), pr(9, source="missing"), pr(10, source="nullable")])
    by_number = {item["number"]: item for item in items}
    check("policy scan is healthy", result["ok"] is True)
    check("reject gets an inert audit item", by_number[7]["bucket"] == "maintainer-edits-required" and by_number[7]["maintainer_edits_policy"]["mode"] == core.PUSHABILITY_FORK_REJECT)
    check("uncertain source gets retryable inert item", by_number[9]["bucket"] == "source-permission-unverified" and by_number[9]["maintainer_edits_policy"]["mode"] == core.PUSHABILITY_UNVERIFIED)
    check("nullable source gets retryable inert item", by_number[10]["bucket"] == "source-permission-unverified" and by_number[10]["maintainer_edits_policy"]["mode"] == core.PUSHABILITY_UNVERIFIED)
    check("reject and uncertainty never probe fork CI", calls["action_runs"] == [])
    rendered = render_card.render(by_number[7], owner="owner")
    check("policy card has no actionable checkbox markers", "<!-- opt:" not in rendered["body"])
    check("policy card carries terminal audit label", render_card.MAINTAINER_EDITS_REQUIRED_LABEL in rendered["labels"])


def test_manual_conflict_copy_blames_not_contributor():
    import apply_decision
    save_rest = apply_decision.core.gh_rest
    calls = []
    def fake_rest(path, method=None, fields=None, **_kwargs):
        calls.append((path, method, fields))
        if method == "PUT": raise RuntimeError("merge conflict")
        return {
            "head": {"sha": "head", "repo": {"full_name": "owner/demo"}},
            "base": {"sha": "base", "repo": {"full_name": "owner/demo"}},
            "state": "open",
        }
    apply_decision.core.gh_rest = fake_rest
    try:
        message, terminal = apply_decision.do_merge("owner", "demo", 1, "head")
    finally:
        apply_decision.core.gh_rest = save_rest
    check("conflict remains retryable until assist ships", terminal == "none")
    check("conflict copy makes the captain own manual resolution", "captain must resolve" in message and "without asking the contributor to rebase" in message)


def main():
    test_readiness_ignores_mergeability()
    test_conflict_cards_without_nudge_or_poll()
    test_pushability_policy_before_ci()
    test_manual_conflict_copy_blames_not_contributor()
    if _failures:
        print("%d FAILED: %s" % (len(_failures), ", ".join(_failures)))
        raise SystemExit(1)
    print("all merge conflict tests passed")


if __name__ == "__main__":
    main()
