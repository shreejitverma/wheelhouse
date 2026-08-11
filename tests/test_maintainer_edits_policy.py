#!/usr/bin/env python3
"""Offline order and fail-closed tests for maintainer-edits policy."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import apply_decision  # noqa: E402
import maintainer_edits_policy as policy  # noqa: E402
import reconcile  # noqa: E402
import render_card  # noqa: E402
import wheelhouse_core as core  # noqa: E402

_failures = []


def check(name, condition):
    print(("ok   " if condition else "FAIL ") + name)
    if not condition:
        _failures.append(name)


def source_pr():
    return {
        "state": "OPEN",
        "isCrossRepository": True,
        "headRefName": "feature",
        "headRefOid": "head",
        "maintainerCanModify": True,
        "headRepository": {
            "nameWithOwner": "org/fork",
            "isFork": True,
            "owner": {"login": "org", "__typename": "Organization"},
        },
    }


def policy_item():
    derived = core.derive_pushability(source_pr())
    return {
        "repo": "demo",
        "number": 7,
        "head_sha": "head",
        "maintainer_edits_policy": {
            "version": 1,
            "mode": derived["mode"],
            "reason": derived["reason"],
            "head_sha": "head",
            "source": derived["source"],
        },
    }


def unverified_policy_item():
    pr = source_pr()
    pr["maintainerCanModify"] = None
    pr["headRepository"] = {
        "nameWithOwner": "alice/fork",
        "isFork": True,
        "owner": {"login": "alice", "__typename": "User"},
    }
    derived = core.derive_pushability(pr)
    item = policy_item()
    item.update(
        {
            "number": 8,
            "kind": "pr-review",
            "priority": "med",
            "title": "Source permission unavailable",
            "author": "contributor",
            "bucket": core.PUSHABILITY_UNVERIFIED,
            "comp": "pass",
            "tests": "pass",
            "pushability": core.PUSHABILITY_UNVERIFIED,
        }
    )
    item["maintainer_edits_policy"] = {
        "version": 1,
        "mode": derived["mode"],
        "reason": derived["reason"],
        "head_sha": "head",
        "source": derived["source"],
    }
    return item


def test_notice_then_card_then_exact_close():
    calls = []
    comments = []
    saved = (
        policy.core.get_owner,
        policy.core.maintainers,
        policy.core.gh_graphql_pr,
        policy.core.gh_rest,
    )
    policy.core.get_owner = lambda: "owner"
    policy.core.maintainers = lambda: {"owner"}
    policy.core.gh_graphql_pr = lambda *_args: source_pr()

    def rest(path, method=None, fields=None, **_kwargs):
        calls.append((path, method, fields))
        if method == "POST":
            comment = {"id": 99, "body": fields["body"], "user": {"login": "owner"}}
            comments.append(comment)
            return comment
        if method == "PATCH":
            return {"state": "closed"}
        return [comments]

    policy.core.gh_rest = rest
    try:
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "scan.json"
            actions = Path(directory) / "actions.json"
            notices = Path(directory) / "notices.json"
            attached = Path(directory) / "attached.json"
            close_actions = Path(directory) / "close-actions.json"
            close_results = Path(directory) / "close-results.json"
            dark_item = policy_item()
            dark_item["repo"] = "dark"
            scan.write_text(
                json.dumps(
                    {
                        "repos": {
                            "demo": {"ok": True},
                            "dark": {"ok": False, "warning": "unreadable"},
                        },
                        "items": [policy_item(), unverified_policy_item(), dark_item],
                    }
                ),
                encoding="utf-8",
            )
            policy.prepare(str(scan), str(actions))
            prepared_actions = json.loads(actions.read_text(encoding="utf-8"))
            policy.notify(str(actions), str(notices))
            notice_result = json.loads(notices.read_text(encoding="utf-8"))[0]
            policy.attach_notices(str(scan), str(notices), str(attached))
            attached_items = json.loads(attached.read_text(encoding="utf-8"))["items"]
            attached_item = attached_items[0]
            unverified_card = render_card.render(attached_items[1])
            unverified_state = core.parse_state_block(unverified_card["body"])
            close_actions.write_text(
                json.dumps(
                    [
                        {
                            "card_issue": 17,
                            "repo": "demo",
                            "number": 7,
                            "comment_id": 99,
                            "policy": attached_item["maintainer_edits_policy"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            policy.close(str(close_actions), str(close_results))
            close_result = json.loads(close_results.read_text(encoding="utf-8"))[0]
    finally:
        (
            policy.core.get_owner,
            policy.core.maintainers,
            policy.core.gh_graphql_pr,
            policy.core.gh_rest,
        ) = saved
    writes = [(path, method) for path, method, _fields in calls if method]
    notice = next((fields["body"] for _path, method, fields in calls if method == "POST"), "")
    check(
        "policy: production scan items honor repository health",
        len(prepared_actions) == 1
        and prepared_actions[0]["repo"] == "demo"
        and "phase" not in attached_items[2]["maintainer_edits_policy"],
    )
    check(
        "policy: unverified source remains an inert retryable card",
        unverified_state.get("maintainer_edits_policy", {}).get("mode")
        == core.PUSHABILITY_UNVERIFIED
        and "Source permission check" in unverified_card["body"]
        and "<!-- opt:" not in unverified_card["body"],
    )
    check("policy: notice precedes target close", writes == [
        ("/repos/owner/demo/issues/7/comments", "POST"),
        ("/repos/owner/demo/issues/7", "PATCH"),
    ])
    check("policy: notice has exact head-bound marker", 'wheelhouse-maintainer-edits-required:v1 {"head_sha":"head"}' in notice)
    check("policy: notice explains the contributor requirement", "Allow edits from maintainers" in notice and "Organization-owned forks" in notice)
    check("policy: notice result binds its comment", notice_result == {"repo": "demo", "number": 7, "head_sha": "head", "status": "notified", "comment_id": 99})
    check("policy: exact reread closes only after audit handoff", close_result["status"] == "closed" and close_result["card_issue"] == 17)


def test_ingest_route_enforces_source_policy_before_projection():
    rejected = source_pr()
    rejected.update({"title": "Rejected fork", "author": {"login": "contributor"}, "updatedAt": "2026-01-01T00:00:00Z"})
    uncertain = dict(rejected)
    uncertain["headRepository"] = None
    saved = (policy.core.get_owner, policy.core.gh_graphql_pr)
    policy.core.get_owner = lambda: "owner"
    try:
        with tempfile.TemporaryDirectory() as directory:
            item_path = Path(directory) / "item.json"
            actions_path = Path(directory) / "actions.json"
            item_path.write_text(json.dumps({"repo": "demo", "number": 7, "kind": "pr-review", "head_sha": "hint", "auto_triage": True}), encoding="utf-8")
            policy.core.gh_graphql_pr = lambda *_args: rejected
            policy.route_item(str(item_path), str(actions_path))
            routed = json.loads(item_path.read_text(encoding="utf-8"))
            actions = json.loads(actions_path.read_text(encoding="utf-8"))

            item_path.write_text(json.dumps({"repo": "demo", "number": 8, "kind": "pr-review", "head_sha": "hint", "auto_triage": True}), encoding="utf-8")
            policy.core.gh_graphql_pr = lambda *_args: uncertain
            policy.route_item(str(item_path), str(actions_path))
            retryable = json.loads(item_path.read_text(encoding="utf-8"))
            retry_actions = json.loads(actions_path.read_text(encoding="utf-8"))

            item_path.write_text(json.dumps({"repo": "demo", "number": 9, "kind": "pr-review", "auto_triage": True}), encoding="utf-8")
            policy.core.gh_graphql_pr = lambda *_args: (_ for _ in ()).throw(RuntimeError("unreadable"))
            policy.route_item(str(item_path), str(actions_path))
            revision_unavailable = json.loads(item_path.read_text(encoding="utf-8"))
            revision_unavailable_card = render_card.render(revision_unavailable)
    finally:
        policy.core.get_owner, policy.core.gh_graphql_pr = saved
    check(
        "policy: ingest reject becomes inert before PR projection",
        routed["maintainer_edits_policy"]["mode"] == core.PUSHABILITY_FORK_REJECT
        and routed["auto_triage"] is False
        and "target_observation" not in routed
        and len(actions) == 1,
    )
    check(
        "policy: ingest uncertainty stays retryable without a notice action",
        retryable["maintainer_edits_policy"]["mode"] == core.PUSHABILITY_UNVERIFIED
        and retryable["auto_triage"] is False
        and retry_actions == [],
    )
    check(
        "policy: ingest read failure without a head still creates an inert card",
        revision_unavailable["head_sha"] == ""
        and core.parse_state_block(revision_unavailable_card["body"])
        .get("maintainer_edits_policy", {})
        .get("mode")
        == core.PUSHABILITY_UNVERIFIED
        and "<!-- opt:" not in revision_unavailable_card["body"],
    )


def test_action_admission_rechecks_live_source_policy():
    saved = (apply_decision.core.get_owner, apply_decision.core.gh_graphql_pr)
    apply_decision.core.get_owner = lambda: "owner"
    try:
        apply_decision.core.gh_graphql_pr = lambda *_args: source_pr()
        rejected = apply_decision._live_pr_source_policy("owner", "demo", 7)
        apply_decision.core.gh_graphql_pr = lambda *_args: (_ for _ in ()).throw(RuntimeError("unreadable"))
        uncertain = apply_decision._live_pr_source_policy("owner", "demo", 7)
        editable_pr = source_pr()
        editable_pr["headRepository"] = {
            "nameWithOwner": "alice/fork",
            "isFork": True,
            "owner": {"login": "alice", "__typename": "User"},
        }
        apply_decision.core.gh_graphql_pr = lambda *_args: editable_pr
        editable = apply_decision._live_pr_source_policy("owner", "demo", 7)
    finally:
        apply_decision.core.get_owner, apply_decision.core.gh_graphql_pr = saved
    check("policy: stale action sees deterministic fork reject", rejected["mode"] == core.PUSHABILITY_FORK_REJECT)
    check("policy: stale action fails closed on unreadable evidence", uncertain["mode"] == core.PUSHABILITY_UNVERIFIED)
    check("policy: editable personal fork remains actionable", editable["mode"] == core.PUSHABILITY_PERSONAL_FORK_EDITABLE)


def test_execute_rechecks_source_permission_after_revision():
    target_writes = []
    saved = (
        apply_decision.core.get_owner,
        apply_decision.core.gh_graphql_pr,
        apply_decision.core.gh_rest,
    )
    apply_decision.core.get_owner = lambda: "owner"
    apply_decision.core.gh_graphql_pr = lambda *_args: source_pr()

    def rest(path, method=None, fields=None, **_kwargs):
        if method:
            target_writes.append((path, method, fields))
        return {"head": {"sha": "head"}}

    apply_decision.core.gh_rest = rest
    old_output = os.environ.get("GITHUB_OUTPUT")
    old_env = {key: os.environ.get(key) for key in (
        "DECISION", "FREE_TEXT", "TARGET_REPO", "TARGET_NUMBER", "HEAD_SHA",
        "KIND", "TARGET_REVISION",
    )}
    try:
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "output")
            os.environ.update(
                {
                    "GITHUB_OUTPUT": output,
                    "DECISION": "close",
                    "FREE_TEXT": "",
                    "TARGET_REPO": "demo",
                    "TARGET_NUMBER": "7",
                    "HEAD_SHA": "head",
                    "KIND": "pr-review",
                    "TARGET_REVISION": "head",
                }
            )
            apply_decision.cmd_execute()
            values = dict(
                line.split("=", 1)
                for line in Path(output).read_text(encoding="utf-8").splitlines()
                if "=" in line
            )
    finally:
        apply_decision.core.get_owner, apply_decision.core.gh_graphql_pr, apply_decision.core.gh_rest = saved
        if old_output is None:
            os.environ.pop("GITHUB_OUTPUT", None)
        else:
            os.environ["GITHUB_OUTPUT"] = old_output
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    check(
        "policy: final action gate routes revoked permission to reconciliation",
        values.get("terminal_state") == "retryable"
        and values.get("source_policy_mode") == core.PUSHABILITY_FORK_REJECT,
    )
    check("policy: final action gate performs no target write", target_writes == [])


def test_unreadable_source_never_contacts_or_closes():
    calls = []
    saved = (policy.core.get_owner, policy.core.maintainers, policy.core.gh_graphql_pr, policy.core.gh_rest)
    policy.core.get_owner = lambda: "owner"
    policy.core.maintainers = lambda: {"owner"}
    policy.core.gh_graphql_pr = lambda *_args: (_ for _ in ()).throw(RuntimeError("target unreadable"))
    policy.core.gh_rest = lambda *args, **kwargs: calls.append((args, kwargs))
    try:
        with tempfile.TemporaryDirectory() as directory:
            actions = Path(directory) / "actions.json"
            results = Path(directory) / "results.json"
            actions.write_text(json.dumps([policy_item()]), encoding="utf-8")
            policy.notify(str(actions), str(results))
            result = json.loads(results.read_text(encoding="utf-8"))[0]
    finally:
        policy.core.get_owner, policy.core.maintainers, policy.core.gh_graphql_pr, policy.core.gh_rest = saved
    check("policy: unreadable source is retryable", result["status"] == "error")
    check("policy: unreadable source has no target write", calls == [])


def test_notice_phase_refreshes_an_existing_inert_card():
    before = policy_item()
    pending = dict(before["maintainer_edits_policy"])
    after = dict(pending)
    after.update({"phase": "notice-posted", "target_comment_id": 99})
    updated = dict(before)
    updated["maintainer_edits_policy"] = after
    check(
        "policy: same notice state does not refresh repeatedly",
        render_card.maintainer_edits_policy_stale(before, {"maintainer_edits_policy": pending}) is False,
    )
    check(
        "policy: verified notice refreshes the inert audit card",
        render_card.maintainer_edits_policy_stale(updated, {"maintainer_edits_policy": pending}) is True,
    )


def test_policy_cards_bypass_pr_projection_and_supersede_locked_state():
    item = policy_item()
    item.update(
        {
            "kind": "pr-review",
            "priority": "med",
            "title": "Needs source policy",
            "author": "contributor",
            "bucket": "maintainer-edits-required",
            "comp": "pass",
            "tests": "pass",
            "url": "https://github.com/owner/demo/pull/7",
            "pushability": core.PUSHABILITY_FORK_REJECT,
        }
    )
    saved = (
        render_card.lookup_card_lifecycle,
        render_card._create_and_verify_card,
        render_card.get_card,
        render_card._get_lifecycle_issue,
        render_card.ensure_labels,
        render_card._gh,
    )
    created = []
    render_card.lookup_card_lifecycle = lambda _item: {
        "open": None,
        "reusable": None,
    }
    render_card._create_and_verify_card = lambda _item, card: created.append(card) or 17
    try:
        created_number = render_card.upsert_card(item)
        created_state = core.parse_state_block(created[0]["body"])

        old_state = {
            "repo": "demo",
            "number": 7,
            "kind": "pr-review",
            "head_sha": "head",
        }
        live = {
            "number": 17,
            "title": "Old decision",
            "body": "<!-- wheelhouse-state: %s -->"
            % json.dumps(old_state, separators=(",", ":")),
            "labels": [
                {"name": "repo:demo"},
                {"name": "target:demo-7"},
                {"name": "kind:pr-review"},
                {"name": "blocked"},
            ],
            "author": {"login": "app/github-actions"},
            "state": "OPEN",
            "updatedAt": "2026-01-01T00:00:00Z",
            "comments": 0,
        }
        initial = json.loads(json.dumps(live))
        render_card.get_card = lambda _number: json.loads(json.dumps(initial))
        render_card._get_lifecycle_issue = lambda _number: json.loads(json.dumps(live))
        render_card.ensure_labels = lambda _labels: None

        def edit_card(args, check=True):
            if args[:3] != ["issue", "edit", "17"]:
                raise AssertionError(args)
            body_path = args[args.index("--body-file") + 1]
            live["body"] = Path(body_path).read_text(encoding="utf-8")
            live["title"] = args[args.index("--title") + 1]
            names = {row["name"] for row in live["labels"]}
            index = 3
            while index < len(args):
                if args[index] == "--add-label":
                    names.add(args[index + 1])
                    index += 2
                elif args[index] == "--remove-label":
                    names.discard(args[index + 1])
                    index += 2
                else:
                    index += 1
            live["labels"] = [{"name": name} for name in sorted(names)]
            return type("Result", (), {"stdout": "", "stderr": "", "returncode": 0})()

        render_card._gh = edit_card
        refreshed_number = render_card.upsert_card(item, existing=initial)
        refreshed_state = core.parse_state_block(live["body"])
        refreshed_labels = {row["name"] for row in live["labels"]}
    finally:
        (
            render_card.lookup_card_lifecycle,
            render_card._create_and_verify_card,
            render_card.get_card,
            render_card._get_lifecycle_issue,
            render_card.ensure_labels,
            render_card._gh,
        ) = saved
    check(
        "policy: missing PR observation still creates inert audit card",
        created_number == 17
        and created_state.get("maintainer_edits_policy")
        == item["maintainer_edits_policy"]
        and "<!-- opt:" not in created[0]["body"],
    )
    check(
        "policy: locked card transitions to verified inert audit state",
        refreshed_number == 17
        and refreshed_state.get("maintainer_edits_policy")
        == item["maintainer_edits_policy"]
        and "blocked" not in refreshed_labels
        and "needs-decision" in refreshed_labels
        and render_card.MAINTAINER_EDITS_REQUIRED_LABEL in refreshed_labels,
    )


def test_policy_handoff_requires_trusted_card_identity():
    item = policy_item()
    item.update({"kind": "pr-review", "priority": "med"})
    live_policy = dict(item["maintainer_edits_policy"])
    live_policy.update({"phase": "notice-posted", "target_comment_id": 99})
    item["maintainer_edits_policy"] = live_policy
    state = {
        "repo": "demo",
        "number": 7,
        "kind": "pr-review",
        "maintainer_edits_policy": live_policy,
    }
    card = {
        "number": 17,
        "body": "<!-- wheelhouse-state: %s -->" % json.dumps(state, separators=(",", ":")),
        "labels": [
            {"name": "needs-decision"},
            {"name": "repo:demo"},
            {"name": "target:demo-7"},
            {"name": "kind:pr-review"},
        ],
        "author": {"login": "app/github-actions"},
        "state": "OPEN",
    }
    accepted = reconcile.policy_action_for_card(card, item, live_policy)
    forged_author = dict(card)
    forged_author["author"] = {"login": "attacker"}
    ambiguous_kind = dict(card)
    ambiguous_kind["labels"] = card["labels"] + [{"name": "kind:ci-approval"}]
    check(
        "policy: trusted audit card admits close handoff",
        accepted
        == {
            "card_issue": 17,
            "repo": "demo",
            "number": 7,
            "comment_id": 99,
            "policy": live_policy,
        },
    )
    check(
        "policy: user-authored state cannot admit close handoff",
        reconcile.policy_action_for_card(forged_author, item, live_policy) is None,
    )
    check(
        "policy: ambiguous managed labels cannot admit close handoff",
        reconcile.policy_action_for_card(ambiguous_kind, item, live_policy) is None,
    )


def test_record_binds_terminal_target_evidence_atomically():
    policy_state = {
        "repo": "demo",
        "number": 7,
        "head_sha": "head",
        "maintainer_edits_policy": {
            "version": 1,
            "mode": core.PUSHABILITY_FORK_REJECT,
            "phase": "notice-posted",
            "target_comment_id": 99,
        },
    }
    card = {"number": 17, "body": "body", "labels": [{"name": "needs-decision"}], "state": "OPEN"}
    calls = []
    saved = (policy.render_card.get_card, policy.render_card.issue_is_open, policy.core.parse_state_block, policy.render_card.close_card)
    policy.render_card.get_card = lambda _number: card
    policy.render_card.issue_is_open = lambda _card: True
    policy.core.parse_state_block = lambda _body: dict(policy_state)
    policy.render_card.close_card = lambda *args, **kwargs: calls.append((args, kwargs))
    try:
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results.json"
            results.write_text(json.dumps([{"status": "closed", "card_issue": 17, "repo": "demo", "number": 7, "head_sha": "head", "comment_id": 99}]), encoding="utf-8")
            policy.record(str(results))
    finally:
        policy.render_card.get_card, policy.render_card.issue_is_open, policy.core.parse_state_block, policy.render_card.close_card = saved
    kwargs = calls[0][1] if calls else {}
    terminal = (kwargs.get("terminal_state") or {}).get(render_card.MAINTAINER_EDITS_POLICY_FIELD) or {}
    check("policy: record closes exactly one matching audit card", len(calls) == 1 and kwargs.get("label") == "resolved")
    check("policy: terminal record binds comment and close result", terminal.get("target_comment_id") == 99 and terminal.get("target_close_result") == "closed")
    check("policy: terminal close drops operational label", render_card.MAINTAINER_EDITS_CLOSING_LABEL in kwargs.get("remove_labels", set()))


def main():
    test_notice_then_card_then_exact_close()
    test_ingest_route_enforces_source_policy_before_projection()
    test_action_admission_rechecks_live_source_policy()
    test_execute_rechecks_source_permission_after_revision()
    test_unreadable_source_never_contacts_or_closes()
    test_notice_phase_refreshes_an_existing_inert_card()
    test_policy_cards_bypass_pr_projection_and_supersede_locked_state()
    test_policy_handoff_requires_trusted_card_identity()
    test_record_binds_terminal_target_evidence_atomically()
    if _failures:
        raise SystemExit("%d FAILED: %s" % (len(_failures), ", ".join(_failures)))
    print("all maintainer-edits policy tests passed")


if __name__ == "__main__":
    main()
