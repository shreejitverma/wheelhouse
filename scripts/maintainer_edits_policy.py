#!/usr/bin/env python3
"""Apply and record the maintainer-edits contribution policy.

Phase 0 deliberately has no assisted merge or source-push credential. This CLI
separates the policy transaction so the only target-side order is:

  exact source proof -> policy notice -> default-token audit card ->
  exact source proof -> target close -> atomic terminal card record

It never receives, reads, or needs ASSISTED_MERGE_PUSH_TOKEN. That credential
is reserved for a later captain-initiated, assisted-conflict-resolution phase.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import render_card  # noqa: E402
import wheelhouse_core as core  # noqa: E402

POLICY_VERSION = 1
MARKER = "wheelhouse-maintainer-edits-required"


def _load(path, default):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default
    return value


def _write(path, value):
    Path(path).write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def _policy_record(action):
    policy = (
        (action.get("policy") or action.get(render_card.MAINTAINER_EDITS_POLICY_FIELD))
        if isinstance(action, dict)
        else None
    )
    if not isinstance(policy, dict):
        return None
    source = policy.get("source")
    if not isinstance(source, dict):
        return None
    head = str(policy.get("head_sha") or action.get("head_sha") or "").strip()
    repo = str(action.get("repo") or "").strip()
    try:
        number = int(action.get("number") or 0)
    except (TypeError, ValueError):
        number = 0
    if (
        not head
        or not repo
        or number < 1
        or policy.get("version") != POLICY_VERSION
        or policy.get("mode") != core.PUSHABILITY_FORK_REJECT
    ):
        return None
    return {
        "version": POLICY_VERSION,
        "repo": repo,
        "number": number,
        "head_sha": head,
        "source": source,
    }


def _marker(record):
    # Keep the contributor-visible marker deliberately minimal and exactly
    # head-bound. Source coordinates remain in the default-token audit card.
    return "<!-- %s:v1 %s -->" % (
        MARKER,
        json.dumps({"head_sha": record["head_sha"]}, separators=(",", ":")),
    )


def notice_body(record):
    return "\n".join(
        [
            "Automated notice: this pull request is being closed because its branch cannot be updated by repository maintainers.",
            "",
            "For pull requests from forks, contributing here requires a personal fork with **Allow edits from maintainers** enabled in the pull request sidebar. That permission lets maintainers resolve a small merge conflict directly on this same pull request, without asking you to rebase your work.",
            "",
            "Organization-owned forks cannot provide this GitHub permission. If you want to continue, enable the setting and reopen this PR, or open a replacement PR from a personal fork with the setting enabled.",
            "",
            _marker(record),
        ]
    )


def _trusted_existing_notice(comments, record, maintainers):
    needle = _marker(record)
    for comment in core._flatten_paginated_comments(comments):
        if not isinstance(comment, dict):
            continue
        if needle not in str(comment.get("body") or ""):
            continue
        if core._trusted_ask_author(core._event_author(comment), maintainers):
            return comment
    return None


def _current_policy(owner, repo, number):
    pr = core.gh_graphql_pr(owner, repo, number)
    policy = core.derive_pushability(pr)
    return pr, policy


def _matches(record, pr, policy):
    if not isinstance(pr, dict) or str(pr.get("state") or "").upper() != "OPEN":
        return False
    if policy.get("mode") != core.PUSHABILITY_FORK_REJECT:
        return False
    if str(pr.get("headRefOid") or "") != record["head_sha"]:
        return False
    source = policy.get("source")
    return isinstance(source, dict) and source == record["source"]


def _healthy_repos(scan):
    if not isinstance(scan, dict):
        return set()
    return {
        repo
        for repo, result in (scan.get("repos") or {}).items()
        if isinstance(repo, str)
        and isinstance(result, dict)
        and result.get("ok") is True
        and not result.get("truncated")
    }


def _scan_actions(scan):
    healthy_repos = _healthy_repos(scan)
    actions = []
    for item in scan.get("items") or [] if isinstance(scan, dict) else []:
        if not isinstance(item, dict) or item.get("repo") not in healthy_repos:
            continue
        record = _policy_record(item)
        if record:
            actions.append(
                {
                    "repo": record["repo"],
                    "number": record["number"],
                    "policy": item[render_card.MAINTAINER_EDITS_POLICY_FIELD],
                }
            )
    return actions


def prepare(scan_path, actions_path):
    _write(actions_path, _scan_actions(_load(scan_path, {})))


def _route_item(item):
    if not isinstance(item, dict) or item.get("kind") not in {"pr-review", "ci-approval"}:
        return item, None, True
    owner = core.get_owner()
    repo = str(item.get("repo") or "").strip()
    number = int(item.get("number") or 0)
    try:
        pr, pushability = _current_policy(owner, repo, number)
    except Exception as error:
        pr = {}
        pushability = {
            "mode": core.PUSHABILITY_UNVERIFIED,
            "reason": str(error)[:300] or "source permission evidence is unavailable",
            "source": {},
        }
    mode = pushability.get("mode")
    if mode not in {core.PUSHABILITY_FORK_REJECT, core.PUSHABILITY_UNVERIFIED}:
        item["pushability"] = mode
        return item, None, True
    head_sha = str(pr.get("headRefOid") or item.get("head_sha") or "")
    policy = {
        "version": POLICY_VERSION,
        "mode": mode,
        "reason": str(pushability.get("reason") or "source permission evidence is unavailable"),
        "head_sha": head_sha,
        "source": pushability.get("source") or {},
    }
    item.update(
        {
            "kind": "pr-review",
            "head_sha": head_sha,
            "title": str(pr.get("title") or item.get("title") or "(no title)"),
            "author": str(core._author_login(pr.get("author") or {}) or item.get("author") or "?"),
            "updated_at": str(pr.get("updatedAt") or item.get("updated_at") or ""),
            "bucket": "maintainer-edits-required" if mode == core.PUSHABILITY_FORK_REJECT else "source-permission-unverified",
            "comp": "unknown",
            "tests": "unknown",
            "pushability": mode,
            render_card.MAINTAINER_EDITS_POLICY_FIELD: policy,
            "auto_triage": False,
        }
    )
    item.pop("target_observation", None)
    item.pop("projection_ref", None)
    action = None
    if mode == core.PUSHABILITY_FORK_REJECT and _policy_record(item):
        action = {"repo": repo, "number": number, "policy": policy}
    return item, action, False


def route_item(item_path, actions_path):
    item, action, admitted = _route_item(_load(item_path, {}))
    _write(item_path, item)
    _write(actions_path, [action] if action else [])
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("admitted=%s\n" % ("true" if admitted else "false"))


def attach_item(item_path, results_path):
    item = _load(item_path, {})
    results = _load(results_path, [])
    if not isinstance(results, list):
        results = []
    notice = _notice_result_for_item(results, item) if isinstance(item, dict) else None
    policy = item.get(render_card.MAINTAINER_EDITS_POLICY_FIELD) if isinstance(item, dict) else None
    if isinstance(policy, dict):
        policy = dict(policy)
        if notice:
            policy["phase"] = "notice-posted"
            policy["target_comment_id"] = notice["comment_id"]
        else:
            policy.pop("phase", None)
            policy.pop("target_comment_id", None)
        item[render_card.MAINTAINER_EDITS_POLICY_FIELD] = policy
    _write(item_path, item)


def prepare_close(item_path, issue, actions_path):
    item = _load(item_path, {})
    try:
        issue = int(issue)
    except (TypeError, ValueError):
        issue = 0
    policy = item.get(render_card.MAINTAINER_EDITS_POLICY_FIELD) if isinstance(item, dict) else None
    actions = []
    if (
        issue > 0
        and isinstance(policy, dict)
        and policy.get("mode") == core.PUSHABILITY_FORK_REJECT
        and policy.get("phase") == "notice-posted"
    ):
        card = render_card.get_card(issue)
        try:
            state = render_card.trusted_open_target_card(card, item)
        except render_card.CardLifecycleError:
            state = None
        if state and state.get(render_card.MAINTAINER_EDITS_POLICY_FIELD) == policy:
            actions.append(
                {
                    "card_issue": issue,
                    "repo": item["repo"],
                    "number": int(item["number"]),
                    "comment_id": policy["target_comment_id"],
                    "policy": policy,
                }
            )
    _write(actions_path, actions)


def notify(actions_path, results_path):
    actions = _load(actions_path, [])
    if not isinstance(actions, list):
        actions = []
    owner = core.get_owner()
    maintainers = {login.casefold() for login in core.maintainers()}
    results = []
    for action in actions:
        record = _policy_record(action)
        result = {
            "repo": action.get("repo") if isinstance(action, dict) else "",
            "number": action.get("number") if isinstance(action, dict) else 0,
            "head_sha": record.get("head_sha") if record else "",
            "status": "deferred",
        }
        if not record:
            result["reason"] = "malformed policy action"
            results.append(result)
            continue
        try:
            pr, source_policy = _current_policy(
                owner, record["repo"], record["number"]
            )
            if not _matches(record, pr, source_policy):
                result["reason"] = "target/source policy changed before notice"
                results.append(result)
                continue
            slug = "%s/%s" % (owner, record["repo"])
            comments = core.gh_rest(
                "/repos/%s/issues/%s/comments?per_page=100" % (slug, record["number"]),
                paginate=True,
                slurp=True,
            )
            notice = _trusted_existing_notice(comments, record, maintainers)
            if notice is None:
                notice = core.gh_rest(
                    "/repos/%s/issues/%s/comments" % (slug, record["number"]),
                    method="POST",
                    fields={"body": notice_body(record)},
                )
            # The card writer must receive only a source identity that still
            # matches after the externally visible policy notice.
            pr, source_policy = _current_policy(
                owner, record["repo"], record["number"]
            )
            if not _matches(record, pr, source_policy):
                result["reason"] = "target/source policy changed after notice"
                results.append(result)
                continue
            comment_id = (notice or {}).get("id") if isinstance(notice, dict) else None
            try:
                comment_id = int(comment_id)
            except (TypeError, ValueError):
                result["reason"] = "policy notice response lacked a comment id"
                results.append(result)
                continue
            result.update({"status": "notified", "comment_id": comment_id})
        except Exception as error:
            # Keep the policy card non-actionable and retryable. Never claim a
            # notice or close a target after an unreadable source/target read.
            result.update({"status": "error", "reason": str(error)[:200]})
        results.append(result)
    _write(results_path, results)


def _notice_result_for_item(results, item):
    policy = item.get(render_card.MAINTAINER_EDITS_POLICY_FIELD)
    if not isinstance(policy, dict):
        return None
    for result in results:
        if not isinstance(result, dict) or result.get("status") != "notified":
            continue
        if (
            result.get("repo") == item.get("repo")
            and int(result.get("number") or 0) == int(item.get("number") or 0)
            and result.get("head_sha") == policy.get("head_sha")
        ):
            return result
    return None


def attach_notices(scan_path, results_path, output_path):
    scan = _load(scan_path, {})
    results = _load(results_path, [])
    if not isinstance(results, list):
        results = []
    if not isinstance(scan, dict):
        _write(output_path, scan)
        return
    healthy_repos = _healthy_repos(scan)
    for item in scan.get("items") or []:
        if not isinstance(item, dict) or item.get("repo") not in healthy_repos:
            continue
        notice = _notice_result_for_item(results, item)
        policy = item.get(render_card.MAINTAINER_EDITS_POLICY_FIELD)
        if not isinstance(policy, dict):
            continue
        policy = dict(policy)
        if notice:
            policy["phase"] = "notice-posted"
            policy["target_comment_id"] = notice["comment_id"]
        else:
            policy.pop("phase", None)
            policy.pop("target_comment_id", None)
        item[render_card.MAINTAINER_EDITS_POLICY_FIELD] = policy
    _write(output_path, scan)


def close(actions_path, results_path):
    actions = _load(actions_path, [])
    if not isinstance(actions, list):
        actions = []
    owner = core.get_owner()
    maintainers = {login.casefold() for login in core.maintainers()}
    results = []
    for action in actions:
        record = _policy_record(action)
        result = {
            "card_issue": action.get("card_issue") if isinstance(action, dict) else None,
            "repo": action.get("repo") if isinstance(action, dict) else "",
            "number": action.get("number") if isinstance(action, dict) else 0,
            "head_sha": record.get("head_sha") if record else "",
            "comment_id": action.get("comment_id") if isinstance(action, dict) else None,
            "status": "deferred",
        }
        if not record:
            result["reason"] = "malformed policy close action"
            results.append(result)
            continue
        try:
            comment_id = int(result["comment_id"])
        except (TypeError, ValueError):
            result["reason"] = "policy card lacks a target notice id"
            results.append(result)
            continue
        try:
            pr, source_policy = _current_policy(
                owner, record["repo"], record["number"]
            )
            if not _matches(record, pr, source_policy):
                result["reason"] = "target/source policy changed before close"
                results.append(result)
                continue
            slug = "%s/%s" % (owner, record["repo"])
            comments = core.gh_rest(
                "/repos/%s/issues/%s/comments?per_page=100" % (slug, record["number"]),
                paginate=True,
                slurp=True,
            )
            notice = _trusted_existing_notice(comments, record, maintainers)
            if not notice or int(notice.get("id") or 0) != comment_id:
                result["reason"] = "target policy notice is not trustworthy"
                results.append(result)
                continue
            # The exact source-proof reread occurs after the card is written and
            # immediately before target closure. No scan snapshot can bypass it.
            pr, source_policy = _current_policy(
                owner, record["repo"], record["number"]
            )
            if not _matches(record, pr, source_policy):
                result["reason"] = "target/source policy changed before close"
                results.append(result)
                continue
            closed = core.gh_rest(
                "/repos/%s/issues/%s" % (slug, record["number"]),
                method="PATCH",
                fields={"state": "closed"},
            )
            if not isinstance(closed, dict) or str(closed.get("state") or "").lower() != "closed":
                result["reason"] = "target close did not return CLOSED"
                results.append(result)
                continue
            result["status"] = "closed"
        except Exception as error:
            result.update({"status": "error", "reason": str(error)[:200]})
        results.append(result)
    _write(results_path, results)


def record(results_path):
    results = _load(results_path, [])
    if not isinstance(results, list):
        return
    for result in results:
        if not isinstance(result, dict) or result.get("status") != "closed":
            continue
        try:
            card_number = int(result.get("card_issue") or 0)
            comment_id = int(result.get("comment_id") or 0)
        except (TypeError, ValueError):
            continue
        card = render_card.get_card(card_number)
        state = core.parse_state_block((card or {}).get("body", ""))
        policy = (state or {}).get(render_card.MAINTAINER_EDITS_POLICY_FIELD)
        if (
            not card
            or not render_card.issue_is_open(card)
            or not isinstance(policy, dict)
            or policy.get("mode") != core.PUSHABILITY_FORK_REJECT
            or policy.get("phase") != "notice-posted"
            or int(policy.get("target_comment_id") or 0) != comment_id
            or state.get("repo") != result.get("repo")
            or int(state.get("number") or 0) != int(result.get("number") or 0)
            or state.get("head_sha") != result.get("head_sha")
        ):
            continue
        terminal_policy = dict(policy)
        terminal_policy["phase"] = "closed"
        terminal_policy["target_close_result"] = "closed"
        render_card.close_card(
            card_number,
            "Maintainer-edits contribution policy notice was posted and the target PR was closed.",
            label="resolved",
            expected=card,
            terminal_state={
                render_card.MAINTAINER_EDITS_POLICY_FIELD: terminal_policy
            },
            remove_labels={render_card.MAINTAINER_EDITS_CLOSING_LABEL},
        )


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "prepare":
        prepare(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) == 4 and sys.argv[1] == "route-item":
        route_item(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) == 4 and sys.argv[1] == "attach-item":
        attach_item(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) == 5 and sys.argv[1] == "prepare-close":
        prepare_close(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    if len(sys.argv) == 4 and sys.argv[1] == "notify":
        notify(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) == 5 and sys.argv[1] == "attach-notices":
        attach_notices(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    if len(sys.argv) == 4 and sys.argv[1] == "close":
        close(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "record":
        record(sys.argv[2])
        return
    sys.exit(
        "usage: maintainer_edits_policy.py prepare SCAN ACTIONS | "
        "route-item ITEM ACTIONS | attach-item ITEM RESULTS | "
        "prepare-close ITEM ISSUE ACTIONS | notify ACTIONS RESULTS | "
        "attach-notices SCAN RESULTS OUTPUT | close ACTIONS RESULTS | record RESULTS"
    )


if __name__ == "__main__":
    main()
