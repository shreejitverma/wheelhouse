#!/usr/bin/env python3
"""Verify the queue-owned context behind a PR-triage admission identity.

This deliberately accepts only opaque digests from workflow_dispatch. It
re-reads the decision card, reconstructs the digest from its queued state, and
then verifies the target's current head, base and default-branch VISION.md
identity with the fleet read token before a durable claim can be created.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import render_card


SHA = re.compile(r"^[0-9A-Fa-f]{7,64}$")


def _output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT", "")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (name, value.replace("\n", " ")))


def _fleet_json(endpoint: str) -> tuple[int, object, str]:
    token = os.environ.get("WHEELHOUSE_FLEET_TOKEN", "")
    if not token:
        raise ValueError("fleet read token was unavailable")
    env = dict(os.environ)
    env["GH_TOKEN"] = token
    result = subprocess.run(
        ("gh", "api", endpoint),
        text=True,
        capture_output=True,
        timeout=30,
        env=env,
    )
    if result.returncode:
        return result.returncode, None, result.stderr[:300]
    try:
        return 0, json.loads(result.stdout), ""
    except ValueError as error:
        raise ValueError("fleet response was malformed") from error


def _vision_sha(owner: str, repo: str) -> str | None:
    code, value, error = _fleet_json("repos/%s/%s/contents/VISION.md" % (owner, repo))
    if code:
        # GitHub CLI reports the response status in stderr. Only a definite 404
        # proves absence; auth, rate, transport, and every other failure deny.
        if re.search(r"\bHTTP\s+404\b", error, re.IGNORECASE):
            return None
        raise ValueError("default-branch VISION.md could not be read")
    if not isinstance(value, dict):
        raise ValueError("default-branch VISION.md response was malformed")
    sha = value.get("sha")
    if value.get("type") != "file" or not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("default-branch VISION.md identity was malformed")
    return sha


def verify_bound_context(
    card: object,
    owner: str,
    revision: str,
    supplied_review: str,
    supplied_recovery: str,
) -> tuple[str, str, dict]:
    if not isinstance(card, dict) or not render_card.issue_is_open(card):
        raise ValueError("decision card was not open")
    if not render_card.is_refreshable(card.get("labels")):
        raise ValueError("decision card was not a pure needs-decision card")
    state = render_card._unique_state_block(card.get("body", ""))
    if not state or state.get("kind") != "pr-review":
        raise ValueError("decision card was not a PR-review card")
    if not render_card.triage_queued_for_head(state, revision):
        raise ValueError("decision card was no longer queued for this revision")
    context, review_token = render_card.triage_admission_context_for_state(state, revision)
    if context is None or review_token != supplied_review:
        raise ValueError("queued review context did not match the dispatch token")
    observation = render_card.target_contracts.normalize_review_observation(
        state.get(render_card.REVIEW_OBSERVATION_FIELD)
    )
    repo = state.get("repo")
    number = state.get("number")
    if (
        observation is None
        or observation["target"].get("owner") != owner
        or not isinstance(repo, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo)
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
    ):
        raise ValueError("decision card target identity was malformed")
    code, target, _error = _fleet_json("repos/%s/%s/pulls/%s" % (owner, repo, number))
    if code or not isinstance(target, dict):
        raise ValueError("target PR could not be read")
    head = ((target.get("head") or {}).get("sha") if isinstance(target.get("head"), dict) else "")
    base = ((target.get("base") or {}).get("sha") if isinstance(target.get("base"), dict) else "")
    if (
        str(target.get("state") or "").lower() != "open"
        or head != revision
        or base != context["base_sha"]
    ):
        raise ValueError("target head or base no longer matched queued review context")
    if _vision_sha(owner, repo) != context["vision_sha"]:
        raise ValueError("default-branch VISION.md no longer matched queued review context")
    marker = state.get(render_card.TRIAGE_BACKFILL_FIELD)
    recovery_token = ""
    if marker is not None:
        marker_review = marker.get("review_context") if isinstance(marker, dict) else ""
        marker_token = render_card.triage_backfill_recovery_token(
            marker, marker_review
        )
        if not marker_token:
            raise ValueError("queued policy recovery allowance was malformed")
        if marker_review == review_token:
            recovery_token = marker_token
    if supplied_recovery != recovery_token:
        raise ValueError("queued recovery context did not match the dispatch token")
    return review_token, recovery_token, context


def verify(
    card: object,
    owner: str,
    revision: str,
    supplied_review: str,
    supplied_recovery: str,
) -> tuple[str, str]:
    review_token, recovery_token, _context = verify_bound_context(
        card, owner, revision, supplied_review, supplied_recovery
    )
    return review_token, recovery_token


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--card", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--review-context", required=True)
    parser.add_argument("--recovery-context", default="")
    args = parser.parse_args()
    if not SHA.fullmatch(args.revision):
        raise ValueError("PR revision was malformed")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", args.owner):
        raise ValueError("target owner was malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", args.review_context):
        raise ValueError("review context token was malformed")
    if args.recovery_context and not re.fullmatch(r"[0-9a-f]{64}", args.recovery_context):
        raise ValueError("recovery context token was malformed")
    with open(args.card, encoding="utf-8") as handle:
        card = json.load(handle)
    review_token, recovery_token, context = verify_bound_context(
        card,
        args.owner,
        args.revision,
        args.review_context,
        args.recovery_context,
    )
    _output("review_context", review_token)
    _output("recovery_context", recovery_token)
    _output("base_sha", context["base_sha"])
    _output("vision_present", "true" if context["vision_sha"] is not None else "false")
    _output("vision_sha", context["vision_sha"] or "")
    print("queued PR review context verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("triage admission context error: %s" % str(error)[:240], file=sys.stderr)
        raise SystemExit(1)
