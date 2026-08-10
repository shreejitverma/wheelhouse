#!/usr/bin/env python3
"""Offline regression coverage for the verified base/VISION context-refresh
allowance (audit F13).

A queued re-triage triggered ONLY by a verified base-SHA or VISION-SHA movement
against an unchanged head consumes a separate small bounded allowance, never
the ordinary per-head retry budget. Every use binds the exact (head, base,
VISION) identity, so a repeated context grants nothing; the daily UTC
reservation ledger, the sealed dispatch permit, idempotency, and G6 verdict
revalidation are unchanged. Exhaustion emits an explicit bounded diagnostic
and performs no dispatch.

Run: python tests/test_triage_context_allowance.py
"""

import copy
import io
import json
import os
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from types import SimpleNamespace

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

import agent_claim  # noqa: E402
import auto_merge  # noqa: E402
import build_item  # noqa: E402
import card_projection  # noqa: E402
import decision_context  # noqa: E402
import reconcile  # noqa: E402
import render_card as rc  # noqa: E402
import target_observation  # noqa: E402
import triage_admission  # noqa: E402
import wheelhouse_core as core  # noqa: E402
from agent_runtime import admission as runtime_admission  # noqa: E402

# Spend-guard tests isolate reservation ordering from cross-repo gate reads.
rc._evaluate_automerge_card_projection = lambda *args, **kwargs: (
    rc.criteria_schema.unavailable_criteria("offline context-allowance fixture")
)

HEAD = "d" * 40
HEAD2 = "9" * 40
B1, B2, B3, B4 = "1" * 40, "2" * 40, "3" * 40, "4" * 40
V1, V2, V3 = "a" * 40, "b" * 40, "c" * 40
PURE = ["needs-decision", "kind:pr-review"]


@contextmanager
def patched(module, replacements):
    originals = {name: getattr(module, name) for name in replacements}
    for name, value in replacements.items():
        setattr(module, name, value)
    try:
        yield
    finally:
        for name, value in originals.items():
            setattr(module, name, value)


def item(base_sha=B1, vision_sha=V1, head=HEAD, allowance=2, cap=2, **overrides):
    base = {
        "repo": "wheelhouse",
        "number": 42,
        "kind": "pr-review",
        "head_sha": head,
        "updated_at": "",
        "title": "A bounded triage candidate",
        "author": "contributor",
        "bucket": "merge-ready",
        "comp": "pass",
        "tests": "green",
        "url": "https://github.com/example/wheelhouse/pull/42",
        "summary": "safe offline fixture",
        "priority": "med",
        "auto_triage": True,
        "auto_triage_issues": True,
        "triage_attempt_cap_per_revision": cap,
        "triage_context_refresh_allowance": allowance,
        "base_sha": base_sha,
        "automerge_vision_sha": vision_sha,
        "triage_vision_status": "present" if vision_sha else "absent",
    }
    base.update(overrides)
    return base


def state_of(body):
    return core.parse_state_block(body)


def successful_triage():
    return {
        "summary": "Adds lightweight context.",
        "product_implications": "Routine internal change.",
        "evidence": "target.txt: quoted a line from the change",
        "recommended_action": "merge",
        "recommended_reason": "Scope is small.",
        "automerge": {
            "behavior_class": "A",
            "behavior_assertions": [],
            "changes_existing_or_default_behavior": False,
            "optin_default_off": False,
            "aligns_with_vision": True,
            "recommend_merge": True,
        },
    }


def queue_and_succeed(body, it):
    queued = rc.body_with_triage_queued(body, it)
    assert queued != body, "queued write unexpectedly no-op"
    completed = rc.body_with_triage_result(
        queued,
        it["head_sha"],
        triage=successful_triage(),
        automerge_behavior_available=True,
        vision_sha=it["automerge_vision_sha"],
        base_sha=it["base_sha"],
    )
    return completed


def replay_cleared(body):
    """Mirror triage_replay's non-success cache clear exactly."""
    state = rc._unique_state_block(body)
    new_state = dict(state)
    for field in ("triaged_sha", "triage_status", "triage_error"):
        new_state.pop(field, None)
    return rc._replace_state_block(rc.remove_triage_section(body), new_state)


def write_config(data):
    handle, path = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(handle, "w") as out:
        yaml.safe_dump(data, out)
    return path


def load_config_from(path):
    with patched(core, {"config_path": lambda: path}):
        return core.load_config()


# --------------------------------------------------------------------------- #
# config + typed plumbing
# --------------------------------------------------------------------------- #
def test_config_defaults_boundaries_and_override():
    path = write_config({"repos": [{"name": "a"}]})
    try:
        cfg = load_config_from(path)
        assert cfg["triage_context_refresh_allowance"] == 2
        assert cfg["triage_context_allowances"] == {"a": 2}
    finally:
        os.unlink(path)

    path = write_config(
        {
            "triage_context_refresh_allowance": 4,
            "repos": [
                {"name": "a"},
                {"name": "b", "triage_context_refresh_allowance": 0},
                {"name": "c", "triage_context_refresh_allowance": 5},
            ],
        }
    )
    try:
        cfg = load_config_from(path)
        assert cfg["triage_context_refresh_allowance"] == 4
        assert cfg["triage_context_allowances"] == {"a": 4, "b": 0, "c": 5}
    finally:
        os.unlink(path)

    # Every invalid class fails closed to zero (allowance disabled), loudly.
    for bad in (True, -1, 6, "2", 2.5, None):
        path = write_config({"triage_context_refresh_allowance": bad, "repos": []})
        stderr = io.StringIO()
        try:
            with redirect_stderr(stderr):
                cfg = load_config_from(path)
            assert cfg["triage_context_refresh_allowance"] == 0, bad
            assert "::error::" in stderr.getvalue(), bad
        finally:
            os.unlink(path)
    # A malformed per-repo override fails closed to zero even over a valid global.
    path = write_config(
        {
            "triage_context_refresh_allowance": 3,
            "repos": [{"name": "a", "triage_context_refresh_allowance": "x"}],
        }
    )
    stderr = io.StringIO()
    try:
        with redirect_stderr(stderr):
            cfg = load_config_from(path)
        assert cfg["triage_context_allowances"] == {"a": 0}
        assert "::error::" in stderr.getvalue()
    finally:
        os.unlink(path)

    # Direct helper + typed item preflight mirror the attempt-cap helpers.
    assert core._triage_context_allowance({}, 2) == 2
    assert core._triage_context_allowance({"triage_context_refresh_allowance": 1}, 2) == 1
    assert core._triage_context_allowance({"triage_context_refresh_allowance": 9}, 2) == 0
    assert rc.triage_context_allowance(item()) == 2
    assert rc.triage_context_allowance(item(allowance=0)) == 0
    stderr = io.StringIO()
    with redirect_stderr(stderr):
        assert rc.triage_context_allowance(item(allowance=True)) == 0
    assert "::error::" in stderr.getvalue()


def test_ingest_normalization_carries_typed_allowance():
    config = {
        "repos": {
            "wheelhouse": {
                "name": "wheelhouse",
                "triage_context_refresh_allowance": 3,
            }
        },
        "auto_triage": True,
        "auto_triage_issues": True,
        "triage_attempt_cap_per_revision": 2,
        "triage_attempt_caps": {"wheelhouse": 2},
        "triage_context_refresh_allowance": 1,
        "triage_context_allowances": {"wheelhouse": 3},
    }
    payload = {
        "repo": "wheelhouse",
        "number": 42,
        "kind": "pr-review",
        "head_sha": HEAD,
    }
    with patched(build_item, {"load_config": lambda: config}):
        normalized = build_item.normalize(payload)
    assert normalized["triage_context_refresh_allowance"] == 3
    # A repo outside the maps reads the validated global value.
    config["repos"] = {}
    config["triage_context_allowances"] = {}
    payload["repo"] = "other"
    with patched(build_item, {"load_config": lambda: config}):
        normalized = build_item.normalize(payload)
    assert normalized["triage_context_refresh_allowance"] == 1


# --------------------------------------------------------------------------- #
# detection + record strictness
# --------------------------------------------------------------------------- #
def attempted_body(it):
    """A card whose ordinary first attempt succeeded at `it`'s context."""
    return queue_and_succeed(rc.render(it)["body"], it)


def test_context_refresh_detection_matrix():
    body = attempted_body(item())
    state = state_of(body)
    # Verified movements against the unchanged head.
    assert rc.triage_context_refresh(item(B2, V1), state) == (B2, V1)
    assert rc.triage_context_refresh(item(B1, V2), state) == (B1, V2)
    assert rc.triage_context_refresh(item(B2, V2), state) == (B2, V2)
    # No movement -> fresh -> not a context refresh.
    assert rc.triage_context_refresh(item(B1, V1), state) is None
    # Head moved -> ordinary new-revision path, not context.
    assert rc.triage_context_refresh(item(B1, V1, head=HEAD2), state) is None
    # Issue-triage never carries base/VISION context.
    assert (
        rc.triage_context_refresh(item(kind="issue-triage", updated_at="t"), state)
        is None
    )
    # Legacy card: attempt exists for this head but no recorded prior identity
    # (missing triaged_base_sha) -> ordinary budget owns the re-triage.
    legacy_state = dict(state)
    legacy_state.pop("triaged_base_sha", None)
    legacy_state.pop("automerge_verdict", None)
    assert rc.triage_context_refresh(item(B2, V1), legacy_state) is None
    # VISION appearing for the first time (no recorded prior vision identity)
    # is not a verified movement -> ordinary budget owns it.
    no_vision_state = dict(state)
    no_vision_state.pop("triaged_vision_sha", None)
    no_vision_state.pop("automerge_verdict", None)
    assert rc.triage_context_refresh(item(B1, V2), no_vision_state) is None
    # A replay-cleared cache (triaged_sha gone) is the ordinary retry path.
    cleared = state_of(replay_cleared(body))
    assert rc.triage_context_refresh(item(B2, V1), cleared) is None


def test_uses_record_strictness_matrix():
    revision = HEAD
    assert rc._triage_context_uses({}, revision) == ([], False)
    # A record keyed to another head is untrusted and denies capacity.
    stale = {
        rc.TRIAGE_CONTEXT_FIELD: {
            "version": 1,
            "kind": "pr-review",
            "revision": HEAD2,
            "uses": [{"base_sha": B2, "vision_sha": V1}],
        },
        "head_sha": revision,
    }
    assert rc._triage_context_uses(stale, revision) == ([], True)

    valid_uses = [{"base_sha": B2, "vision_sha": V1}]
    base_record = {
        "version": 1,
        "kind": "pr-review",
        "revision": revision,
        "uses": valid_uses,
    }
    good = {rc.TRIAGE_CONTEXT_FIELD: copy.deepcopy(base_record), "head_sha": revision}
    uses, untrusted = rc._triage_context_uses(good, revision)
    assert not untrusted and uses == valid_uses

    malformed = []
    def bad(record):
        malformed.append({rc.TRIAGE_CONTEXT_FIELD: record, "head_sha": revision})

    bad(None)
    bad("uses")
    bad({})
    bad({"version": 1, "kind": "pr-review", "revision": revision})  # missing uses
    bad(dict(base_record, extra=True))
    bad(dict(base_record, version=2))
    bad(dict(base_record, version=True))
    bad(dict(base_record, kind="issue-triage"))
    bad(dict(base_record, revision=""))
    bad(dict(base_record, revision=42))
    bad(dict(base_record, uses="x"))
    bad(dict(base_record, uses=[{"base_sha": B2}]))
    bad(dict(base_record, uses=[{"base_sha": B2, "vision_sha": V1, "x": 1}]))
    bad(dict(base_record, uses=[{"base_sha": 1, "vision_sha": V1}]))
    bad(dict(base_record, uses=[{"base_sha": B2, "vision_sha": None}]))
    # Duplicate identities can only be forged -> deny.
    bad(dict(base_record, uses=[{"base_sha": B2, "vision_sha": V1}] * 2))
    # Oversized history can only be forged -> deny.
    bad(
        dict(
            base_record,
            uses=[{"base_sha": str(i), "vision_sha": ""} for i in range(6)],
        )
    )
    for record in malformed:
        assert rc._triage_context_uses(record, revision) == ([], True), record
    # Record revision disagrees with the card's own head -> deny.
    mismatched = {
        rc.TRIAGE_CONTEXT_FIELD: copy.deepcopy(base_record),
        "head_sha": HEAD2,
    }
    assert rc._triage_context_uses(mismatched, revision) == ([], True)

    # The gate maps each class onto one bounded denial reason.
    state = state_of(attempted_body(item()))
    state[rc.TRIAGE_CONTEXT_FIELD] = copy.deepcopy(base_record)
    moved = item(B3, V1)
    ok, reason = rc.triage_context_allowance_gate(moved, state, allowance=2)
    assert ok and reason == ""
    ok, reason = rc.triage_context_allowance_gate(moved, state, allowance=1)
    assert not ok and reason == rc.TRIAGE_CONTEXT_EXHAUSTED
    ok, reason = rc.triage_context_allowance_gate(item(B2, V1), state, allowance=2)
    assert not ok and reason == rc.TRIAGE_CONTEXT_REPEAT
    state[rc.TRIAGE_CONTEXT_FIELD] = {"version": 2}
    ok, reason = rc.triage_context_allowance_gate(moved, state, allowance=2)
    assert not ok and reason == rc.TRIAGE_CONTEXT_UNTRUSTED


# --------------------------------------------------------------------------- #
# acceptance: the F13 scenario end to end
# --------------------------------------------------------------------------- #
def test_two_context_moves_consume_only_the_separate_allowance():
    """With the ordinary per-head cap at two, two distinct verified base or
    VISION changes consume ONLY the separate allowance and trigger explicit
    refresh behavior (queued status + rebound verdict) each time."""
    body = rc.render(item())["body"]
    state = state_of(body)
    assert rc.should_auto_triage(item(), state, PURE, has_token=True)
    body = queue_and_succeed(body, item())
    state = state_of(body)
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert rc.TRIAGE_CONTEXT_FIELD not in state

    # Verified move 1 (base): queues through the allowance; ordinary count stays.
    assert rc.should_auto_triage(item(B2, V1), state, PURE, has_token=True)
    body = queue_and_succeed(body, item(B2, V1))
    state = state_of(body)
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert state[rc.TRIAGE_CONTEXT_FIELD] == {
        "version": 1,
        "kind": "pr-review",
        "revision": HEAD,
        "uses": [{"base_sha": B2, "vision_sha": V1}],
    }
    assert state["triage_status"] == "succeeded"
    assert (state.get("automerge_verdict") or {}).get("base_sha") == B2

    # Verified move 2 (VISION this time): still only the allowance.
    assert rc.should_auto_triage(item(B2, V2), state, PURE, has_token=True)
    body = queue_and_succeed(body, item(B2, V2))
    state = state_of(body)
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert state[rc.TRIAGE_CONTEXT_FIELD]["uses"] == [
        {"base_sha": B2, "vision_sha": V1},
        {"base_sha": B2, "vision_sha": V2},
    ]
    verdict = state.get("automerge_verdict") or {}
    assert verdict.get("base_sha") == B2 and verdict.get("vision_sha") == V2

    # Move 3: the allowance (2) is exhausted - explicit bounded diagnostic,
    # no queued write, and the ordinary budget is still untouched.
    assert not rc.should_auto_triage(item(B3, V2), state, PURE, has_token=True)
    assert rc.body_with_triage_queued(body, item(B3, V2)) == body
    output = io.StringIO()
    with redirect_stdout(output):
        assert (
            rc.triage_context_deferral_reason(item(B3, V2), state, PURE, True)
            == rc.TRIAGE_CONTEXT_EXHAUSTED
        )
        rc.report_triage_context_deferral(42, item(B3, V2), rc.TRIAGE_CONTEXT_EXHAUSTED)
    text = output.getvalue()
    assert "::warning::triage-context-refresh context-allowance-exhausted" in text
    event = json.loads(text.split("wheelhouse-triage-budget-event ", 1)[1])
    assert event["event"] == "context.deferred"
    assert event["code"] == "context-allowance-exhausted"
    assert event["card"] == 42 and event["revision"] == HEAD
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1


def test_repeating_an_identical_context_identity_grants_nothing():
    body = attempted_body(item())  # ordinary attempt at (HEAD, B1, V1)
    # Allowance 3 so repetition (not exhaustion) is the binding constraint.
    body = queue_and_succeed(body, item(B2, V1, allowance=3))
    state = state_of(body)
    assert len(state[rc.TRIAGE_CONTEXT_FIELD]["uses"]) == 1
    # Returning to B1 is a NEW verified identity (the old verdict was cleared
    # by the B2 queue), so it lawfully consumes the second allowance unit.
    assert rc.should_auto_triage(item(B1, V1, allowance=3), state, PURE, True)
    body = queue_and_succeed(body, item(B1, V1, allowance=3))
    state = state_of(body)
    assert len(state[rc.TRIAGE_CONTEXT_FIELD]["uses"]) == 2
    # Moving to B2 again repeats an already-consumed identity: no attempt even
    # though one allowance unit remains.
    repeat = item(B2, V1, allowance=3)
    assert rc.triage_context_refresh(repeat, state) == (B2, V1)
    assert not rc.should_auto_triage(repeat, state, PURE, has_token=True)
    assert (
        rc.triage_context_deferral_reason(repeat, state, PURE, True)
        == rc.TRIAGE_CONTEXT_REPEAT
    )
    assert rc.body_with_triage_queued(body, repeat) == body
    output = io.StringIO()
    with redirect_stdout(output):
        rc.report_triage_context_deferral(42, repeat, rc.TRIAGE_CONTEXT_REPEAT)
    assert "context-identity-repeat" in output.getvalue()
    assert state[rc.TRIAGE_CONTEXT_FIELD]["uses"] == [
        {"base_sha": B2, "vision_sha": V1},
        {"base_sha": B1, "vision_sha": V1},
    ]
    # The reporter itself bounds a junk reason to the untrusted code.
    output = io.StringIO()
    with redirect_stdout(output):
        rc.report_triage_context_deferral(42, repeat, "bogus")
    assert rc.TRIAGE_CONTEXT_UNTRUSTED in output.getvalue()


def test_ordinary_same_context_failures_stay_on_the_original_cap():
    body = attempted_body(item())  # count 1 at (HEAD, B1, V1)
    body = queue_and_succeed(body, item(B2, V1))  # allowance use 1
    # The context attempt fails; an operator replay clears the cache. The
    # re-queue is ORDINARY (cache cleared) and consumes the original cap.
    failed = rc.body_with_triage_result(
        body, HEAD, triage=None, error="Claude did not return a result."
    )
    assert state_of(failed)["triage_status"] == "error"
    replayed = replay_cleared(failed)
    state = state_of(replayed)
    assert rc.triage_context_refresh(item(B2, V1), state) is None
    assert rc.should_auto_triage(item(B2, V1), state, PURE, True)
    requeued = rc.body_with_triage_queued(replayed, item(B2, V1))
    state = state_of(requeued)
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 2
    # Replay must never mint context spend: the allowance history survived.
    assert state[rc.TRIAGE_CONTEXT_FIELD]["uses"] == [
        {"base_sha": B2, "vision_sha": V1}
    ]
    # A second replay at the same context hits the ORIGINAL cap (2), and the
    # deferral diagnostic is the ordinary one - the allowance is not consulted.
    replayed2 = replay_cleared(requeued)
    state = state_of(replayed2)
    assert not rc.should_auto_triage(item(B2, V1), state, PURE, True)
    assert rc.triage_attempt_deferral_needed(item(B2, V1), state, PURE, True)
    assert rc.triage_context_deferral_reason(item(B2, V1), state, PURE, True) == ""
    output = io.StringIO()
    with redirect_stdout(output):
        rc.report_triage_attempt_exhaustion(42, item(B2, V1))
    assert "attempt-cap-exhausted" in output.getvalue()


def test_allowance_zero_disables_context_refresh_only():
    body = attempted_body(item(allowance=0))
    state = state_of(body)
    moved = item(B2, V1, allowance=0)
    assert rc.triage_context_refresh(moved, state) == (B2, V1)
    assert not rc.should_auto_triage(moved, state, PURE, has_token=True)
    assert (
        rc.triage_context_deferral_reason(moved, state, PURE, True)
        == rc.TRIAGE_CONTEXT_EXHAUSTED
    )
    assert rc.body_with_triage_queued(body, moved) == body
    # The ordinary path is untouched: a new head still queues normally.
    new_head = item(B2, V1, head=HEAD2, allowance=0)
    fresh = state_of(rc.render(new_head)["body"])
    assert rc.should_auto_triage(new_head, fresh, PURE, has_token=True)


def test_issue_triage_never_touches_the_allowance():
    it = item(kind="issue-triage", updated_at="2026-07-16T12:00:00Z", head="")
    body = rc.body_with_triage_queued(rc.render(it)["body"], it)
    state = state_of(body)
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert rc.TRIAGE_CONTEXT_FIELD not in state
    assert rc.triage_context_refresh(it, state) is None
    # A newer updatedAt starts a new per-revision ordinary count, as before.
    newer = item(kind="issue-triage", updated_at="2026-07-16T13:00:00Z", head="")
    assert rc.should_auto_triage(newer, state, PURE, has_token=True)
    body2 = rc.body_with_triage_queued(body, newer)
    assert state_of(body2)[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert rc.TRIAGE_CONTEXT_FIELD not in state_of(body2)


# --------------------------------------------------------------------------- #
# reservation, sealed permit, idempotency, G6
# --------------------------------------------------------------------------- #
def review_observation(base_sha=B1, head=HEAD, changed_path="src/change.py"):
    """A complete native ReviewObservation v2 for the fixture target."""
    checks = [
        {
            "name": "PR must be raised via no-mistakes",
            "role": "compliance",
            "outcome": "pass",
        },
        {"name": "tests", "role": "test", "outcome": "pass"},
    ]
    return target_observation.make_observation(
        "example",
        "wheelhouse",
        42,
        head_sha=head,
        base_sha=base_sha,
        expected_head_sha=head,
        observed_at="2026-07-16T10:00:00Z",
        source="bulk-scan",
        completeness={
            "complete": True,
            "target": True,
            "checks": True,
            "configured_checks": True,
            "changed_paths": True,
            "action_required_runs": True,
            "head_matches_expected": True,
            "check_contexts_seen": len(checks),
            "check_contexts_total": len(checks),
            "mergeability": "conclusive",
        },
        facts={
            "open": True,
            "title": "A bounded triage candidate",
            "author": "contributor",
            "updated_at": "2026-07-16T09:59:59Z",
            "draft": False,
            "cross_repo": False,
            "head_ref": "feature-42",
            "mergeable": "MERGEABLE",
            "ci": True,
            "comp": "pass",
            "tests": "green",
            "bucket": "merge-ready",
            "approval_phase": "not-required",
            "check_phase": "terminal",
            "configured_checks": checks,
        },
        changed_paths=target_observation.changed_path_facts(
            [changed_path], complete=True
        ),
    )


def observed_item(it, changed_path="src/change.py"):
    """Attach the current queue-authorized v2 observation/context."""
    obs = review_observation(
        base_sha=it["base_sha"], head=it["head_sha"], changed_path=changed_path
    )
    snapshot = decision_context.repository_snapshot([], "2026-07-16T10:00:00Z")
    return dict(
        it,
        target_observation=obs,
        decision_context=decision_context.build_decision_context(obs, snapshot),
    )


def projection_card(it):
    """A production-shaped authoritative v2 projection card for `it`.

    The pr-review queue path (`mark_triage_queued`) refuses any card whose
    state block is not owned by the v2 projection writer, so the spend-boundary
    tests must exercise the real projected body, not a bare render.
    """
    it = observed_item(it)
    projection = card_projection.plan_card_projection(it, prior={})
    return {
        "number": 42,
        "title": projection["title"],
        "body": projection["body"],
        "labels": [{"name": name} for name in projection["managed_labels"]],
        "state": "OPEN",
        "updatedAt": "2026-07-16T10:00:01Z",
        "author": {"login": rc.GET_CARD_AUTOMATION_AUTHOR},
        "comments": [],
    }


def ledger_card_boundary(card):
    """In-memory card plus the projection writer's PATCH boundary."""
    current = copy.deepcopy(card)
    order = []

    def get_card(number):
        return copy.deepcopy(current)

    def gh(args, check=True):
        if args[:3] == ["api", "--method", "PATCH"] and "--input" in args:
            order.append("card-write")
            path = args[args.index("--input") + 1]
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
            current["title"] = payload["title"]
            current["body"] = payload["body"]
            current["labels"] = [{"name": name} for name in payload["labels"]]
            current["updatedAt"] = "2026-07-16T10:00:02Z"
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")
        raise AssertionError("unexpected gh call: %r" % (args,))

    return current, order, get_card, gh


def test_context_queue_reserves_one_unit_and_returns_a_sealed_permit():
    card = projection_card(item())
    card["body"] = queue_and_succeed(card["body"], item())
    current, order, get_card, gh = ledger_card_boundary(card)
    body = current["body"]

    def reserve(number, queued_item, ceiling):
        order.append("reserve")
        return True

    config = {
        "repos": {"wheelhouse": {"name": "wheelhouse"}},
        "triage_attempt_cap_per_revision": 2,
        "triage_daily_ceiling": 100,
        "triage_context_refresh_allowance": 2,
        "triage_context_allowances": {"wheelhouse": 2},
    }
    moved = observed_item(item(B2, V1))
    with (
        patched(
            rc,
            {"get_card": get_card, "reserve_triage_budget": reserve, "_gh": gh},
        ),
        patched(core, {"load_config": lambda: config}),
        redirect_stdout(io.StringIO()),
    ):
        permit = rc.mark_triage_queued(42, moved, body)
    assert isinstance(permit, rc._TriageDispatchPermit)
    assert order == ["reserve", "card-write"], order
    state = state_of(current["body"])
    assert state["triage_status"] == "queued"
    # One reservation bought one context-refresh queue; ordinary count unmoved.
    assert state[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert state[rc.TRIAGE_CONTEXT_FIELD]["uses"] == [
        {"base_sha": B2, "vision_sha": V1}
    ]
    context, token = rc.triage_admission_context_for_state(state, HEAD)
    assert context and token == permit.review_context
    assert context["observation_id"] == moved["target_observation"]["observation_id"]
    assert context["base_sha"] == B2 and context["vision_sha"] == V1
    with patched(
        triage_admission,
        {
            "_fleet_json": lambda endpoint: (
                (0, {"state": "open", "head": {"sha": HEAD}, "base": {"sha": B2}}, "")
                if "/pulls/" in endpoint
                else (0, {"type": "file", "sha": V1}, "")
            )
        },
    ):
        assert triage_admission.verify(
            current, "example", HEAD, permit.review_context, ""
        ) == (permit.review_context, "")
        review, recovery, verified = triage_admission.verify_bound_context(
            current, "example", HEAD, permit.review_context, ""
        )
        assert (review, recovery) == (permit.review_context, "")
        assert verified["base_sha"] == B2
        assert verified["vision_sha"] == V1

    for live_base, live_vision in ((B3, V1), (B2, V2)):
        with patched(
            triage_admission,
            {
                "_fleet_json": lambda endpoint, base=live_base, vision=live_vision: (
                    (0, {"state": "open", "head": {"sha": HEAD}, "base": {"sha": base}}, "")
                    if "/pulls/" in endpoint
                    else (0, {"type": "file", "sha": vision}, "")
                )
            },
        ):
            try:
                triage_admission.verify_bound_context(
                    current, "example", HEAD, permit.review_context, ""
                )
            except ValueError:
                pass
            else:
                raise AssertionError("moved base/VISION context was accepted")

    # Dispatch accepts only the sealed permit for this exact card/item.
    calls = []
    with patched(rc, {"_gh": lambda args, check=True: calls.append(args)}):
        rc.dispatch_triage_workflow(permit)
    assert calls and calls[0][:3] == ["workflow", "run", "triage.yml"]
    assert "head_sha=%s" % HEAD in calls[0]
    assert "review_context=%s" % permit.review_context in calls[0]
    try:
        rc.dispatch_triage_workflow(object())
    except RuntimeError:
        pass
    else:
        raise AssertionError("dispatch accepted a forged permit")


def test_vision_absence_requires_an_explicit_http_404_status():
    failures = (
        "transport error requesting https://api.github.com/repos/example/repo404/contents/VISION.md",
        "repository example/repo404 was not reachable",
        "HTTP 403: API rate limit exceeded for repo404",
    )
    for error in failures:
        with patched(
            triage_admission,
            {"_fleet_json": lambda _endpoint, message=error: (1, None, message)},
        ):
            try:
                triage_admission._vision_sha("example", "repo404")
            except ValueError:
                pass
            else:
                raise AssertionError("non-404 fleet failure proved VISION.md absence")

    with patched(
        triage_admission,
        {"_fleet_json": lambda _endpoint: (1, None, "gh: Not Found (HTTP 404)")},
    ):
        assert triage_admission._vision_sha("example", "repo404") is None

    for error in failures:
        with patched(
            core,
            {
                "gh_rest": lambda _path, message=error: (
                    _ for _ in ()
                ).throw(RuntimeError(message))
            },
        ):
            assert core._default_branch_vision_observation("example/repo404") == {
                "status": "unavailable",
                "sha": "",
            }
    with patched(
        core,
        {
            "gh_rest": lambda _path: (_ for _ in ()).throw(
                RuntimeError("gh: Not Found (HTTP 404)")
            )
        },
    ):
        assert core._default_branch_vision_observation("example/repo404") == {
            "status": "absent",
            "sha": "",
        }


def queue_through_admission(card, queued_item, reservations):
    current, order, get_card, gh = ledger_card_boundary(card)
    config = {
        "repos": {"wheelhouse": {"name": "wheelhouse"}},
        "triage_attempt_cap_per_revision": 2,
        "triage_daily_ceiling": 100,
        "triage_context_refresh_allowance": 2,
        "triage_context_allowances": {"wheelhouse": 2},
    }

    def reserve(number, value, ceiling):
        reservations.append((number, value["head_sha"], ceiling))
        order.append("reserve")
        return True

    with (
        patched(rc, {"get_card": get_card, "reserve_triage_budget": reserve, "_gh": gh}),
        patched(core, {"load_config": lambda: config}),
        redirect_stdout(io.StringIO()),
    ):
        permit = rc.mark_triage_queued(42, queued_item, current["body"])
    return current, permit, order


def claim_key(review_context):
    identity = runtime_admission.normalized_event_identity(
        action="triage.pr.local",
        owner="example",
        repo="wheelhouse",
        number=42,
        card_issue=42,
        revision=HEAD,
        review_context=review_context,
    )
    return runtime_admission.event_key_sha256(identity)


def admit_claim(review_context, comments):
    outputs = {}

    def gh_json(*args):
        if "--paginate" in args:
            return [copy.deepcopy(comments)]
        if "--method" in args and "POST" in args:
            body = next(value[5:] for value in args if value.startswith("body="))
            comment = {
                "id": len(comments) + 1,
                "body": body,
                "user": {"login": "github-actions[bot]"},
                "created_at": "2026-07-16T10:00:00Z",
                "updated_at": "2026-07-16T10:00:00Z",
            }
            comments.append(comment)
            return copy.deepcopy(comment)
        comment_id = int(args[-1].rsplit("/", 1)[-1])
        return copy.deepcopy(next(row for row in comments if row["id"] == comment_id))

    args = SimpleNamespace(
        action="triage.pr.local",
        owner="example",
        repo="wheelhouse",
        number=42,
        issue=42,
        revision=HEAD,
        event_id="",
        review_context=review_context,
        recovery_context="",
        repo_slug="example/wheelhouse",
    )
    with patched(
        agent_claim,
        {
            "gh_json": gh_json,
            "output": lambda name, value: outputs.__setitem__(name, value),
        },
    ):
        assert agent_claim.claim(args) == 0
    return outputs["admitted"] == "true", outputs["event_key"]


def resolve_and_claim(card, permit, comments, base_sha, vision_sha):
    def fleet(endpoint):
        if "/pulls/" in endpoint:
            return 0, {
                "state": "open",
                "head": {"sha": HEAD},
                "base": {"sha": base_sha},
            }, ""
        if vision_sha is None:
            return 1, None, "HTTP 404: Not Found"
        return 0, {"type": "file", "sha": vision_sha}, ""

    with patched(triage_admission, {"_fleet_json": fleet}):
        review, recovery, _context = triage_admission.verify_bound_context(
            card, "example", HEAD, permit.review_context, ""
        )
    assert recovery == ""
    return admit_claim(review, comments)


def test_queue_to_claim_admits_first_vision_and_denies_identical_context():
    absent = observed_item(item(vision_sha=""))
    current, first, _order = queue_through_admission(
        projection_card(absent), absent, reservations := []
    )
    assert first is not None and len(reservations) == 1
    claims = []
    admitted, first_key = resolve_and_claim(current, first, claims, B1, None)
    assert admitted
    current["body"] = rc.body_with_triage_result(
        current["body"], HEAD, triage=None, error="completed", base_sha=B1
    )

    unchanged, duplicate, duplicate_order = queue_through_admission(
        current, absent, reservations
    )
    assert duplicate is None and duplicate_order == [] and len(reservations) == 1
    assert unchanged["body"] == current["body"]
    duplicate_admitted, duplicate_key = admit_claim(first.review_context, claims)
    assert not duplicate_admitted and duplicate_key == first_key

    first_vision = observed_item(item(B1, V1))
    current, vision_permit, _order = queue_through_admission(
        current, first_vision, reservations
    )
    assert vision_permit is not None and len(reservations) == 2
    vision_admitted, vision_key = resolve_and_claim(
        current, vision_permit, claims, B1, V1
    )
    assert vision_admitted and vision_key != first_key
    queued = state_of(current["body"])
    assert queued[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 2
    assert rc.TRIAGE_CONTEXT_FIELD not in queued


def test_verified_vision_removal_uses_context_allowance_and_new_claim():
    present = observed_item(item(B1, V1))
    current, first, _order = queue_through_admission(
        projection_card(present), present, reservations := []
    )
    current["body"] = rc.body_with_triage_result(
        current["body"], HEAD, triage=None, error="completed", base_sha=B1,
        vision_sha=V1
    )
    absent = observed_item(item(B1, ""))
    assert not rc.triage_fresh(absent, state_of(current["body"]))
    assert rc.triage_context_refresh(absent, state_of(current["body"])) == (B1, "")
    current, second, _order = queue_through_admission(current, absent, reservations)
    queued = state_of(current["body"])
    assert second is not None and len(reservations) == 2
    assert queued[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 1
    assert queued[rc.TRIAGE_CONTEXT_FIELD]["uses"] == [
        {"base_sha": B1, "vision_sha": ""}
    ]
    claims = []
    first_admitted, first_key = admit_claim(first.review_context, claims)
    second_admitted, second_key = resolve_and_claim(current, second, claims, B1, None)
    assert first_admitted and second_admitted and second_key != first_key


def test_completed_backfill_marker_does_not_block_later_context_review():
    original = observed_item(item(B1, V1))
    current, first, _order = queue_through_admission(
        projection_card(original), original, reservations := []
    )
    assert first is not None
    current["body"] = rc.body_with_triage_result(
        current["body"],
        HEAD,
        triage=None,
        error="completed policy recovery",
        base_sha=B1,
        vision_sha=V1,
    )
    completed_state = state_of(current["body"])
    _record, original_context = rc.triage_admission_context_for_state(
        completed_state, HEAD
    )
    assert original_context
    completed_state[rc.TRIAGE_BACKFILL_FIELD] = {
        "version": rc.TRIAGE_BACKFILL_VERSION,
        "policy": "fixture-policy",
        "wave": "fixture-wave",
        "revision": HEAD,
        "review_context": original_context,
        "at": "2026-07-23T12:00:00Z",
        "run_number": 1,
    }
    current["body"] = rc._replace_state_block(current["body"], completed_state)

    moved = observed_item(item(B2, V1))
    current, second, _order = queue_through_admission(current, moved, reservations)
    assert second is not None and len(reservations) == 2
    assert second.review_context != original_context
    assert second.recovery_context == ""
    queued_state = state_of(current["body"])
    assert queued_state[rc.TRIAGE_BACKFILL_FIELD]["review_context"] == original_context
    assert queued_state[rc.TRIAGE_ADMISSION_CONTEXT_FIELD]["base_sha"] == B2
    claims = []
    first_admitted, first_key = admit_claim(original_context, claims)
    second_admitted, second_key = resolve_and_claim(current, second, claims, B2, V1)
    assert first_admitted and second_admitted and second_key != first_key


def test_complete_observation_drift_reaches_a_distinct_claim():
    original = observed_item(item())
    current, first, _order = queue_through_admission(
        projection_card(original), original, reservations := []
    )
    queued_state = state_of(current["body"])
    payload = successful_triage()
    payload["recommendation_basis"] = {
        "kind": "other",
        "observation_id": queued_state[rc.REVIEW_OBSERVATION_FIELD]["observation_id"],
        "context_id": queued_state[rc.DECISION_CONTEXT_FIELD]["context_id"],
    }
    current["body"] = rc.body_with_triage_result(
        current["body"], HEAD, triage=payload, owner="example", base_sha=B1, vision_sha=V1
    )
    completed_state = state_of(current["body"])
    assert rc.assessment_current_admitted(completed_state)

    drifted = observed_item(item(), changed_path="src/rotated.py")
    drifted_state = dict(completed_state)
    drifted_state[rc.REVIEW_OBSERVATION_FIELD] = drifted["target_observation"]
    drifted_state[rc.DECISION_CONTEXT_FIELD] = drifted["decision_context"]
    current["body"] = rc._replace_state_block(current["body"], drifted_state)
    assert rc.observation_drift_retriage_needed(drifted, drifted_state)

    current, second, _order = queue_through_admission(current, drifted, reservations)
    assert second is not None and len(reservations) == 2
    assert second.review_context != first.review_context
    claims = []
    first_admitted, first_key = admit_claim(first.review_context, claims)
    second_admitted, second_key = resolve_and_claim(current, second, claims, B1, V1)
    assert first_admitted and second_admitted and second_key != first_key
    assert state_of(current["body"])[rc.TRIAGE_ATTEMPTS_FIELD]["count"] == 2


def test_untrusted_or_raced_context_denies_before_reservation():
    valid = observed_item(item())
    cases = []
    unavailable = dict(valid, triage_vision_status="unavailable")
    cases.append((projection_card(valid), unavailable))

    incomplete_observation = copy.deepcopy(valid["target_observation"])
    incomplete_observation["completeness"]["complete"] = False
    incomplete = dict(valid, target_observation=incomplete_observation)
    cases.append((projection_card(valid), incomplete))

    raced = projection_card(valid)
    stale_body = raced["body"]
    raced_state = state_of(stale_body)
    raced_state["priority"] = "high"
    raced["body"] = rc._replace_state_block(stale_body, raced_state)
    cases.append((raced, valid, stale_body))

    for case in cases:
        card_value, queued_item = case[:2]
        supplied_body = case[2] if len(case) == 3 else card_value["body"]
        reservations = []
        current, order, get_card, gh = ledger_card_boundary(card_value)
        config = {
            "repos": {"wheelhouse": {"name": "wheelhouse"}},
            "triage_attempt_cap_per_revision": 2,
            "triage_daily_ceiling": 100,
            "triage_context_refresh_allowance": 2,
            "triage_context_allowances": {"wheelhouse": 2},
        }
        with (
            patched(
                rc,
                {
                    "get_card": get_card,
                    "reserve_triage_budget": lambda *args: reservations.append(args) or True,
                    "_gh": gh,
                },
            ),
            patched(core, {"load_config": lambda: config}),
            redirect_stdout(io.StringIO()),
        ):
            assert rc.mark_triage_queued(42, queued_item, supplied_body) is None
        assert reservations == [] and order == []
        assert current["body"] == card_value["body"]

    current, permit, _order = queue_through_admission(
        projection_card(valid), valid, reservations := []
    )
    assert permit is not None and len(reservations) == 1
    claims = []
    try:
        resolve_and_claim(current, permit, claims, B2, V1)
    except ValueError:
        pass
    else:
        raise AssertionError("raced base context reached durable claim admission")
    assert claims == []


def test_context_exhaustion_reserves_nothing_and_never_dispatches():
    card = projection_card(item())
    card["body"] = queue_and_succeed(card["body"], item())
    card["body"] = queue_and_succeed(card["body"], item(B2, V1))
    card["body"] = queue_and_succeed(card["body"], item(B2, V2))
    current, order, get_card, gh = ledger_card_boundary(card)
    body = current["body"]

    def reserve(number, queued_item, ceiling):
        order.append("reserve")
        return True

    config = {
        "repos": {"wheelhouse": {"name": "wheelhouse"}},
        "triage_attempt_cap_per_revision": 2,
        "triage_daily_ceiling": 100,
        "triage_context_refresh_allowance": 2,
        "triage_context_allowances": {"wheelhouse": 2},
    }
    output = io.StringIO()
    with (
        patched(
            rc,
            {"get_card": get_card, "reserve_triage_budget": reserve, "_gh": gh},
        ),
        patched(core, {"load_config": lambda: config}),
        redirect_stdout(output),
    ):
        permit = rc.mark_triage_queued(42, observed_item(item(B3, V2)), body)
    assert permit is None
    assert order == [], order  # no reservation, no card write, no dispatch
    text = output.getvalue()
    assert "context-allowance-exhausted" in text
    assert "context.deferred" in text

    # The reconcile path surfaces the same explicit bounded diagnostic.
    row = {
        "number": 42,
        "body": body,
        "labels": PURE,
        "state": state_of(body),
    }
    dispatched = []
    output = io.StringIO()
    with (
        patched(
            reconcile.render_card,
            {
                "mark_triage_queued": lambda number, queued_item, body: True,
                "dispatch_triage_workflow": lambda permit: dispatched.append(permit),
            },
        ),
        redirect_stdout(output),
    ):
        queued = reconcile.maybe_queue_auto_triage(item(B3, V2), row, True)
    assert queued is False
    assert dispatched == []
    assert "context-allowance-exhausted" in output.getvalue()
    assert "context.deferred" in output.getvalue()


def test_reservation_failure_consumes_no_allowance():
    card = projection_card(item())
    card["body"] = queue_and_succeed(card["body"], item())
    current, order, get_card, gh = ledger_card_boundary(card)
    body = current["body"]

    def reserve(number, queued_item, ceiling):
        order.append("reserve")
        return False

    config = {
        "repos": {"wheelhouse": {"name": "wheelhouse"}},
        "triage_attempt_cap_per_revision": 2,
        "triage_daily_ceiling": 100,
        "triage_context_refresh_allowance": 2,
        "triage_context_allowances": {"wheelhouse": 2},
    }
    with (
        patched(
            rc,
            {
                "get_card": get_card,
                "reserve_triage_budget": reserve,
                "_gh": gh,
                "publish_triage_budget_deferral": lambda *a, **k: None,
            },
        ),
        patched(core, {"load_config": lambda: config}),
    ):
        permit = rc.mark_triage_queued(42, observed_item(item(B2, V1)), body)
    assert permit is None
    assert order == ["reserve"], order
    assert rc.TRIAGE_CONTEXT_FIELD not in state_of(current["body"])


def test_idempotency_same_context_never_requeues():
    body = attempted_body(item())
    moved = item(B2, V1)
    queued = rc.body_with_triage_queued(body, moved)
    state = state_of(queued)
    # Queued for exactly this context: fresh, so no scan requeues it.
    assert state["triage_status"] == "queued"
    assert rc.triage_fresh(moved, state)
    assert not rc.should_auto_triage(moved, state, PURE, has_token=True)
    assert rc.body_with_triage_queued(queued, moved) == queued
    # Same after the attempt completes: success AND failure are both final.
    succeeded = rc.body_with_triage_result(
        queued,
        HEAD,
        triage=successful_triage(),
        automerge_behavior_available=True,
        vision_sha=V1,
        base_sha=B2,
    )
    state = state_of(succeeded)
    assert rc.triage_fresh(moved, state)
    assert not rc.should_auto_triage(moved, state, PURE, has_token=True)
    failed = rc.body_with_triage_result(
        queued, HEAD, triage=None, error="boom"
    )
    state = state_of(failed)
    assert rc.triage_fresh(moved, state)
    assert not rc.should_auto_triage(moved, state, PURE, has_token=True)


def test_g6_revalidation_binds_the_refreshed_context():
    body = attempted_body(item())
    verdict_before = state_of(body).get("automerge_verdict") or {}
    assert verdict_before.get("base_sha") == B1
    # After a verified base move, the refreshed verdict binds the NEW context.
    body = queue_and_succeed(body, item(B2, V1))
    verdict = state_of(body).get("automerge_verdict") or {}
    assert verdict == {
        "behavior_class": "A",
        "behavior_admission": {
            "contradicts_existing_contract": False,
            "version": 1,
        },
        "changes_existing_or_default_behavior": False,
        "optin_default_off": False,
        "aligns_with_vision": True,
        "recommend_merge": True,
        "vision_sha": V1,
        "base_sha": B2,
    }
    ok, cls, _reason = auto_merge.verdict_eligible(verdict)
    assert ok and cls == "A"
    # G6's live-base binding compares the persisted verdict against the live
    # base SHA: the refreshed verdict matches the new live base, while the
    # stale one does not (the exact comparison evaluate_candidate enforces).
    live_base, live_vision = B2, V1
    assert verdict["base_sha"] == live_base and verdict["vision_sha"] == live_vision
    assert verdict_before["base_sha"] != live_base
    facts, _ = auto_merge.behavior_verdict_facts(verdict)
    assert all(
        facts[key]["status"] == rc.criteria_schema.STATUS_MET
        for key in (
            "g6_behavior_class",
            "g6_vision_alignment",
            "g6_default_behavior",
            "g6_verdict_merge",
            "g6_class_c_mode",
        )
    )


# --------------------------------------------------------------------------- #
# non-materiality + same-revision preservation
# --------------------------------------------------------------------------- #
def test_allowance_record_is_nonmaterial_and_preserved_across_refresh():
    body = attempted_body(item())
    with_record = queue_and_succeed(body, item(B2, V1))
    state_with = state_of(with_record)
    assert rc.TRIAGE_CONTEXT_FIELD in state_with
    # The record must never drive a material refresh decision.
    stripped = dict(state_with)
    stripped.pop(rc.TRIAGE_CONTEXT_FIELD, None)
    assert rc.material_changed(item(B2, V1), state_with) == rc.material_changed(
        item(B2, V1), stripped
    )
    assert not rc.material_changed(item(B2, V1), state_with)

    # A same-revision refresh preserves the record through the triage lift.
    labels = ["needs-decision", "kind:pr-review"]
    refreshed_item = dict(item(B2, V1), priority="high")
    refreshed = rc._preserve_same_revision_triage(
        rc.render(refreshed_item)["body"],
        with_record,
        refreshed_item,
        state_of(with_record),
        owner="example",
    )
    assert (
        state_of(refreshed).get(rc.TRIAGE_CONTEXT_FIELD)
        == state_with[rc.TRIAGE_CONTEXT_FIELD]
    )

    # Reading an old-head record against a NEW head denies capacity. Rendering
    # the new head starts a clean card without carrying the stale record.
    new_head = item(B2, V1, head=HEAD2)
    uses, untrusted = rc._triage_context_uses(state_with, HEAD2)
    assert uses == [] and untrusted
    fresh = state_of(rc.render(new_head)["body"])
    assert rc.TRIAGE_CONTEXT_FIELD not in fresh
    assert rc.should_auto_triage(new_head, fresh, PURE, has_token=True)


def test_item_level_invalid_allowance_fails_closed_loudly():
    body = attempted_body(item())
    state = state_of(body)
    stderr = io.StringIO()
    with redirect_stderr(stderr):
        assert not rc.should_auto_triage(
            item(B2, V1, allowance="lots"), state, PURE, has_token=True
        )
    assert "::error::" in stderr.getvalue()
    assert rc.body_with_triage_queued(body, item(B2, V1, allowance="lots")) == body


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok - %s" % name)
    print("all context-allowance tests passed")
