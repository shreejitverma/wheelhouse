#!/usr/bin/env python3
"""Captain-initiated assisted in-place merge (Phase 1).

The captain ticks `Merge it` (or `/merge`, or an NL merge) on a conflicted PR.
Instead of asking the contributor to rebase, Wheelhouse resolves the conflict as
a merge commit pushed directly to the EXISTING pull request head branch of a
same-repository or editable personal-fork PR. There is no landing branch, no replacement PR, no force
push, and no rewrite of the contributor's commits - they stay
byte-identical as the merge commit's FIRST parent, and the model is credited
only through a ``Co-authored-by`` trailer on the resolution commit.

The order is deliberate and every stage fails closed:

    bind (exact live re-read, policy, workflow gates, kill switches)
      -> prepare (credential-free mechanical `git merge`, conflict admission)
      -> one bounded model turn (no tools that write, no credential, no network)
      -> apply (trusted code writes the bytes; zero novel lines by construction)
      -> push (the ONLY step that sees the push credential; exact-SHA CAS)
      -> record (default-token card state; the captain confirms the final merge)

Credential contract (see README "Assisted-merge push credential"):

* Personal-fork PR branches whose author enabled **Allow edits from
  maintainers** are pushed with ``ASSISTED_MERGE_PUSH_TOKEN``, the repository
  owner's own short-lived classic PAT with only ``public_repo`` scope.
  Same-repository branches use ``FLEET_TOKEN`` instead.
* The selected credential is delivered through ``GIT_ASKPASS`` for exactly one
  plain, non-force push process after the remote ref is re-read at the expected
  head SHA. The token never reaches a model, a target checkout, a target
  workflow, a git config file or credential helper, a command line, or a log.

The model never authors a line. It chooses, per conflicted hunk, one of four
orderings of lines that already exist in the two merge parents, so the resolved
bytes are provably a concatenation of already-reviewed parent lines.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apply_decision  # noqa: E402
import render_card  # noqa: E402
import wheelhouse_core as core  # noqa: E402

# --------------------------------------------------------------------------- #
# Contract constants
# --------------------------------------------------------------------------- #
ASSIST_VERSION = 3
ASSIST_MODE = "in-place"
ASSIST_FIELD = render_card.MERGE_ASSIST_FIELD
NO_ASSIST_LABEL = core.NO_ASSISTED_MERGE_LABEL
AWAITING_CONFIRM_LABEL = core.AWAITING_CAPTAIN_CONFIRM_LABEL
PUSH_TOKEN_SECRET = "ASSISTED_MERGE_PUSH_TOKEN"

PHASE_AWAITING_CONFIRMATION = "awaiting-confirmation"
PHASE_ESCALATED = "escalated"
PUSH_OUTCOME_NOT_PUSHED = "not-pushed"
PUSH_OUTCOME_PUSHED = "pushed"
PUSH_OUTCOME_UNCERTAIN = "uncertain"
_PUSH_OUTCOMES = frozenset(
    {PUSH_OUTCOME_NOT_PUSHED, PUSH_OUTCOME_PUSHED, PUSH_OUTCOME_UNCERTAIN}
)

# Every admitted resolution is one of these four orderings of parent lines. A
# model can pick between already-reviewed lines; it can never author one. This
# is deliberately stricter than a novel-line budget: V1 has no novel lines at
# all, so a prompt-injected "resolution" cannot introduce a single new byte of
# source.
SELECTIONS = ("ours", "theirs", "ours-then-theirs", "theirs-then-ours")
CANNOT_RESOLVE = "cannot_safely_resolve"

# Conflict markers, in git's default (non-diff3) `merge` conflict style, which
# `prepare` pins explicitly so a repository-level `merge.conflictStyle` cannot
# change what trusted code has to parse.
_OURS_MARKER = re.compile(r"<{7}(?: .*)?")
_BASE_MARKER = re.compile(r"\|{7}(?: .*)?")
_THEIRS_MARKER = re.compile(r">{7}(?: .*)?")
_SEPARATOR = "======="

_SHA40 = re.compile(r"[0-9a-f]{40}")
# Branch names reach git only inside a refspec, but keep them provably ordinary
# so no target-controlled value can look like an option or a traversal.
_SAFE_REF = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._/-]{0,240}")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_LFS_POINTER = "version https://git-lfs.github.com/spec/"
_ADMITTED_MODES = frozenset({"100644", "100755"})
_CONTEXT_LINES = 6
_MAX_PATH_LENGTH = 240
_MAX_REASON_LENGTH = 400
_MAX_DOCUMENT_BYTES = 400_000

_ELIGIBLE_SOURCE_MODES = frozenset(
    {core.PUSHABILITY_PERSONAL_FORK_EDITABLE, core.PUSHABILITY_SAME_REPO}
)
_RESOLUTION_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "agent_runtime"
    / "schemas"
    / "actions"
    / "merge-resolve-v1.schema.json"
)


class AssistError(Exception):
    """A deterministic, escalate-not-guess failure."""


class PreMutationAssistError(AssistError):
    pass


# --------------------------------------------------------------------------- #
# Small IO helpers
# --------------------------------------------------------------------------- #
def _load(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def _write(path, value):
    destination = Path(path)
    fd, temporary = tempfile.mkstemp(
        prefix=".merge-assist-", suffix=".json", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    text = "" if value is None else str(value).replace("\n", " ")
    if not path:
        print("%s=%s" % (name, text))
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("%s=%s\n" % (name, text))


def _bounded(value, maximum=_MAX_REASON_LENGTH):
    return str(value or "").strip()[:maximum]


# --------------------------------------------------------------------------- #
# git: no hooks, no credential helpers, no prompts, no target code execution
# --------------------------------------------------------------------------- #
_GIT_SAFE_FLAGS = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "merge.conflictStyle=merge",
    "-c",
    "gc.auto=0",
    "-c",
    "protocol.version=2",
)


def _git_env(extra=None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("RUNNER_TEMP") or os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    env.update(extra or {})
    return env


def git(repo, *args, env_extra=None, check=True):
    """Run one git command with hooks, helpers, and prompting disabled."""
    result = subprocess.run(
        ("git", "-C", str(repo)) + _GIT_SAFE_FLAGS + tuple(args),
        capture_output=True,
        text=True,
        env=_git_env(env_extra),
        timeout=600,
    )
    if check and result.returncode != 0:
        raise AssistError(
            "git %s failed: %s" % (args[0], _bounded(result.stderr or result.stdout))
        )
    return result


# --------------------------------------------------------------------------- #
# Conflict parsing and resolution (pure - the offline-testable core)
# --------------------------------------------------------------------------- #
def parse_conflicted_text(text):
    """Split a conflicted file into literal segments and two-sided hunks.

    Any marker that is unbalanced, nested, diff3-style, or otherwise not the
    exact shape trusted code knows how to reconstruct raises, because a file we
    cannot parse exactly is a file we must not rewrite.
    """
    lines = text.split("\n")
    segments = []
    hunks = []
    literal = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if _BASE_MARKER.fullmatch(line):
            raise AssistError("diff3 conflict style is not supported")
        if line == _SEPARATOR or _THEIRS_MARKER.fullmatch(line):
            raise AssistError("unbalanced conflict marker")
        if not _OURS_MARKER.fullmatch(line):
            literal.append(line)
            index += 1
            continue
        segments.append(("literal", literal))
        literal = []
        index += 1
        ours = []
        while index < len(lines) and lines[index] != _SEPARATOR:
            current = lines[index]
            if (
                _OURS_MARKER.fullmatch(current)
                or _THEIRS_MARKER.fullmatch(current)
                or _BASE_MARKER.fullmatch(current)
            ):
                raise AssistError("nested conflict marker")
            ours.append(current)
            index += 1
        if index >= len(lines):
            raise AssistError("conflict hunk has no separator")
        index += 1
        theirs = []
        while index < len(lines) and not _THEIRS_MARKER.fullmatch(lines[index]):
            current = lines[index]
            if (
                _OURS_MARKER.fullmatch(current)
                or _BASE_MARKER.fullmatch(current)
                or current == _SEPARATOR
            ):
                raise AssistError("nested conflict marker")
            theirs.append(current)
            index += 1
        if index >= len(lines):
            raise AssistError("conflict hunk has no closing marker")
        index += 1
        segments.append(("hunk", len(hunks)))
        hunks.append({"ours": ours, "theirs": theirs})
    segments.append(("literal", literal))
    if not hunks:
        raise AssistError("file has no parsable conflict hunk")
    return {"segments": segments, "hunks": hunks}


def resolved_hunk_lines(hunk, selection):
    if selection == "ours":
        return list(hunk["ours"])
    if selection == "theirs":
        return list(hunk["theirs"])
    if selection == "ours-then-theirs":
        return list(hunk["ours"]) + list(hunk["theirs"])
    if selection == "theirs-then-ours":
        return list(hunk["theirs"]) + list(hunk["ours"])
    raise AssistError("unsupported hunk selection")


def render_resolution(parsed, selections):
    """Rebuild the file from its own skeleton plus parent lines only.

    Trusted code - never the model - produces these bytes. Every literal
    (non-conflicted) byte is copied from the mechanical merge skeleton, and
    every resolved byte is an exact line from one of the two merge parents.
    """
    if len(selections) != len(parsed["hunks"]):
        raise AssistError("resolution does not cover every conflict hunk exactly once")
    out = []
    for kind, value in parsed["segments"]:
        if kind == "literal":
            out.extend(value)
            continue
        out.extend(resolved_hunk_lines(parsed["hunks"][value], selections[value]))
    text = "\n".join(out)
    parents = set()
    for hunk in parsed["hunks"]:
        parents.update(hunk["ours"])
        parents.update(hunk["theirs"])
    for hunk, selection in zip(parsed["hunks"], selections):
        for line in resolved_hunk_lines(hunk, selection):
            if line not in parents:
                raise AssistError("resolved line is not present in a merge parent")
    if contains_conflict_marker(text):
        raise AssistError("resolved text still contains a conflict marker")
    return text


def contains_conflict_marker(text):
    for line in str(text or "").split("\n"):
        if (
            _OURS_MARKER.fullmatch(line)
            or _THEIRS_MARKER.fullmatch(line)
            or _BASE_MARKER.fullmatch(line)
            or line == _SEPARATOR
        ):
            return True
    return False


def conflict_line_count(parsed):
    return sum(len(h["ours"]) + len(h["theirs"]) for h in parsed["hunks"])


# --------------------------------------------------------------------------- #
# Admission: escalate BEFORE any model spend
# --------------------------------------------------------------------------- #
def resolution_row_capacity():
    try:
        schema = json.loads(_RESOLUTION_SCHEMA.read_text(encoding="utf-8"))
        capacity = schema["properties"]["resolutions"]["maxItems"]
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise AssistError("the merge resolution schema capacity is unavailable") from error
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
        raise AssistError("the merge resolution schema capacity is invalid")
    return capacity


def admit_conflicts(entries, max_files, max_lines):
    """Return ``(ok, reason)`` for a complete conflicted-file enumeration.

    Every rule here refuses rather than guesses. The exclusion set is the exact
    ``_auto_merge_exclusions`` judgment auto-merge already encodes, so the files
    where an injected or mis-chosen line would be most damaging - workflows,
    governance, dependencies, security, migrations, build entrypoints,
    VISION.md - never reach the model at all.
    """
    if not isinstance(entries, list) or not entries:
        return False, "no complete conflict enumeration was available"
    if len(entries) > max_files:
        return False, "%d conflicted files exceed the limit of %d" % (
            len(entries),
            max_files,
        )
    paths = []
    total_lines = 0
    total_hunks = 0
    for entry in entries:
        if not isinstance(entry, dict):
            return False, "conflict enumeration is malformed"
        path = str(entry.get("path") or "")
        if not path or len(path) > _MAX_PATH_LENGTH:
            return False, "conflicted path is missing or oversized"
        if _CONTROL_CHARACTER.search(path):
            return False, "conflicted path contains a control character"
        paths.append(path)
        if entry.get("status") != "UU":
            return False, "%s is not a both-modified text conflict (%s)" % (
                path,
                _bounded(entry.get("status") or "unknown", 40),
            )
        stage_modes = []
        for stage in ("ours_mode", "theirs_mode", "base_mode"):
            mode = str(entry.get(stage) or "")
            if not mode:
                return False, "%s lacks a complete three-stage merge index" % path
            if mode not in _ADMITTED_MODES:
                return False, "%s has an unsupported entry mode (%s)" % (path, mode)
            stage_modes.append(mode)
        if len(set(stage_modes)) != 1:
            return False, "%s has differing stage modes and cannot be resolved safely" % path
        if entry.get("binary") is not False:
            return False, "%s is binary or not valid UTF-8 text" % path
        if entry.get("lfs") is not False:
            return False, "%s looks like a Git LFS pointer" % path
        try:
            hunk_lines = int(entry.get("conflict_lines"))
        except (TypeError, ValueError):
            return False, "%s has no conflicted-line count" % path
        if hunk_lines < 1:
            return False, "%s has no parsable conflict hunk" % path
        try:
            hunks = int(entry.get("hunks"))
        except (TypeError, ValueError):
            return False, "%s has no conflict-hunk count" % path
        if hunks < 1:
            return False, "%s has no parsable conflict hunk" % path
        total_lines += hunk_lines
        total_hunks += hunks
    excluded = core._auto_merge_exclusions(paths)
    if excluded:
        return False, "conflicted path is in the unconditional exclusion set: %s" % (
            _bounded(", ".join(sorted(excluded)), 200)
        )
    if total_lines > max_lines:
        return False, "%d conflicted lines exceed the limit of %d" % (
            total_lines,
            max_lines,
        )
    capacity = resolution_row_capacity()
    if total_hunks > capacity:
        return False, "%d conflict hunks exceed the result capacity of %d" % (
            total_hunks,
            capacity,
        )
    return True, ""


def parse_name_status_z(output):
    """Return every path from a complete ``git diff --name-status -z`` result."""
    if output == "":
        return []
    if not isinstance(output, str) or not output.endswith("\0"):
        raise AssistError("the base-to-resolution path list is incomplete")
    fields = output.split("\0")
    fields.pop()
    paths = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        path_count = 2 if re.fullmatch(r"[RC](?:100|[0-9]{1,2})", status) else 1
        if status not in {"A", "M", "D", "T"} and path_count == 1:
            raise AssistError("the base-to-resolution path list has an unsupported status")
        if index + path_count > len(fields):
            raise AssistError("the base-to-resolution path list is malformed")
        record_paths = fields[index : index + path_count]
        if any(not path for path in record_paths):
            raise AssistError("the base-to-resolution path list has an empty path")
        paths.extend(record_paths)
        index += path_count
    return paths


def workflow_touch_reason(paths):
    """Refuse any path whose merge result would trip the manual-UI merge gate.

    Neither `FLEET_TOKEN` nor the classic push PAT carries `workflow` scope, so
    a resolution that introduced a `.github/workflows/**` change into the PR's
    history would be unpushable AND unmergeable. Detect it before acting.
    """
    touched = core._workflow_merge_gated_files(paths or [])
    if touched:
        return "the base-to-resolution path touches %s; workflow changes stay a manual GitHub UI merge" % (
            _bounded(", ".join(sorted(touched)), 200)
        )
    return ""


# --------------------------------------------------------------------------- #
# The model result boundary
# --------------------------------------------------------------------------- #
def normalize_resolution(candidate, expected):
    """Validate a model candidate against the exact conflicted hunk inventory.

    ``expected`` is ``{path: hunk_count}`` derived by trusted code from the
    mechanical merge. The candidate must address every hunk exactly once, name
    no other path, and choose only from the fixed selection vocabulary.
    """
    if not isinstance(candidate, dict):
        raise AssistError("resolution result is not an object")
    status = candidate.get("status")
    if status == CANNOT_RESOLVE:
        raise AssistError(
            "the resolver declined: %s"
            % (_bounded(candidate.get("reason")) or "no reason given")
        )
    if status != "resolved":
        raise AssistError("resolution result has an unsupported status")
    rows = candidate.get("resolutions")
    if not isinstance(rows, list) or not rows:
        raise AssistError("resolution result carries no hunk selections")
    seen = {}
    for row in rows:
        if not isinstance(row, dict):
            raise AssistError("hunk selection is malformed")
        path = row.get("file")
        selection = row.get("selection")
        hunk = row.get("hunk")
        if not isinstance(path, str) or path not in expected:
            raise AssistError("hunk selection names a path outside the conflict set")
        if selection not in SELECTIONS:
            raise AssistError("hunk selection is outside the admitted vocabulary")
        if isinstance(hunk, bool) or not isinstance(hunk, int):
            raise AssistError("hunk index is not an integer")
        if not 0 <= hunk < expected[path]:
            raise AssistError("hunk index is outside the conflicted hunk inventory")
        if (path, hunk) in seen:
            raise AssistError("hunk selection is duplicated")
        seen[(path, hunk)] = selection
    for path, count in expected.items():
        for hunk in range(count):
            if (path, hunk) not in seen:
                raise AssistError("resolution does not cover every conflict hunk")
    return {
        path: [seen[(path, index)] for index in range(count)]
        for path, count in expected.items()
    }


def resolution_digest(selections):
    payload = json.dumps(selections, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def conflict_digest(entries, base_sha=""):
    """Bind an exact conflict inventory so two jobs cannot disagree.

    The model job and the resolving job each derive the mechanical merge
    independently. If the second derivation differs in any way - including the
    base commit or exact conflicted file bytes - the resolution is refused
    instead of being applied to a tree the model never saw.
    """
    payload = json.dumps(
        {"base_sha": str(base_sha or ""), "entries": entries},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Durable, head-bound, NON-MATERIAL card record
# --------------------------------------------------------------------------- #
def build_record(
    *,
    source_mode,
    original_head_sha,
    base_sha,
    phase,
    conflicted_paths=(),
    resolution_head_sha="",
    escalation_reason="",
    digest="",
    confirmation_label_may_be_present=False,
    push_outcome=None,
):
    if phase not in (PHASE_AWAITING_CONFIRMATION, PHASE_ESCALATED):
        raise AssistError("unsupported assisted-merge phase")
    # Only a proven-eligible source can carry a PUSHED record. An escalation may
    # honestly record an unverified source, because failing to verify the source
    # is itself one of the reasons an assist stops.
    if phase == PHASE_AWAITING_CONFIRMATION:
        if source_mode not in _ELIGIBLE_SOURCE_MODES:
            raise AssistError("a pushed assisted merge requires an eligible source")
    elif source_mode not in core.PUSHABILITY_MODES:
        raise AssistError("assisted merge requires a known source mode")
    if push_outcome is None:
        push_outcome = (
            PUSH_OUTCOME_PUSHED
            if phase == PHASE_AWAITING_CONFIRMATION
            else PUSH_OUTCOME_NOT_PUSHED
        )
    if push_outcome not in _PUSH_OUTCOMES:
        raise AssistError("unsupported assisted-merge push outcome")
    if phase == PHASE_AWAITING_CONFIRMATION and push_outcome != PUSH_OUTCOME_PUSHED:
        raise AssistError("an awaiting confirmation record requires a proven push")
    record = {
        "version": ASSIST_VERSION,
        "mode": ASSIST_MODE,
        "source_mode": source_mode,
        "original_head_sha": str(original_head_sha or ""),
        "base_sha": str(base_sha or ""),
        "resolution_head_sha": str(resolution_head_sha or ""),
        "phase": phase,
        "conflicted_paths": [
            _bounded(path, _MAX_PATH_LENGTH) for path in list(conflicted_paths)[:20]
        ],
        "escalation_reason": _bounded(escalation_reason),
        "resolution_digest": str(digest or ""),
        "confirmation_label_may_be_present": bool(
            confirmation_label_may_be_present
        ),
        "push_outcome": push_outcome,
    }
    if phase == PHASE_AWAITING_CONFIRMATION and not _SHA40.fullmatch(
        record["resolution_head_sha"]
    ):
        raise AssistError("a pushed assisted merge requires its resolution head SHA")
    return record


# --------------------------------------------------------------------------- #
# Stage 0: bind (exact live re-read under FLEET_TOKEN, no writes)
# --------------------------------------------------------------------------- #
def assisted_merge_policy(repo):
    cfg = core.load_config()
    repo_cfg = (cfg.get("repos") or {}).get(repo) or {}
    return {
        "enabled": core._assisted_merge_enabled(repo_cfg, cfg.get("assisted_merge")),
        "max_files": core._assisted_merge_max_files(
            repo_cfg, cfg.get("assisted_merge_max_conflict_files")
        ),
        "max_lines": core._assisted_merge_max_lines(
            repo_cfg, cfg.get("assisted_merge_max_conflict_lines")
        ),
    }


def bind(owner, repo, number, head_sha, card_issue):
    """Prove the exact target is still an eligible assisted-merge candidate."""
    slug = "%s/%s" % (owner, repo)
    policy = assisted_merge_policy(repo)
    if not policy["enabled"]:
        raise AssistError(
            "assisted in-place merge is not enabled for %s (set assisted_merge in "
            "wheelhouse.config.yml)" % repo
        )
    source_pr = core.gh_graphql_pr(owner, repo, number)
    pushability = core.derive_pushability(source_pr)
    mode = pushability.get("mode")
    if mode not in _ELIGIBLE_SOURCE_MODES:
        raise AssistError(
            "source branch cannot be updated by maintainers (%s)"
            % _bounded(pushability.get("reason"), 160)
        )
    source = pushability.get("source") or {}
    if source.get("head_sha") != head_sha:
        raise AssistError("the pull request head moved since the merge decision")
    if str(source_pr.get("state") or "").upper() != "OPEN":
        raise AssistError("the pull request is no longer open")

    pr = core.gh_rest("/repos/%s/pulls/%s" % (slug, number))
    if not isinstance(pr, dict):
        raise AssistError("the pull request could not be re-read")
    if pr.get("merged") or str(pr.get("state") or "") != "open":
        raise AssistError("the pull request is no longer open")
    no_assist = core.target_label_state(owner, repo, number, NO_ASSIST_LABEL)
    if no_assist is None:
        raise AssistError("the target's assisted-merge kill switch could not be verified")
    if no_assist is True:
        raise AssistError("the target carries the %s label" % NO_ASSIST_LABEL)
    if str((pr.get("head") or {}).get("sha") or "") != head_sha:
        raise AssistError("the pull request head moved since the merge decision")
    base_ref = str((pr.get("base") or {}).get("ref") or "")
    base_sha = str((pr.get("base") or {}).get("sha") or "")
    repo_info = core.gh_rest("/repos/%s" % slug)
    default_branch = str((repo_info or {}).get("default_branch") or "")
    if not base_ref or not default_branch or base_ref != default_branch:
        raise AssistError("assisted merge only targets the repository default branch")
    if not _SHA40.fullmatch(base_sha):
        raise AssistError("the base branch revision could not be verified")
    commit_count = core._changed_file_count(pr.get("commits"))
    if commit_count is None:
        raise AssistError("the pull request commit count could not be verified")
    if commit_count + 1 > core.PR_COMMITS_API_CAP:
        raise AssistError(
            "assisted merge would exceed the %s-commit confirmation proof limit; "
            "merge this pull request by hand" % core.PR_COMMITS_API_CAP
        )

    # The PR as it stands today must already be free of the manual-UI workflow
    # policy. A base-to-resolution workflow touch is checked locally in
    # `prepare`, where the exact merge base is known.
    gate = apply_decision._workflow_merge_gate(owner, repo, number, pr)
    if gate.get("status") != apply_decision.WORKFLOW_GATE_CLEAR:
        raise AssistError(
            "workflow-touching pull requests stay a manual GitHub UI merge (%s)"
            % _bounded(gate.get("reason"), 160)
        )

    head_ref = str((pr.get("head") or {}).get("ref") or "")
    head_repo = (pr.get("head") or {}).get("repo") or {}
    head_full_name = str(head_repo.get("full_name") or "") if isinstance(head_repo, dict) else ""
    if not head_ref or not head_full_name:
        raise AssistError("the source branch coordinates could not be verified")
    proven_repository = (
        slug
        if mode == core.PUSHABILITY_SAME_REPO
        else str(source.get("repository") or "")
    )
    proven_ref = str(source.get("head_ref") or "")
    if (
        not proven_repository
        or head_full_name.casefold() != proven_repository.casefold()
        or head_ref != proven_ref
    ):
        raise AssistError(
            "the source branch coordinates changed between authoritative reads"
        )
    for ref in (head_ref, base_ref):
        if not _SAFE_REF.fullmatch(ref) or ".." in ref:
            raise AssistError("a branch name is not a safe ref for this transaction")
    author_node = source_pr.get("author") or {}
    author = str(core._author_login(author_node) or "")
    if not author or core._author_is_bot(author_node) or author.casefold() in {
        login.casefold() for login in core.maintainers()
    }:
        raise AssistError("assisted merge is only for contributor pull requests")
    # The numeric id comes from a trusted API read, never from PR text, so the
    # `Co-authored-by` trailer credits the real contributor account.
    user = pr.get("user") if isinstance(pr.get("user"), dict) else {}
    author_id = user.get("id")
    if (
        isinstance(author_id, bool)
        or not isinstance(author_id, int)
        or author_id < 1
        or str(user.get("login") or "").casefold() != author.casefold()
    ):
        raise AssistError("the contributor's GitHub account could not be verified")

    return {
        "owner": owner,
        "repo": repo,
        "number": int(number),
        "card_issue": int(card_issue),
        "head_sha": head_sha,
        "head_ref": head_ref,
        "base_ref": base_ref,
        "base_sha": base_sha,
        "source_mode": mode,
        "source_repo": head_full_name,
        "author": author,
        "author_id": author_id,
        "max_files": policy["max_files"],
        "max_lines": policy["max_lines"],
    }


# --------------------------------------------------------------------------- #
# Stage 1/2: prepare (credential-free mechanical merge + admission)
# --------------------------------------------------------------------------- #
def _status_codes(repo):
    codes = {}
    result = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    for entry in result.stdout.split("\0"):
        if len(entry) > 3:
            codes[entry[3:]] = entry[:2]
    return codes


def _unmerged_stages(repo):
    stages = {}
    result = git(repo, "ls-files", "-u", "-z")
    for entry in result.stdout.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) != 3 or not path:
            raise AssistError("the merge index could not be read exactly")
        mode, _, stage = parts
        stages.setdefault(path, {})[stage] = mode
    return stages


def _file_text(path):
    raw = Path(path).read_bytes()
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def enumerate_conflicts(repo):
    """Describe every unmerged path exactly, or raise."""
    stages = _unmerged_stages(repo)
    codes = _status_codes(repo)
    entries = []
    for path in sorted(stages):
        target = Path(repo) / path
        stage_modes = stages[path]
        entry = {
            "path": path,
            "status": codes.get(path, "??"),
            "base_mode": stage_modes.get("1", ""),
            "ours_mode": stage_modes.get("2", ""),
            "theirs_mode": stage_modes.get("3", ""),
            "binary": True,
            "lfs": True,
            "conflict_lines": 0,
            "hunks": 0,
            "content_sha256": "",
        }
        if target.is_symlink() or not target.is_file():
            entries.append(entry)
            continue
        text = _file_text(target)
        if text is None:
            entries.append(entry)
            continue
        entry["binary"] = False
        entry["lfs"] = text.startswith(_LFS_POINTER)
        try:
            parsed = parse_conflicted_text(text)
        except AssistError:
            entries.append(entry)
            continue
        entry["conflict_lines"] = conflict_line_count(parsed)
        entry["hunks"] = len(parsed["hunks"])
        entry["content_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        entries.append(entry)
    return entries


def conflict_document(repo, entries):
    """Bounded, untrusted, pass-by-reference conflict payload for the model."""
    blocks = [
        "# Merge conflicts to resolve",
        "",
        "`ours` is the pull request branch. `theirs` is the base branch being merged in.",
        "Every hunk below must get exactly one selection.",
        "",
    ]
    for entry in entries:
        text = _file_text(Path(repo) / entry["path"])
        parsed = parse_conflicted_text(text)
        blocks.append("## file: %s" % entry["path"])
        blocks.append("")
        cursor = []
        hunk_index = 0
        for kind, value in parsed["segments"]:
            if kind == "literal":
                cursor = value
                continue
            hunk = parsed["hunks"][value]
            blocks.append("### hunk %d" % hunk_index)
            blocks.append("")
            blocks.append("context before:")
            blocks.append("```")
            blocks.extend(cursor[-_CONTEXT_LINES:])
            blocks.append("```")
            blocks.append("ours:")
            blocks.append("```")
            blocks.extend(hunk["ours"])
            blocks.append("```")
            blocks.append("theirs:")
            blocks.append("```")
            blocks.extend(hunk["theirs"])
            blocks.append("```")
            blocks.append("")
            hunk_index += 1
        blocks.append("")
    document = "\n".join(blocks)
    if len(document.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise AssistError("the conflict payload exceeds its bounded transport size")
    return document


def fetch_target(binding, repo_dir, token, askpass_dir):
    """Create a credential-free local repository holding exactly two commits.

    The contributor's head is served by the BASE repository as
    ``refs/pull/N/head``, so no fork remote and no fork credential is involved
    in reading it. Nothing from the target is executed: hooks are disabled,
    LFS smudging is off, and no checkout of a submodule is ever attempted.
    """
    directory = Path(repo_dir)
    directory.mkdir(parents=True, exist_ok=True)
    base_ref = str(binding.get("base_ref") or "")
    if not _SAFE_REF.fullmatch(base_ref) or ".." in base_ref:
        raise AssistError("the base branch name is not a safe ref to fetch")
    remote = "https://github.com/%s/%s.git" % (binding["owner"], binding["repo"])
    git(directory, "init", "--quiet")
    git(directory, "config", "core.hooksPath", "/dev/null")
    git(directory, "config", "advice.detachedHead", "false")
    env_extra = {}
    if token:
        askpass = _askpass_script(askpass_dir)
        env_extra = {
            "GIT_ASKPASS": str(askpass),
            "WHEELHOUSE_GIT_USERNAME": "x-access-token",
            "WHEELHOUSE_GIT_PASSWORD": token,
        }
    git(
        directory,
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        remote,
        "refs/pull/%d/head:refs/wheelhouse/head" % int(binding["number"]),
        "refs/heads/%s:refs/wheelhouse/base" % base_ref,
        env_extra=env_extra,
    )
    head = git(directory, "rev-parse", "refs/wheelhouse/head").stdout.strip()
    base = git(directory, "rev-parse", "refs/wheelhouse/base").stdout.strip()
    if head != binding["head_sha"]:
        raise AssistError("the pull request head moved since the merge decision")
    if not _SHA40.fullmatch(base):
        raise AssistError("the base branch revision could not be verified")
    return base


def prepare(binding, repo_dir):
    """Merge mechanically and decide whether a model turn may be spent."""
    head_sha = binding["head_sha"]
    base_sha = binding["base_sha"]
    git(repo_dir, "checkout", "--detach", head_sha)
    merge_base = git(repo_dir, "merge-base", head_sha, base_sha).stdout.strip()
    if not _SHA40.fullmatch(merge_base):
        raise AssistError("the merge base could not be determined")
    advanced = git(
        repo_dir, "diff", "--name-status", "-z", "%s..%s" % (merge_base, base_sha)
    ).stdout
    reason = workflow_touch_reason(parse_name_status_z(advanced))
    if reason:
        raise AssistError(reason)

    merge = git(
        repo_dir,
        "merge",
        "--no-ff",
        "--no-commit",
        "--no-verify",
        base_sha,
        check=False,
    )
    entries = enumerate_conflicts(repo_dir)
    if not entries:
        if merge.returncode != 0:
            raise AssistError(
                "the mechanical merge failed without a parsable conflict: %s"
                % _bounded(merge.stderr or merge.stdout)
            )
        return {"conflicts": [], "document": "", "admitted": True, "reason": ""}
    admitted, reason = admit_conflicts(
        entries, binding["max_files"], binding["max_lines"]
    )
    if not admitted:
        return {"conflicts": entries, "document": "", "admitted": False, "reason": reason}
    return {
        "conflicts": entries,
        "document": conflict_document(repo_dir, entries),
        "admitted": True,
        "reason": "",
    }


# --------------------------------------------------------------------------- #
# Stage 3/4: apply the trusted resolution and commit
# --------------------------------------------------------------------------- #
def _merged_index(repo):
    """Every already-merged (stage 0) index entry, as path -> (mode, blob).

    A `git merge --no-commit` legitimately stages everything the base branch
    changed. Confinement therefore cannot be "nothing else is staged"; it is
    "nothing already-merged by git changed", compared exactly.
    """
    entries = {}
    for row in git(repo, "ls-files", "-s", "-z").stdout.split("\0"):
        if not row:
            continue
        meta, _, path = row.partition("\t")
        parts = meta.split()
        if len(parts) != 3 or not path:
            raise AssistError("the merge index could not be read exactly")
        mode, blob, stage = parts
        if stage == "0":
            entries[path] = (mode, blob)
    return entries


def apply_resolution(repo_dir, entries, selections_by_path):
    """Write the resolved bytes with trusted code and verify total confinement.

    Confinement is proved against git's own index, not against trust in a tool
    boundary: every entry git had already merged must be byte-identical
    afterwards, and the only entries that may appear are exactly the conflicted
    paths this resolution was admitted for.
    """
    conflicted = {entry["path"] for entry in entries}
    before = _merged_index(repo_dir)
    for path in sorted(conflicted):
        target = Path(repo_dir) / path
        parsed = parse_conflicted_text(_file_text(target))
        resolved = render_resolution(parsed, selections_by_path[path])
        target.write_text(resolved, encoding="utf-8")
        git(repo_dir, "add", "--", path)
    if _unmerged_stages(repo_dir):
        raise AssistError("unmerged index entries survived the resolution")
    after = _merged_index(repo_dir)
    appeared = set(after) - set(before)
    if appeared != conflicted:
        raise AssistError(
            "the resolution staged files outside the conflict set: %s"
            % _bounded(", ".join(sorted(appeared ^ conflicted)), 200)
        )
    changed = [path for path, value in before.items() if after.get(path) != value]
    if changed:
        raise AssistError(
            "the resolution modified already-merged files: %s"
            % _bounded(", ".join(sorted(changed)), 200)
        )
    untracked = sorted(
        path for path, code in _status_codes(repo_dir).items() if code == "??"
    )
    if untracked:
        raise AssistError(
            "the resolution left untracked files: %s"
            % _bounded(", ".join(untracked), 200)
        )
    for path in sorted(conflicted):
        if contains_conflict_marker(_file_text(Path(repo_dir) / path) or ""):
            raise AssistError("a conflict marker survived in %s" % path)
    whitespace = git(
        repo_dir,
        "diff",
        "--cached",
        "--check",
        "--",
        *sorted(conflicted),
        check=False,
    )
    if whitespace.returncode != 0:
        raise AssistError("the staged resolution failed git's whitespace/marker check")
    return sorted(conflicted)


def commit_message(binding, conflicted_paths, author_id):
    lines = [
        "Merge branch '%s' into %s"
        % (binding["base_ref"], _bounded(binding["head_ref"], 120)),
        "",
        "Merge conflicts were resolved in:",
    ]
    lines.extend("  %s" % path for path in conflicted_paths)
    lines.append("")
    lines.append(
        "Co-authored-by: %s <%s+%s@users.noreply.github.com>"
        % (binding["author"], author_id, binding["author"])
    )
    return "\n".join(lines) + "\n"


def commit_resolution(repo_dir, binding, conflicted_paths, author_id, identity):
    message = commit_message(binding, conflicted_paths, author_id)
    git(
        repo_dir,
        "commit",
        "--no-verify",
        "--no-gpg-sign",
        "-m",
        message,
        env_extra={
            "GIT_AUTHOR_NAME": identity["name"],
            "GIT_AUTHOR_EMAIL": identity["email"],
            "GIT_COMMITTER_NAME": identity["name"],
            "GIT_COMMITTER_EMAIL": identity["email"],
        },
    )
    resolution = git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    if not _SHA40.fullmatch(resolution):
        raise AssistError("the resolution commit could not be identified")
    parents = git(repo_dir, "rev-list", "--parents", "-n", "1", "HEAD").stdout.split()
    if len(parents) != 3 or parents[1] != binding["head_sha"] or parents[2] != binding["base_sha"]:
        raise AssistError("the resolution commit does not have the exact two parents")
    return resolution


# --------------------------------------------------------------------------- #
# Stage 5: the one credentialed plain push after an exact-head re-read
# --------------------------------------------------------------------------- #
def push_remote_url(binding):
    if binding.get("source_mode") not in _ELIGIBLE_SOURCE_MODES:
        raise AssistError("the source mode may not receive an assisted push")
    slug = binding["source_repo"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", slug):
        raise AssistError("the source repository slug is not a safe remote identity")
    return "https://github.com/%s.git" % slug


def push_token_env_name(source_mode):
    """Return the credential authorized for an eligible source mode."""
    if source_mode == core.PUSHABILITY_PERSONAL_FORK_EDITABLE:
        return PUSH_TOKEN_SECRET
    if source_mode == core.PUSHABILITY_SAME_REPO:
        return "FLEET_TOKEN"
    raise AssistError("no push credential is authorized for this source mode")


def _askpass_script(directory):
    script = Path(directory) / "wheelhouse-askpass"
    script.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  Username*) printf '%s' \"$WHEELHOUSE_GIT_USERNAME\" ;;\n"
        "  Password*) printf '%s' \"$WHEELHOUSE_GIT_PASSWORD\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _redact(text, secret):
    text = str(text or "")
    if secret:
        text = text.replace(secret, "***")
    return _bounded(text, 300)


def verified_push_plan(repo_dir, binding, resolution_sha):
    push_token_env_name(binding.get("source_mode"))
    head_ref = str(binding.get("head_ref") or "")
    if not _SAFE_REF.fullmatch(head_ref) or ".." in head_ref:
        raise AssistError("the source branch name is not a safe push target")
    remote = push_remote_url(binding)
    ref = "refs/heads/%s" % head_ref
    observed = git(repo_dir, "ls-remote", remote, ref, check=False)
    if observed.returncode != 0:
        raise AssistError(
            "the source branch could not be re-read before pushing: %s"
            % _bounded(observed.stderr, 300)
        )
    current = observed.stdout.split("\t")[0].strip() if observed.stdout.strip() else ""
    if current != binding["head_sha"]:
        raise AssistError(
            "the source branch moved before the push (expected %s, observed %s)"
            % (binding["head_sha"][:12], (current or "<absent>")[:12])
        )
    return {
        "remote": remote,
        "refspec": "%s:%s" % (resolution_sha, ref),
        "target_ref": ref,
        "expected_head_sha": binding["head_sha"],
    }


def push_resolution(repo_dir, plan, token, askpass_dir):
    """Perform the single credentialed plain, non-force push."""
    if not token:
        raise AssistError("the selected push credential is unavailable")
    remote = str(plan.get("remote") or "")
    refspec = str(plan.get("refspec") or "")
    target_ref = str(plan.get("target_ref") or "")
    expected_head_sha = str(plan.get("expected_head_sha") or "")
    if (
        not remote.startswith("https://github.com/")
        or not re.fullmatch(r"[0-9a-f]{40}:refs/heads/[A-Za-z0-9._/-]+", refspec)
        or not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", target_ref)
        or not _SHA40.fullmatch(expected_head_sha)
        or refspec.split(":", 1)[1] != target_ref
    ):
        raise AssistError("the verified push plan is malformed")
    observed = git(repo_dir, "ls-remote", remote, target_ref, check=False)
    if observed.returncode != 0:
        raise AssistError(
            "the source branch could not be re-read at the push boundary: %s"
            % _bounded(observed.stderr, 300)
        )
    current = observed.stdout.split("\t")[0].strip() if observed.stdout.strip() else ""
    if current != expected_head_sha:
        raise AssistError(
            "the source branch moved before the push (expected %s, observed %s)"
            % (expected_head_sha[:12], (current or "<absent>")[:12])
        )
    askpass = _askpass_script(askpass_dir)
    try:
        result = git(
            repo_dir,
            "push",
            remote,
            refspec,
            env_extra={
                "GIT_ASKPASS": str(askpass),
                "WHEELHOUSE_GIT_USERNAME": "x-access-token",
                "WHEELHOUSE_GIT_PASSWORD": token,
            },
            check=False,
        )
    finally:
        askpass.unlink(missing_ok=True)
    if result.returncode != 0:
        raise AssistError(
            "the non-force push to the pull request branch was refused: %s"
            % _redact(result.stderr, token)
        )
    return refspec.split(":", 1)[0]


# --------------------------------------------------------------------------- #
# CLI (each subcommand runs in exactly one workflow step / token context)
# --------------------------------------------------------------------------- #
def _fail(binding_defaults, error, output_path):
    record = {
        "status": "escalated",
        "reason": _bounded(str(error)),
        "binding": binding_defaults,
    }
    _write(output_path, record)
    _output("status", "escalated")
    _output("reason", record["reason"])


def cmd_bind(args):
    defaults = {
        "owner": args.owner,
        "repo": args.repo,
        "number": int(args.number),
        "card_issue": int(args.issue),
        "head_sha": args.head_sha,
    }
    try:
        binding = bind(args.owner, args.repo, args.number, args.head_sha, args.issue)
    except (AssistError, RuntimeError, TypeError, ValueError, KeyError) as error:
        _fail(defaults, error, args.out)
        return
    _write(args.out, {"status": "bound", "reason": "", "binding": binding})
    _output("status", "bound")
    _output("source_mode", binding["source_mode"])
    _output("head_ref", binding["head_ref"])
    _output("base_sha", binding["base_sha"])


def cmd_prepare(args):
    state = _load(args.state, {}) or {}
    binding = state.get("binding") or {}
    try:
        if state.get("status") != "bound":
            raise AssistError(state.get("reason") or "the target was never bound")
        binding = dict(binding)
        binding["base_sha"] = fetch_target(
            binding,
            args.repo_dir,
            os.environ.get("WHEELHOUSE_ASSIST_FETCH_TOKEN", ""),
            args.askpass_dir,
        )
        result = prepare(binding, args.repo_dir)
    except (AssistError, RuntimeError, OSError, TypeError, ValueError, KeyError) as error:
        _fail(binding, error, args.out)
        return
    if not result["admitted"]:
        _fail(binding, AssistError(result["reason"]), args.out)
        return
    conflicts = result["conflicts"]
    digest = conflict_digest(conflicts, binding["base_sha"])
    if args.expect_digest and args.expect_digest != digest:
        _fail(
            binding,
            AssistError(
                "the conflict set changed between preparation and resolution"
            ),
            args.out,
        )
        return
    if result["document"]:
        Path(args.document).write_text(result["document"], encoding="utf-8")
    _write(
        args.out,
        {
            "status": "resolvable" if conflicts else "clean",
            "reason": "",
            "binding": binding,
            "conflicts": conflicts,
            "conflict_digest": digest,
        },
    )
    _output("status", "resolvable" if conflicts else "clean")
    _output("conflicted_files", len(conflicts))
    _output("conflict_digest", digest)


def cmd_apply(args):
    state = _load(args.state, {}) or {}
    binding = state.get("binding") or {}
    conflicts = state.get("conflicts") or []
    try:
        if state.get("status") not in {"resolvable", "clean"}:
            raise AssistError(state.get("reason") or "no admitted conflict set")
        selections = {}
        if conflicts:
            candidate = _load(args.result)
            expected = {entry["path"]: entry["hunks"] for entry in conflicts}
            selections = normalize_resolution(candidate, expected)
        paths = apply_resolution(args.repo_dir, conflicts, selections)
        author_id = int(binding.get("author_id") or 0)
        if author_id < 1:
            raise AssistError("the contributor's numeric GitHub id is required")
        resolution = commit_resolution(
            args.repo_dir,
            binding,
            paths,
            author_id,
            {"name": args.identity_name, "email": args.identity_email},
        )
    except (AssistError, RuntimeError, OSError, TypeError, ValueError, KeyError) as error:
        _fail(binding, error, args.out)
        return
    _write(
        args.out,
        {
            "status": "resolved",
            "reason": "",
            "binding": binding,
            "conflicted_paths": paths,
            "selections": selections,
            "resolution_digest": resolution_digest(selections),
            "resolution_head_sha": resolution,
        },
    )
    _output("status", "resolved")
    _output("resolution_head_sha", resolution)


def _ensure_confirmation_label(binding):
    slug = "%s/%s" % (binding["owner"], binding["repo"])
    try:
        core.gh_rest(
            "/repos/%s/labels" % slug,
            method="POST",
            fields={
                "name": AWAITING_CONFIRM_LABEL,
                "color": "B60205",
                "description": "Assisted resolution awaits maintainer confirmation",
            },
        )
    except RuntimeError:
        core.gh_rest("/repos/%s/labels/%s" % (slug, quote(AWAITING_CONFIRM_LABEL, safe="")))
    core.gh_rest(
        "/repos/%s/issues/%s/labels" % (slug, binding["number"]),
        method="POST",
        fields={"labels[]": AWAITING_CONFIRM_LABEL},
    )


def _confirmation_denial_state(binding):
    slug = "%s/%s" % (binding["owner"], binding["repo"])
    pr = core.gh_rest("/repos/%s/pulls/%s" % (slug, binding["number"]))
    if not isinstance(pr, dict):
        raise AssistError("the pull request denial state could not be read")
    return {
        "head_sha": str(((pr.get("head") or {}).get("sha") or "")),
        "label": core.target_label_state(
            binding["owner"],
            binding["repo"],
            binding["number"],
            AWAITING_CONFIRM_LABEL,
        ),
    }


def apply_confirmation_denial(binding):
    slug = "%s/%s" % (binding["owner"], binding["repo"])
    try:
        pr = core.gh_rest("/repos/%s/pulls/%s" % (slug, binding["number"]))
        if not isinstance(pr, dict):
            raise PreMutationAssistError(
                "the pull request could not be read before applying the confirmation label"
            )
        if str(((pr.get("head") or {}).get("sha") or "")) != binding["head_sha"]:
            raise PreMutationAssistError(
                "the pull request head moved before applying the confirmation label"
            )
        no_assist = core.target_label_state(
            binding["owner"],
            binding["repo"],
            binding["number"],
            NO_ASSIST_LABEL,
        )
        if no_assist is None:
            raise PreMutationAssistError(
                "the target's assisted-merge kill switch could not be verified"
            )
        if no_assist is True:
            raise PreMutationAssistError(
                "the target carries the %s label" % NO_ASSIST_LABEL
            )
    except PreMutationAssistError:
        raise
    except (RuntimeError, OSError, TypeError, ValueError, KeyError) as error:
        raise PreMutationAssistError(str(error)) from error
    _ensure_confirmation_label(binding)
    verified = _confirmation_denial_state(binding)
    if verified["head_sha"] != binding["head_sha"]:
        raise AssistError("the pull request head moved while applying the confirmation label")
    if verified["label"] is not True:
        raise AssistError("the confirmation label could not be verified")
    return verified


def _credential_present_for_mode(source_mode, fork_present, same_repo_present):
    secret_name = push_token_env_name(source_mode)
    present = (
        fork_present
        if source_mode == core.PUSHABILITY_PERSONAL_FORK_EDITABLE
        else same_repo_present
    )
    if not present:
        raise AssistError(
            "the %s secret is not configured; assisted merge cannot push the "
            "resolution. Add it in Settings > Secrets and variables > Actions."
            % secret_name
        )


def rollback_confirmation_denial(binding):
    slug = "%s/%s" % (binding["owner"], binding["repo"])
    try:
        observed = _confirmation_denial_state(binding)
        if observed["head_sha"] != binding["head_sha"]:
            return False
        if observed["label"] is False:
            return True
        if observed["label"] is not True:
            return False
        core.gh_rest(
            "/repos/%s/issues/%s/labels/%s"
            % (slug, binding["number"], quote(AWAITING_CONFIRM_LABEL, safe="")),
            method="DELETE",
        )
        verified = _confirmation_denial_state(binding)
        return (
            verified["head_sha"] == binding["head_sha"]
            and verified["label"] is False
        )
    except (AssistError, RuntimeError, OSError, TypeError, ValueError, KeyError):
        return False


def cmd_claim_target(args):
    state = _load(args.state, {}) or {}
    original_binding = state.get("binding") or {}
    try:
        if state.get("status") != "resolved":
            raise AssistError(state.get("reason") or "there is no resolution to push")
        _credential_present_for_mode(
            original_binding.get("source_mode"),
            getattr(args, "fork_credential_present", False),
            getattr(args, "same_repo_credential_present", False),
        )
        plan = verified_push_plan(
            args.repo_dir, original_binding, state["resolution_head_sha"]
        )
    except (AssistError, RuntimeError, OSError, TypeError, ValueError, KeyError) as error:
        _fail(original_binding, str(error), args.out)
        return

    binding = dict(original_binding)
    binding["confirmation_label_may_be_present"] = True
    claim_intent = dict(state)
    claim_intent["status"] = "claim-intent"
    claim_intent["reason"] = "target confirmation claim was staged"
    claim_intent["binding"] = binding
    claim_intent["push_plan"] = plan
    claim_intent["push_outcome"] = PUSH_OUTCOME_UNCERTAIN
    try:
        _write(args.intent_out, claim_intent)
    except (OSError, TypeError, ValueError) as error:
        unchanged_binding = dict(original_binding)
        unchanged_binding["confirmation_label_may_be_present"] = False
        _fail(
            unchanged_binding,
            "target claim intent could not be persisted; the target was unchanged (%s)"
            % error,
            args.out,
        )
        return

    try:
        apply_confirmation_denial(binding)
    except PreMutationAssistError as error:
        unchanged_binding = dict(original_binding)
        unchanged_binding["confirmation_label_may_be_present"] = False
        _fail(
            unchanged_binding,
            "%s; no target mutation was attempted" % error,
            args.out,
        )
        return
    except (AssistError, RuntimeError, OSError, TypeError, ValueError, KeyError) as error:
        _fail(binding, str(error), args.out)
        return

    claimed = dict(claim_intent)
    claimed["status"] = "target-claimed"
    claimed["reason"] = ""
    claimed.pop("push_outcome", None)
    try:
        _write(args.out, claimed)
    except (OSError, TypeError, ValueError) as error:
        if rollback_confirmation_denial(binding):
            binding["confirmation_label_may_be_present"] = False
            _fail(
                binding,
                "target claim state could not be persisted; the confirmation label was rolled back",
                args.out,
            )
        else:
            uncertain = dict(claim_intent)
            uncertain["status"] = "escalated"
            uncertain["reason"] = _bounded(
                "target claim state could not be persisted; inspect the live pull request before acting (%s)"
                % error
            )
            try:
                _write(args.out, uncertain)
                _output("status", "escalated")
                _output("reason", uncertain["reason"])
            except (OSError, TypeError, ValueError):
                pass
        return
    _output("status", "target-claimed")


def cmd_push(args):
    state = _load(args.state, {}) or {}
    token = os.environ.pop("WHEELHOUSE_ASSIST_PUSH_TOKEN", "")
    try:
        if state.get("status") != "target-claimed":
            raise AssistError(state.get("reason") or "the target was not claimed for pushing")
        push_resolution(args.repo_dir, state.get("push_plan") or {}, token, args.askpass_dir)
    except (AssistError, RuntimeError, OSError, TypeError, ValueError, KeyError) as error:
        failed = dict(state)
        failed["status"] = "push-failed"
        failed["reason"] = _bounded(str(error))
        _write(args.out, failed)
        _output("status", "push-failed")
        _output("reason", failed["reason"])
        return
    pushed = dict(state)
    pushed["status"] = "pushed"
    _write(args.out, pushed)
    _output("status", "pushed")


def cmd_observe_push(args):
    state = _load(args.state, {}) or {}
    if state.get("status") == "pushed":
        _write(args.out, state)
        _output("status", "pushed")
        return
    observed = dict(state)
    observed["status"] = "escalated"
    observed["push_outcome"] = PUSH_OUTCOME_UNCERTAIN
    if state.get("status") == "push-failed":
        plan = state.get("push_plan") or {}
        remote = str(plan.get("remote") or "")
        target_ref = str(plan.get("target_ref") or "")
        expected = str(plan.get("expected_head_sha") or "")
        resolution = str(state.get("resolution_head_sha") or "")
        if (
            remote.startswith("https://github.com/")
            and re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", target_ref)
            and _SHA40.fullmatch(expected)
            and _SHA40.fullmatch(resolution)
        ):
            result = git(args.repo_dir, "ls-remote", remote, target_ref, check=False)
            if result.returncode == 0:
                current = result.stdout.split("\t")[0].strip() if result.stdout.strip() else ""
                if current == resolution:
                    observed["status"] = "pushed"
                    observed.pop("push_outcome", None)
                elif current == expected:
                    observed["push_outcome"] = PUSH_OUTCOME_NOT_PUSHED
    _write(args.out, observed)
    _output("status", observed["status"])
    if observed["status"] != "pushed":
        _output("push_outcome", observed["push_outcome"])


def select_outcome_state(state_dir):
    directory = Path(state_dir)
    for name in (
        "assist-push-observed.json",
        "assist-pushed.json",
        "assist-target-claimed.json",
        "assist-claim-intent.json",
        "assist-resolved.json",
        "assist-prepared.json",
        "assist-state.json",
    ):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def cmd_record_outcome(args):
    selected = select_outcome_state(args.state_dir)
    if selected is None:
        _output("status", "no-state")
        return
    cmd_record(argparse.Namespace(state=str(selected)))


def cmd_record(args):
    """Write the durable card record with the DEFAULT token only."""
    state = _load(args.state, {}) or {}
    binding = state.get("binding") or {}
    try:
        card_issue = int(binding.get("card_issue") or 0)
    except (TypeError, ValueError):
        card_issue = 0
    if card_issue < 1:
        _output("status", "no-card")
        return
    status = state.get("status")
    try:
        if status == "pushed":
            record = build_record(
                source_mode=binding["source_mode"],
                original_head_sha=binding["head_sha"],
                base_sha=binding["base_sha"],
                phase=PHASE_AWAITING_CONFIRMATION,
                conflicted_paths=state.get("conflicted_paths") or [],
                resolution_head_sha=state["resolution_head_sha"],
                digest=state.get("resolution_digest") or "",
            )
        else:
            explicit_outcome = state.get("push_outcome")
            push_outcome = (
                explicit_outcome
                if explicit_outcome in _PUSH_OUTCOMES
                else (
                    PUSH_OUTCOME_UNCERTAIN
                    if status in {"claim-intent", "target-claimed", "push-failed"}
                    else PUSH_OUTCOME_NOT_PUSHED
                )
            )
            record = build_record(
                source_mode=binding.get("source_mode")
                or core.PUSHABILITY_UNVERIFIED,
                original_head_sha=binding.get("head_sha") or "",
                base_sha=binding.get("base_sha") or "",
                phase=PHASE_ESCALATED,
                conflicted_paths=[
                    entry.get("path", "")
                    for entry in (state.get("conflicts") or [])
                    if isinstance(entry, dict)
                ],
                escalation_reason=state.get("reason") or "assisted merge did not finish",
                confirmation_label_may_be_present=bool(
                    binding.get("confirmation_label_may_be_present")
                ),
                push_outcome=push_outcome,
            )
    except AssistError as error:
        record = {
            "version": ASSIST_VERSION,
            "mode": ASSIST_MODE,
            "source_mode": core.PUSHABILITY_UNVERIFIED,
            "original_head_sha": str(binding.get("head_sha") or ""),
            "base_sha": "",
            "resolution_head_sha": "",
            "phase": PHASE_ESCALATED,
            "conflicted_paths": [],
            "escalation_reason": _bounded(str(error)),
            "resolution_digest": "",
            "confirmation_label_may_be_present": bool(
                binding.get("confirmation_label_may_be_present")
            ),
            "push_outcome": (
                state.get("push_outcome")
                if state.get("push_outcome") in _PUSH_OUTCOMES
                else (
                    PUSH_OUTCOME_UNCERTAIN
                    if status in {"claim-intent", "target-claimed", "push-failed"}
                    else PUSH_OUTCOME_NOT_PUSHED
                )
            ),
        }
    outcome = render_card.record_merge_assist(card_issue, record)
    committed = outcome in {"committed", "unchanged"}
    level = "notice" if committed else "warning"
    print(
        "::%s::wheelhouse merge-assist %s card=%s outcome=%s"
        % (level, record["phase"], card_issue, outcome)
    )
    _output("status", record["phase"] if committed else "record-%s" % outcome)
    _output("card_outcome", outcome)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    bind_parser = sub.add_parser("bind")
    bind_parser.add_argument("--owner", required=True)
    bind_parser.add_argument("--repo", required=True)
    bind_parser.add_argument("--number", required=True, type=int)
    bind_parser.add_argument("--head-sha", required=True, dest="head_sha")
    bind_parser.add_argument("--issue", required=True, type=int)
    bind_parser.add_argument("--out", required=True)
    bind_parser.set_defaults(func=cmd_bind)

    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--state", required=True)
    prepare_parser.add_argument("--repo-dir", required=True, dest="repo_dir")
    prepare_parser.add_argument("--askpass-dir", required=True, dest="askpass_dir")
    prepare_parser.add_argument("--document", required=True)
    prepare_parser.add_argument("--expect-digest", default="", dest="expect_digest")
    prepare_parser.add_argument("--out", required=True)
    prepare_parser.set_defaults(func=cmd_prepare)

    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("--state", required=True)
    apply_parser.add_argument("--repo-dir", required=True, dest="repo_dir")
    apply_parser.add_argument("--result", default="")
    apply_parser.add_argument("--identity-name", required=True, dest="identity_name")
    apply_parser.add_argument("--identity-email", required=True, dest="identity_email")
    apply_parser.add_argument("--out", required=True)
    apply_parser.set_defaults(func=cmd_apply)

    claim_target_parser = sub.add_parser("claim-target")
    claim_target_parser.add_argument("--state", required=True)
    claim_target_parser.add_argument("--repo-dir", required=True, dest="repo_dir")
    claim_target_parser.add_argument(
        "--fork-credential-present", action="store_true", dest="fork_credential_present"
    )
    claim_target_parser.add_argument(
        "--same-repo-credential-present",
        action="store_true",
        dest="same_repo_credential_present",
    )
    claim_target_parser.add_argument("--intent-out", required=True, dest="intent_out")
    claim_target_parser.add_argument("--out", required=True)
    claim_target_parser.set_defaults(func=cmd_claim_target)

    push_parser = sub.add_parser("push")
    push_parser.add_argument("--state", required=True)
    push_parser.add_argument("--repo-dir", required=True, dest="repo_dir")
    push_parser.add_argument("--askpass-dir", required=True, dest="askpass_dir")
    push_parser.add_argument("--out", required=True)
    push_parser.set_defaults(func=cmd_push)

    observe_push_parser = sub.add_parser("observe-push")
    observe_push_parser.add_argument("--state", required=True)
    observe_push_parser.add_argument("--repo-dir", required=True, dest="repo_dir")
    observe_push_parser.add_argument("--out", required=True)
    observe_push_parser.set_defaults(func=cmd_observe_push)

    record_parser = sub.add_parser("record")
    record_parser.add_argument("--state", required=True)
    record_parser.set_defaults(func=cmd_record)

    record_outcome_parser = sub.add_parser("record-outcome")
    record_outcome_parser.add_argument("--state-dir", required=True, dest="state_dir")
    record_outcome_parser.set_defaults(func=cmd_record_outcome)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
