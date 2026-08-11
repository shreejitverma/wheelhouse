#!/usr/bin/env python3
"""Captain-initiated assisted in-place merge (Phase 1), fully offline.

Covers the three things that actually make this safe:

1. The model can never author a line. Every resolved byte comes from the
   mechanical merge skeleton or from a line that already exists in one of the
   two merge parents, and trusted code - not the model - writes the file.
2. Risk escalates instead of being guessed: exclusion paths, non-text and
   non-both-modified conflicts, size caps, base-to-result workflow touches, an
   inventory that changed between jobs, and an unparsable conflict all refuse.
3. The push credential is confined to one plain, non-force update of the
   existing head ref after its exact SHA is re-read.

The end-to-end resolution case runs against a REAL local git repository, so the
conflict markers, merge index, and commit parents are git's own, not fixtures.
"""

import json
import os
import re
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import apply_decision  # noqa: E402
import auto_merge  # noqa: E402
import merge_assist  # noqa: E402
import render_card  # noqa: E402
import wheelhouse_core as core  # noqa: E402

_failures = []
IDENTITY = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def check(name, condition):
    print(("ok   " if condition else "FAIL ") + name)
    if not condition:
        _failures.append(name)


def raises(fn, exc=merge_assist.AssistError):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


# --------------------------------------------------------------------------- #
# Conflict parsing
# --------------------------------------------------------------------------- #
CONFLICTED = "\n".join(
    [
        "alpha",
        "<<<<<<< HEAD",
        "ours-1",
        "ours-2",
        "=======",
        "theirs-1",
        ">>>>>>> base",
        "omega",
    ]
)


def test_parsing():
    parsed = merge_assist.parse_conflicted_text(CONFLICTED)
    check("parse: one hunk with both sides", len(parsed["hunks"]) == 1)
    check(
        "parse: sides are exact parent lines",
        parsed["hunks"][0]["ours"] == ["ours-1", "ours-2"]
        and parsed["hunks"][0]["theirs"] == ["theirs-1"],
    )
    check("parse: conflicted lines counted", merge_assist.conflict_line_count(parsed) == 3)
    check(
        "parse: literal text is preserved around the hunk",
        parsed["segments"][0] == ("literal", ["alpha"])
        and parsed["segments"][-1] == ("literal", ["omega"]),
    )
    check(
        "parse: diff3 conflict style refuses",
        raises(
            lambda: merge_assist.parse_conflicted_text(
                "<<<<<<< a\nx\n||||||| base\nb\n=======\ny\n>>>>>>> b"
            )
        ),
    )
    check(
        "parse: unbalanced separator refuses",
        raises(lambda: merge_assist.parse_conflicted_text("a\n=======\nb")),
    )
    check(
        "parse: unterminated hunk refuses",
        raises(lambda: merge_assist.parse_conflicted_text("<<<<<<< a\nx\n=======\ny")),
    )
    check(
        "parse: nested marker refuses",
        raises(
            lambda: merge_assist.parse_conflicted_text(
                "<<<<<<< a\n<<<<<<< b\n=======\ny\n>>>>>>> b"
            )
        ),
    )
    check(
        "parse: a file with no hunk refuses",
        raises(lambda: merge_assist.parse_conflicted_text("plain\nfile")),
    )


def test_rendering_has_zero_novel_lines():
    parsed = merge_assist.parse_conflicted_text(CONFLICTED)
    rendered = {
        selection: merge_assist.render_resolution(parsed, [selection])
        for selection in merge_assist.SELECTIONS
    }
    check(
        "render: ours keeps only the pull request lines",
        rendered["ours"] == "alpha\nours-1\nours-2\nomega",
    )
    check(
        "render: theirs keeps only the base lines",
        rendered["theirs"] == "alpha\ntheirs-1\nomega",
    )
    check(
        "render: ours-then-theirs concatenates in order",
        rendered["ours-then-theirs"] == "alpha\nours-1\nours-2\ntheirs-1\nomega",
    )
    check(
        "render: theirs-then-ours concatenates in order",
        rendered["theirs-then-ours"] == "alpha\ntheirs-1\nours-1\nours-2\nomega",
    )
    parents = {"ours-1", "ours-2", "theirs-1"}
    literal = {"alpha", "omega"}
    check(
        "render: every output line is a skeleton or parent line",
        all(
            set(text.split("\n")) <= parents | literal for text in rendered.values()
        ),
    )
    check(
        "render: no marker survives any selection",
        not any(merge_assist.contains_conflict_marker(t) for t in rendered.values()),
    )
    check(
        "render: a selection list that misses a hunk refuses",
        raises(lambda: merge_assist.render_resolution(parsed, [])),
    )
    check(
        "render: an unsupported selection refuses",
        raises(lambda: merge_assist.render_resolution(parsed, ["merge-both"])),
    )


# --------------------------------------------------------------------------- #
# Admission: escalate BEFORE any model spend
# --------------------------------------------------------------------------- #
def entry(path="src/app.py", **overrides):
    row = {
        "path": path,
        "status": "UU",
        "base_mode": "100644",
        "ours_mode": "100644",
        "theirs_mode": "100644",
        "binary": False,
        "lfs": False,
        "conflict_lines": 4,
        "hunks": 1,
    }
    row.update(overrides)
    return row


def test_admission():
    ok, _ = merge_assist.admit_conflicts([entry()], 5, 200)
    check("admit: an ordinary small text conflict is admitted", ok)
    cases = {
        "empty enumeration": [],
        "workflow path": [entry(path=".github/workflows/ci.yml")],
        "governance path": [entry(path=".github/CODEOWNERS")],
        "dependency lockfile": [entry(path="package-lock.json")],
        "vision rubric": [entry(path="VISION.md")],
        "add/add conflict": [entry(status="AA")],
        "delete/modify conflict": [entry(status="DU")],
        "missing merge stage": [entry(theirs_mode="")],
        "symlink mode": [entry(ours_mode="120000")],
        "submodule mode": [entry(theirs_mode="160000")],
        "differing stage modes": [entry(theirs_mode="100755")],
        "binary content": [entry(binary=True)],
        "git-lfs pointer": [entry(lfs=True)],
        "unparsable hunk count": [entry(conflict_lines=0)],
        "newline in path": [entry(path="src/safe.py\n\nCo-authored-by: attacker <attacker@example.com>")],
        "control character in path": [entry(path="src/safe.py\x7f")],
        "malformed row": [{"path": "a"}],
    }
    for label, rows in cases.items():
        admitted, reason = merge_assist.admit_conflicts(rows, 5, 200)
        check("admit: %s escalates before model spend" % label, not admitted and reason)
    many = [entry(path="src/f%d.py" % index) for index in range(6)]
    admitted, reason = merge_assist.admit_conflicts(many, 5, 200)
    check("admit: too many conflicted files escalates", not admitted and "exceed" in reason)
    admitted, _ = merge_assist.admit_conflicts(many[:5], 5, 200)
    check("admit: exactly the file cap is admitted", admitted)
    big = [entry(conflict_lines=201)]
    admitted, reason = merge_assist.admit_conflicts(big, 5, 200)
    check("admit: too many conflicted lines escalates", not admitted and "exceed" in reason)
    admitted, _ = merge_assist.admit_conflicts([entry(conflict_lines=200)], 5, 200)
    check("admit: exactly the line cap is admitted", admitted)
    capacity = merge_assist.resolution_row_capacity()
    admitted, _ = merge_assist.admit_conflicts(
        [entry(conflict_lines=capacity, hunks=capacity)], 5, capacity
    )
    check("admit: exactly the schema hunk capacity is admitted", admitted)
    admitted, reason = merge_assist.admit_conflicts(
        [entry(conflict_lines=capacity + 1, hunks=capacity + 1)],
        5,
        capacity + 1,
    )
    check(
        "admit: exceeding the schema hunk capacity escalates before spend",
        not admitted and "result capacity" in reason,
    )
    check(
        "admit: a base-to-result workflow touch escalates",
        merge_assist.workflow_touch_reason([".github/workflows/ci.yml"]) != "",
    )
    check(
        "admit: an ordinary base advance does not",
        merge_assist.workflow_touch_reason(["README.md", "src/app.py"]) == "",
    )


# --------------------------------------------------------------------------- #
# The model result boundary
# --------------------------------------------------------------------------- #
def test_result_boundary():
    expected = {"a.py": 2, "b.py": 1}

    def candidate(rows, status="resolved"):
        return {"status": status, "reason": "", "resolutions": rows}

    good = candidate(
        [
            {"file": "a.py", "hunk": 0, "selection": "ours", "rationale": "r"},
            {"file": "a.py", "hunk": 1, "selection": "theirs", "rationale": "r"},
            {"file": "b.py", "hunk": 0, "selection": "ours-then-theirs", "rationale": "r"},
        ]
    )
    normalized = merge_assist.normalize_resolution(good, expected)
    check(
        "result: a complete candidate normalizes to per-file ordered selections",
        normalized == {"a.py": ["ours", "theirs"], "b.py": ["ours-then-theirs"]},
    )
    refusals = {
        "declined resolution": candidate([], status="cannot_safely_resolve"),
        "unsupported status": candidate([], status="maybe"),
        "no selections": candidate([]),
        "missing a hunk": candidate(good["resolutions"][:2]),
        "duplicate hunk": candidate(good["resolutions"] + [good["resolutions"][0]]),
        "unknown path": candidate(
            good["resolutions"]
            + [{"file": "c.py", "hunk": 0, "selection": "ours", "rationale": "r"}]
        ),
        "out-of-range hunk": candidate(
            [{"file": "a.py", "hunk": 7, "selection": "ours", "rationale": "r"}]
        ),
        "non-integer hunk": candidate(
            [{"file": "a.py", "hunk": True, "selection": "ours", "rationale": "r"}]
        ),
        "invented selection": candidate(
            [{"file": "a.py", "hunk": 0, "selection": "rewrite", "rationale": "r"}]
        ),
        "not an object": "resolved",
    }
    for label, value in refusals.items():
        check(
            "result: %s refuses the resolution" % label,
            raises(lambda value=value: merge_assist.normalize_resolution(value, expected)),
        )


# --------------------------------------------------------------------------- #
# End-to-end against a real git repository
# --------------------------------------------------------------------------- #
def git(repo, *args, check_call=True):
    return merge_assist.git(repo, *args, env_extra=IDENTITY, check=check_call)


def write(repo, path, text):
    target = Path(repo) / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def build_repo(
    directory,
    *,
    base_touches_workflow=False,
    base_renames_workflow=False,
    conflict_path="notes.md",
):
    """A real repository with one genuine both-modified conflict."""
    repo = Path(directory) / "src"
    repo.mkdir(parents=True)
    git(repo, "init", "--quiet")
    git(repo, "checkout", "--quiet", "-b", "main")
    write(repo, conflict_path, "alpha\ntwo\nomega\n")
    write(repo, "untouched.py", "print('same')\n")
    # The base branch also advances a file the pull request never touches, so
    # the mechanical merge legitimately stages more than the conflicted set.
    write(repo, "base_only.md", "original\n")
    if base_renames_workflow:
        write(repo, ".github/workflows/build.yml", "name: build\n")
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "--no-gpg-sign", "-m", "base")
    root = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "checkout", "--quiet", "-b", "contributor")
    write(repo, conflict_path, "alpha\ntwo-head\nomega\n")
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "--no-gpg-sign", "-m", "contributor change")
    head = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "checkout", "--quiet", "main")
    write(repo, conflict_path, "alpha\ntwo-base\nomega\n")
    write(repo, "base_only.md", "advanced by the base branch\n")
    if base_touches_workflow:
        write(repo, ".github/workflows/ci.yml", "name: ci\n")
    if base_renames_workflow:
        destination = repo / "docs" / "retired-build.yml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        (repo / ".github" / "workflows" / "build.yml").rename(destination)
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "--no-gpg-sign", "-m", "base change")
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    binding = {
        "owner": "owner",
        "repo": "demo",
        "number": 7,
        "card_issue": 42,
        "head_sha": head,
        "head_ref": "contributor",
        "base_ref": "main",
        "base_sha": base,
        "source_mode": core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        "source_repo": "contributor/demo",
        "author": "contributor",
        "author_id": 4242,
        "max_files": 5,
        "max_lines": 200,
    }
    return repo, binding, root


def test_end_to_end_resolution():
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory)
        result = merge_assist.prepare(binding, repo)
        check("e2e: the mechanical merge conflicts and is admitted", result["admitted"])
        entries = result["conflicts"]
        check(
            "e2e: exactly the conflicted file is enumerated as both-modified",
            [row["path"] for row in entries] == ["notes.md"]
            and entries[0]["status"] == "UU"
            and entries[0]["hunks"] == 1
            and entries[0]["binary"] is False,
        )
        check(
            "e2e: the conflict payload shows both sides and no other file",
            "two-head" in result["document"]
            and "two-base" in result["document"]
            and "untouched.py" not in result["document"],
        )
        candidate = {
            "status": "resolved",
            "reason": "both sides edit the same line; keep the contributor's",
            "resolutions": [
                {
                    "file": "notes.md",
                    "hunk": 0,
                    "selection": "ours",
                    "rationale": "the pull request's change is the intended one",
                }
            ],
        }
        selections = merge_assist.normalize_resolution(
            candidate, {row["path"]: row["hunks"] for row in entries}
        )
        paths = merge_assist.apply_resolution(repo, entries, selections)
        check("e2e: only the conflicted file is written", paths == ["notes.md"])
        check(
            "e2e: the resolved file is exactly the chosen parent lines",
            (repo / "notes.md").read_text(encoding="utf-8") == "alpha\ntwo-head\nomega\n",
        )
        resolution = merge_assist.commit_resolution(
            repo,
            binding,
            paths,
            binding["author_id"],
            {"name": "wheelhouse", "email": "wheelhouse@example.invalid"},
        )
        parents = git(repo, "rev-list", "--parents", "-n", "1", resolution).stdout.split()
        check(
            "e2e: the resolution is a merge commit with the contributor head first",
            parents[1] == binding["head_sha"] and parents[2] == binding["base_sha"],
        )
        message = git(repo, "log", "-1", "--format=%B", resolution).stdout
        check(
            "e2e: the contributor is co-authored, not replaced",
            "Co-authored-by: contributor <4242+contributor@users.noreply.github.com>"
            in message,
        )
        check(
            "e2e: the target commit uses neutral conflict-resolution copy",
            "Merge conflicts were resolved in:" in message
            and "notes.md" in message
            and all(
                term not in message.casefold()
                for term in ("wheelhouse", "assisted in-place", "card", "captain")
            ),
        )
        check(
            "e2e: the contributor's own commit is byte-identical",
            git(repo, "cat-file", "-p", binding["head_sha"]).stdout
            == git(repo, "cat-file", "-p", parents[1]).stdout,
        )
        check(
            "e2e: the resolution is a fast-forward from the contributor head",
            git(
                repo,
                "merge-base",
                "--is-ancestor",
                binding["head_sha"],
                resolution,
                check_call=False,
            ).returncode
            == 0,
        )
        check(
            "e2e: untouched files are not in the resolution's own change set",
            "untouched.py"
            not in git(
                repo, "diff", "--name-only", "%s..%s" % (binding["head_sha"], resolution)
            ).stdout,
        )
        check(
            "e2e: the working tree is clean after the resolution",
            git(repo, "status", "--porcelain").stdout.strip() == "",
        )
        check(
            "e2e: the base branch's own unrelated advance is carried through intact",
            (repo / "base_only.md").read_text(encoding="utf-8")
            == "advanced by the base branch\n",
        )


def test_end_to_end_escalations():
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory, base_touches_workflow=True)
        check(
            "e2e: a base advance that touches workflows escalates before merging",
            raises(lambda: merge_assist.prepare(binding, repo)),
        )
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory, base_renames_workflow=True)
        check(
            "e2e: a workflow rename out of the gated directory escalates before merging",
            raises(lambda: merge_assist.prepare(binding, repo)),
        )
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory, conflict_path="package-lock.json")
        result = merge_assist.prepare(binding, repo)
        check(
            "e2e: an excluded conflicted path escalates with no payload",
            not result["admitted"] and result["document"] == "",
        )
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(
            directory, conflict_path=".github/workflows/release.yml"
        )
        check(
            "e2e: a conflicted workflow file escalates before any enumeration",
            raises(lambda: merge_assist.prepare(binding, repo)),
        )
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory)
        binding = dict(binding, max_lines=1)
        result = merge_assist.prepare(binding, repo)
        check(
            "e2e: an over-cap conflict escalates with no payload",
            not result["admitted"] and result["document"] == "",
        )
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory)
        entries = merge_assist.prepare(binding, repo)["conflicts"]
        check(
            "e2e: a resolution that misses a hunk never reaches the tree",
            raises(
                lambda: merge_assist.apply_resolution(repo, entries, {"notes.md": []})
            ),
        )
        check(
            "e2e: the tree still holds the unresolved conflict after a refusal",
            merge_assist.contains_conflict_marker(
                (repo / "notes.md").read_text(encoding="utf-8")
            ),
        )
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory)
        entries = merge_assist.prepare(binding, repo)["conflicts"]
        saved_render = merge_assist.render_resolution

        def tampering_render(parsed, selections):
            # Stand in for any resolution path that reaches outside its hunks.
            (repo / "base_only.md").write_text("backdoor\n", encoding="utf-8")
            merge_assist.git(repo, "add", "--", "base_only.md", env_extra=IDENTITY)
            return saved_render(parsed, selections)

        merge_assist.render_resolution = tampering_render
        try:
            refused = raises(
                lambda: merge_assist.apply_resolution(
                    repo, entries, {"notes.md": ["ours"]}
                )
            )
        finally:
            merge_assist.render_resolution = saved_render
        check(
            "e2e: a resolution that modifies an already-merged file is refused",
            refused,
        )


def test_conflict_inventory_binding():
    with tempfile.TemporaryDirectory() as directory:
        repo, binding, _ = build_repo(directory)
        first = merge_assist.prepare(binding, repo)
        digest = merge_assist.conflict_digest(first["conflicts"])
        check(
            "binding: the inventory digest is stable",
            digest == merge_assist.conflict_digest(first["conflicts"]),
        )
        changed = [dict(first["conflicts"][0], path="other.md")]
        check(
            "binding: a changed inventory changes the digest",
            merge_assist.conflict_digest(changed) != digest,
        )
        check(
            "binding: a changed base changes the digest",
            merge_assist.conflict_digest(first["conflicts"], "a" * 40)
            != merge_assist.conflict_digest(first["conflicts"], "b" * 40),
        )
        conflict_file = repo / "notes.md"
        conflict_file.write_text(
            conflict_file.read_text(encoding="utf-8").replace("two-head", "new-head"),
            encoding="utf-8",
        )
        changed_content = merge_assist.enumerate_conflicts(repo)
        first_metadata = dict(first["conflicts"][0], content_sha256="")
        changed_metadata = dict(changed_content[0], content_sha256="")
        check(
            "binding: identical metadata with different hunk bytes changes the digest",
            first_metadata == changed_metadata
            and merge_assist.conflict_digest(changed_content) != digest,
        )


# --------------------------------------------------------------------------- #
# Source and kill-switch binding
# --------------------------------------------------------------------------- #
def test_bind_is_fork_only_and_kill_switch_is_exact():
    source_pr = {"state": "OPEN", "author": {"login": "contributor", "__typename": "User"}}
    pr = {
        "state": "open",
        "merged": False,
        "head": {
            "sha": "a" * 40,
            "ref": "topic",
            "repo": {"full_name": "contributor/demo"},
        },
        "base": {"sha": "b" * 40, "ref": "main"},
        "commits": core.PR_COMMITS_API_CAP - 1,
        "user": {"login": "contributor", "id": 7},
    }
    saved = {
        "policy": merge_assist.assisted_merge_policy,
        "graphql": merge_assist.core.gh_graphql_pr,
        "derive": merge_assist.core.derive_pushability,
        "rest": merge_assist.core.gh_rest,
        "label": merge_assist.core.target_label_state,
        "gate": merge_assist.apply_decision._workflow_merge_gate,
        "maintainers": merge_assist.core.maintainers,
    }
    writes = []
    mode = {"value": core.PUSHABILITY_PERSONAL_FORK_EDITABLE}
    label = {"value": False}
    source = {
        "head_sha": "a" * 40,
        "head_ref": "topic",
        "repository": "contributor/demo",
    }
    merge_assist.assisted_merge_policy = lambda repo: {
        "enabled": True,
        "max_files": 5,
        "max_lines": 200,
    }
    merge_assist.core.gh_graphql_pr = lambda *args: source_pr
    merge_assist.core.derive_pushability = lambda value: {
        "mode": mode["value"],
        "reason": "test",
        "source": dict(source),
    }
    merge_assist.core.target_label_state = lambda *args: label["value"]
    merge_assist.apply_decision._workflow_merge_gate = lambda *args: {"status": "clear"}
    merge_assist.core.maintainers = lambda: {"owner"}

    def fake_rest(path, method="GET", fields=None, **kwargs):
        if method != "GET":
            writes.append((path, method))
        if path.endswith("/pulls/7"):
            return pr
        if path.endswith("/repos/owner/demo"):
            return {"default_branch": "main"}
        raise AssertionError(path)

    merge_assist.core.gh_rest = fake_rest
    try:
        mode["value"] = core.PUSHABILITY_SAME_REPO
        source["repository"] = ""
        pr["head"]["repo"]["full_name"] = "owner/demo"
        same_repo_bound = merge_assist.bind("owner", "demo", 7, "a" * 40, 42)
        check(
            "bind: a same-repository branch reaches admission without a target write",
            same_repo_bound["source_mode"] == core.PUSHABILITY_SAME_REPO
            and same_repo_bound["source_repo"] == "owner/demo"
            and writes == [],
        )
        mode["value"] = core.PUSHABILITY_PERSONAL_FORK_EDITABLE
        source["repository"] = "contributor/demo"
        pr["head"]["repo"]["full_name"] = "contributor/demo"
        label["value"] = None
        check(
            "bind: an unreadable exact kill-switch label fails closed",
            raises(lambda: merge_assist.bind("owner", "demo", 7, "a" * 40, 42)),
        )
        label["value"] = True
        check(
            "bind: a present exact kill-switch label denies",
            raises(lambda: merge_assist.bind("owner", "demo", 7, "a" * 40, 42)),
        )
        label["value"] = False
        bound = merge_assist.bind("owner", "demo", 7, "a" * 40, 42)
        check(
            "bind: matching GraphQL and REST source tuples reach admission",
            bound["source_mode"] == core.PUSHABILITY_PERSONAL_FORK_EDITABLE
            and bound["source_repo"] == "contributor/demo"
            and bound["head_ref"] == "topic",
        )
        source["repository"] = "someone-else/demo"
        check(
            "bind: a mismatched source repository refuses before any mutation",
            raises(lambda: merge_assist.bind("owner", "demo", 7, "a" * 40, 42))
            and writes == [],
        )
        source["repository"] = "contributor/demo"
        source["head_ref"] = "other-topic"
        check(
            "bind: a mismatched source ref refuses before any mutation",
            raises(lambda: merge_assist.bind("owner", "demo", 7, "a" * 40, 42))
            and writes == [],
        )
        source["head_ref"] = "topic"
        pr["commits"] = core.PR_COMMITS_API_CAP
        try:
            merge_assist.bind("owner", "demo", 7, "a" * 40, 42)
            over_limit = ""
        except merge_assist.AssistError as error:
            over_limit = str(error)
        check(
            "bind: confirmation proof capacity includes the resolution commit",
            str(core.PR_COMMITS_API_CAP) in over_limit
            and "merge this pull request by hand" in over_limit
            and writes == [],
        )
    finally:
        merge_assist.assisted_merge_policy = saved["policy"]
        merge_assist.core.gh_graphql_pr = saved["graphql"]
        merge_assist.core.derive_pushability = saved["derive"]
        merge_assist.core.gh_rest = saved["rest"]
        merge_assist.core.target_label_state = saved["label"]
        merge_assist.apply_decision._workflow_merge_gate = saved["gate"]
        merge_assist.core.maintainers = saved["maintainers"]


# --------------------------------------------------------------------------- #
# Push confinement
# --------------------------------------------------------------------------- #
def test_push_confinement():
    fork = {
        "owner": "owner",
        "repo": "demo",
        "head_ref": "topic",
        "head_sha": "a" * 40,
        "source_mode": core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        "source_repo": "contributor/demo",
    }
    same = dict(
        fork,
        source_mode=core.PUSHABILITY_SAME_REPO,
        source_repo="owner/demo",
    )
    check(
        "push: a fork pushes to the contributor's own repository",
        merge_assist.push_remote_url(fork) == "https://github.com/contributor/demo.git",
    )
    check(
        "push: a same-repository branch pushes to the base repository",
        merge_assist.push_remote_url(same) == "https://github.com/owner/demo.git",
    )
    check(
        "push: a fork uses only the dedicated push secret",
        merge_assist.push_token_env_name(fork["source_mode"])
        == "ASSISTED_MERGE_PUSH_TOKEN",
    )
    check(
        "push: a same-repository branch uses only FLEET_TOKEN",
        merge_assist.push_token_env_name(same["source_mode"]) == "FLEET_TOKEN",
    )
    check(
        "push: no credential is authorized for an ineligible source",
        raises(lambda: merge_assist.push_token_env_name(core.PUSHABILITY_FORK_REJECT)),
    )
    check(
        "push: a hostile branch name never becomes a push target",
        raises(
            lambda: merge_assist.verified_push_plan(
                tempfile.gettempdir(),
                dict(fork, head_ref="--upload-pack=sh"),
                "b" * 40,
            )
        )
        and raises(
            lambda: merge_assist.verified_push_plan(
                tempfile.gettempdir(),
                dict(fork, head_ref="a/../../x"),
                "b" * 40,
            )
        ),
    )
    check(
        "push: a hostile source slug never becomes a remote",
        raises(
            lambda: merge_assist.push_remote_url(
                dict(fork, source_repo="evil.com/x --upload-pack=sh")
            )
        ),
    )
    calls = []

    def fake_git(repo, *args, env_extra=None, check=True):
        calls.append((args, dict(env_extra or {})))

        class Result:
            returncode = 0
            stdout = "c" * 40 + "\trefs/heads/topic\n"
            stderr = ""

        if args[0] == "ls-remote":
            return Result()
        raise AssertionError("push must not run after a moved source branch")

    saved = merge_assist.git
    merge_assist.git = fake_git
    try:
        moved = raises(
            lambda: merge_assist.verified_push_plan(
                tempfile.gettempdir(), fork, "b" * 40
            )
        )
    finally:
        merge_assist.git = saved
    check("push: a moved source branch refuses instead of overwriting work", moved)
    check(
        "push: the moved-head read receives no push credential",
        calls
        and calls[0][0][0] == "ls-remote"
        and "GIT_ASKPASS" not in calls[0][1]
        and "WHEELHOUSE_GIT_PASSWORD" not in calls[0][1],
    )

    calls.clear()

    def successful_git(repo, *args, env_extra=None, check=True):
        calls.append((args, dict(env_extra or {})))

        class Result:
            returncode = 0
            stdout = "a" * 40 + "\trefs/heads/topic\n"
            stderr = ""

        return Result()

    merge_assist.git = successful_git
    try:
        merge_assist.push_resolution(
            tempfile.gettempdir(),
            {
                "remote": "https://github.com/contributor/demo.git",
                "refspec": "b" * 40 + ":refs/heads/topic",
                "target_ref": "refs/heads/topic",
                "expected_head_sha": "a" * 40,
            },
            "secret-token",
            tempfile.gettempdir(),
        )
    finally:
        merge_assist.git = saved
    push_args, push_env = calls[1]
    check(
        "push: the credentialed boundary executes one plain non-force push",
        len(calls) == 2
        and calls[0][0][0] == "ls-remote"
        and not calls[0][1]
        and push_args
        == (
            "push",
            "https://github.com/contributor/demo.git",
            "b" * 40 + ":refs/heads/topic",
        )
        and not any(str(arg).startswith("--force") for arg in push_args),
    )
    check(
        "push: only the final push receives the credential",
        push_env.get("GIT_ASKPASS")
        and push_env.get("WHEELHOUSE_GIT_PASSWORD") == "secret-token"
        and not any("secret-token" in str(part) for part in push_args),
    )

    plan = {
        "remote": "https://github.com/contributor/demo.git",
        "refspec": "b" * 40 + ":refs/heads/topic",
        "target_ref": "refs/heads/topic",
        "expected_head_sha": "a" * 40,
    }
    race_results = {}
    for state, remote_head in {
        "exact": "a" * 40,
        "ancestor": "0" * 40,
        "ahead": "c" * 40,
        "unrelated": "d" * 40,
    }.items():
        def lease_server(repo, *args, env_extra=None, check=True, remote_head=remote_head):
            class Result:
                returncode = (
                    0
                    if args[0] == "ls-remote" or remote_head == "a" * 40
                    else 1
                )
                stdout = (
                    "a" * 40 + "\trefs/heads/topic\n"
                    if args[0] == "ls-remote"
                    else ""
                )
                stderr = "stale info" if returncode else ""

            return Result()

        merge_assist.git = lease_server
        try:
            race_results[state] = not raises(
                lambda: merge_assist.push_resolution(
                    tempfile.gettempdir(), plan, "secret-token", tempfile.gettempdir()
                )
            )
        finally:
            merge_assist.git = saved
    check(
        "push: a server-side non-fast-forward rejection fails the push",
        race_results == {
            "exact": True,
            "ancestor": False,
            "ahead": False,
            "unrelated": False,
        },
    )
    subcommand_git_calls = []
    api_calls = []

    def subcommand_git(repo, *args, env_extra=None, check=True):
        subcommand_git_calls.append((args, dict(env_extra or {})))

        class Result:
            returncode = 0
            stdout = (
                "a" * 40 + "\trefs/heads/topic\n"
                if args[0] == "ls-remote"
                else ""
            )
            stderr = ""

        return Result()

    saved_load = merge_assist._load
    saved_write = merge_assist._write
    saved_output = merge_assist._output
    saved_rest = merge_assist.core.gh_rest
    merge_assist.git = subcommand_git
    merge_assist._load = lambda path, default=None: {
        "status": "target-claimed",
        "binding": fork,
        "push_plan": plan,
    }
    merge_assist._write = lambda *args: None
    merge_assist._output = lambda *args: None
    merge_assist.core.gh_rest = lambda *args, **kwargs: api_calls.append(args)
    os.environ["WHEELHOUSE_ASSIST_PUSH_TOKEN"] = "secret-token"
    try:
        merge_assist.cmd_push(
            type(
                "Args",
                (),
                {
                    "state": "state.json",
                    "repo_dir": tempfile.gettempdir(),
                    "askpass_dir": tempfile.gettempdir(),
                    "out": "out.json",
                },
            )()
        )
    finally:
        os.environ.pop("WHEELHOUSE_ASSIST_PUSH_TOKEN", None)
        merge_assist.git = saved
        merge_assist._load = saved_load
        merge_assist._write = saved_write
        merge_assist._output = saved_output
        merge_assist.core.gh_rest = saved_rest
    check(
        "push: the subcommand re-reads anonymously, then makes one credentialed push",
        len(subcommand_git_calls) == 2
        and subcommand_git_calls[0][0][0] == "ls-remote"
        and subcommand_git_calls[0][1] == {}
        and subcommand_git_calls[1][0][0] == "push"
        and subcommand_git_calls[1][1].get("WHEELHOUSE_GIT_PASSWORD")
        == "secret-token"
        and api_calls == [],
    )

    malformed_plans = [
        dict(plan, expected_head_sha=""),
        dict(plan, target_ref="refs/heads/other"),
        dict(plan, expected_head_sha="--force"),
    ]
    check(
        "push: no push can run without an exact old SHA and matching ref",
        all(
            raises(
                lambda candidate=candidate: merge_assist.push_resolution(
                    tempfile.gettempdir(),
                    candidate,
                    "secret-token",
                    tempfile.gettempdir(),
                )
            )
            for candidate in malformed_plans
        ),
    )

    subprocess_calls = []

    def fake_run(command, **kwargs):
        subprocess_calls.append((command, kwargs))

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    saved_run = merge_assist.subprocess.run
    merge_assist.subprocess.run = fake_run
    try:
        merge_assist.git(tempfile.gettempdir(), "status")
    finally:
        merge_assist.subprocess.run = saved_run
    command, options = subprocess_calls[0]
    check(
        "git: every command disables hooks and credential helpers",
        "core.hooksPath=/dev/null" in command
        and "credential.helper=" in command
        and options["env"]["GIT_TERMINAL_PROMPT"] == "0",
    )

    failed_state = {
        "status": "push-failed",
        "reason": "push transport failed",
        "binding": fork,
        "resolution_head_sha": "b" * 40,
        "push_plan": plan,
    }
    observed_states = []
    observed_envs = []
    saved_load = merge_assist._load
    saved_write = merge_assist._write
    saved_output = merge_assist._output
    saved_git = merge_assist.git
    merge_assist._load = lambda path, default=None: failed_state
    merge_assist._write = lambda path, value: observed_states.append(value)
    merge_assist._output = lambda *args: None
    args = type("Args", (), {"state": "state", "repo_dir": "repo", "out": "out"})()
    try:
        for remote_head, returncode in (("a" * 40, 0), ("b" * 40, 0), ("", 1)):
            def observe_git(repo, *git_args, env_extra=None, check=True, remote_head=remote_head, returncode=returncode):
                observed_envs.append(dict(env_extra or {}))

                class Result:
                    pass

                result = Result()
                result.returncode = returncode
                result.stdout = remote_head + "\trefs/heads/topic\n" if remote_head else ""
                result.stderr = "unavailable" if returncode else ""
                return result

            merge_assist.git = observe_git
            merge_assist.cmd_observe_push(args)
    finally:
        merge_assist._load = saved_load
        merge_assist._write = saved_write
        merge_assist._output = saved_output
        merge_assist.git = saved_git
    check(
        "push: a failed push is classified only by an independent anonymous read",
        [(state["status"], state.get("push_outcome")) for state in observed_states]
        == [
            ("escalated", merge_assist.PUSH_OUTCOME_NOT_PUSHED),
            ("pushed", None),
            ("escalated", merge_assist.PUSH_OUTCOME_UNCERTAIN),
        ]
        and observed_envs == [{}, {}, {}],
    )


def test_confirmation_denial_transaction():
    events = []
    binding = {
        "owner": "owner",
        "repo": "demo",
        "number": 7,
        "head_sha": "a" * 40,
        "source_mode": core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
    }

    def fake_rest(path, method="GET", fields=None, **kwargs):
        if path.endswith("/pulls/7"):
            events.append("read-pr")
            return {"head": {"sha": "a" * 40}}
        if path.endswith("/issues/7/labels") and method == "POST":
            check(
                "confirmation: label request uses GitHub's array field",
                fields == {"labels[]": core.AWAITING_CAPTAIN_CONFIRM_LABEL},
            )
            events.append("apply-label")
            return []
        if path.endswith("/labels") and method == "POST":
            events.append("create-label")
            return {}
        raise AssertionError((path, method))

    saved_rest = merge_assist.core.gh_rest
    saved_label_state = merge_assist.core.target_label_state
    merge_assist.core.gh_rest = fake_rest

    def confirmation_label_state(owner, repo, number, label):
        if label == core.NO_ASSISTED_MERGE_LABEL:
            events.append("verify-kill-switch")
            return False
        events.append("verify-label")
        return True

    merge_assist.core.target_label_state = confirmation_label_state
    try:
        verified = merge_assist.apply_confirmation_denial(binding)
    finally:
        merge_assist.core.gh_rest = saved_rest
        merge_assist.core.target_label_state = saved_label_state
    check("confirmation: label is verified", verified["label"] is True)
    check(
        "confirmation: kill switch is the final read before label application",
        events.index("read-pr") < events.index("verify-kill-switch")
        < events.index("apply-label") < events.index("verify-label"),
    )

    calls = []
    saved_apply = merge_assist.apply_confirmation_denial
    saved_plan = merge_assist.verified_push_plan
    saved_load = merge_assist._load
    saved_fail = merge_assist._fail
    saved_write = merge_assist._write
    saved_output = merge_assist._output
    saved_label_state = merge_assist.core.target_label_state
    saved_rollback = merge_assist.rollback_confirmation_denial
    kill_switch = {"value": False}
    merge_assist._load = lambda path, default=None: {"status": "resolved", "binding": binding, "resolution_head_sha": "b" * 40}
    merge_assist._fail = lambda binding, error, path: calls.append(("fail", str(error)))
    merge_assist._write = lambda path, value: calls.append(("write", value["status"]))
    merge_assist._output = lambda name, value: None
    merge_assist.core.target_label_state = lambda *values: calls.append(("kill-switch", "")) or kill_switch["value"]
    args = type("Args", (), {
        "state": "s", "repo_dir": "r", "intent_out": "intent", "out": "o",
        "fork_credential_present": True,
    })()
    try:
        merge_assist.verified_push_plan = lambda *values: calls.append(("read-ref", "")) or {
            "remote": "https://github.com/contributor/demo.git",
            "refspec": "b" * 40 + ":refs/heads/topic",
            "target_ref": "refs/heads/topic",
            "expected_head_sha": "a" * 40,
        }
        def apply_at_acting_boundary(value):
            calls.append(("read-pr", ""))
            no_assist = merge_assist.core.target_label_state(
                value["owner"], value["repo"], value["number"], core.NO_ASSISTED_MERGE_LABEL
            )
            if no_assist is None:
                raise merge_assist.PreMutationAssistError(
                    "the target's assisted-merge kill switch could not be verified"
                )
            if no_assist:
                raise merge_assist.PreMutationAssistError(
                    "the target carries the %s label" % core.NO_ASSISTED_MERGE_LABEL
                )
            calls.append(("label", ""))

        merge_assist.apply_confirmation_denial = apply_at_acting_boundary
        merge_assist.cmd_claim_target(args)
        check(
            "confirmation: claim intent precedes the acting-boundary kill-switch read",
            [name for name, _ in calls]
            == ["read-ref", "write", "read-pr", "kill-switch", "label", "write"],
        )
        calls.clear()
        args.fork_credential_present = False
        merge_assist.cmd_claim_target(args)
        check(
            "confirmation: a missing credential performs no target mutation",
            [name for name, _ in calls] == ["fail"]
            and "ASSISTED_MERGE_PUSH_TOKEN" in calls[0][1],
        )
        args.fork_credential_present = True
        for kill_state in (True, None):
            calls.clear()
            kill_switch["value"] = False
            failed_bindings = []

            def write_then_change_kill_switch(path, value, state=kill_state):
                calls.append(("write", value["status"]))
                if value["status"] == "claim-intent":
                    kill_switch["value"] = state

            merge_assist._write = write_then_change_kill_switch
            merge_assist._fail = lambda failed_binding, error, path: (
                failed_bindings.append(failed_binding),
                calls.append(("fail", str(error))),
            )
            merge_assist.cmd_claim_target(args)
            check(
                "confirmation: a kill-switch state %r applied after intent prevents every target mutation"
                % kill_state,
                [name for name, _ in calls]
                == ["read-ref", "write", "read-pr", "kill-switch", "fail"]
                and failed_bindings[0]["confirmation_label_may_be_present"] is False
                and "no target mutation was attempted" in calls[-1][1],
            )
        kill_switch["value"] = False
        merge_assist._write = lambda path, value: calls.append(("write", value["status"]))
        merge_assist._fail = lambda failed_binding, error, path: calls.append(
            ("fail", str(error))
        )
        for failure in ("label could not be set", "label could not be verified"):
            calls.clear()
            merge_assist.apply_confirmation_denial = lambda value, failure=failure: (_ for _ in ()).throw(merge_assist.AssistError(failure))
            merge_assist.cmd_claim_target(args)
            check("confirmation: %s prevents push plan admission" % failure, [name for name, _ in calls][-1:] == ["fail"])

        persisted = {}
        mutations = []

        def fail_intent_write(path, value):
            if path == "intent":
                raise OSError("disk unavailable")
            persisted[path] = value

        merge_assist._write = fail_intent_write
        merge_assist._fail = lambda failed_binding, error, path: merge_assist._write(
            path,
            {
                "status": "escalated",
                "reason": str(error),
                "binding": failed_binding,
            },
        )
        merge_assist.apply_confirmation_denial = lambda value: mutations.append("label")
        merge_assist.cmd_claim_target(args)
        check(
            "confirmation: a failed claim-intent write leaves the target provably unchanged",
            mutations == []
            and persisted["o"]["status"] == "escalated"
            and persisted["o"]["binding"]["confirmation_label_may_be_present"] is False
            and "target was unchanged" in persisted["o"]["reason"],
        )

        persisted.clear()
        mutations.clear()

        def fail_post_label_writes(path, value):
            if path == "o":
                raise OSError("state storage unavailable")
            persisted[path] = value

        merge_assist._write = fail_post_label_writes
        merge_assist.apply_confirmation_denial = lambda value: mutations.append("label")
        merge_assist.rollback_confirmation_denial = lambda value: False
        merge_assist.cmd_claim_target(args)
        selected = persisted["intent"]
        check(
            "confirmation: claim intent is the durable uncertain floor after label mutation",
            mutations == ["label"]
            and selected["status"] == "claim-intent"
            and selected["push_outcome"] == merge_assist.PUSH_OUTCOME_UNCERTAIN
            and selected["binding"]["confirmation_label_may_be_present"] is True,
        )

        persisted.clear()
        mutations.clear()
        merge_assist._write = lambda path, value: persisted.__setitem__(path, value)
        merge_assist.apply_confirmation_denial = lambda value: mutations.append("label")
        merge_assist.cmd_claim_target(args)
        check(
            "confirmation: ordinary claim success supersedes the durable intent",
            mutations == ["label"]
            and persisted["intent"]["status"] == "claim-intent"
            and persisted["o"]["status"] == "target-claimed",
        )

        calls.clear()
        merge_assist._write = lambda path, value: calls.append(("write", value["status"]))
        merge_assist._fail = lambda failed_binding, error, path: calls.append(("fail", str(error)))
        args.fork_credential_present = True
        args.same_repo_credential_present = True
        same_binding = dict(binding, source_mode=core.PUSHABILITY_SAME_REPO)
        merge_assist._load = lambda path, default=None: {"status": "resolved", "binding": same_binding, "resolution_head_sha": "b" * 40}
        merge_assist.cmd_claim_target(args)
        check(
            "confirmation: a same-repository source reaches the target claim",
            [name for name, _ in calls] == ["read-ref", "write", "write"]
            and calls[-1][1] == "target-claimed"
            and mutations[-1:] == ["label"],
        )
    finally:
        merge_assist.apply_confirmation_denial = saved_apply
        merge_assist.verified_push_plan = saved_plan
        merge_assist._load = saved_load
        merge_assist._fail = saved_fail
        merge_assist._write = saved_write
        merge_assist._output = saved_output
        merge_assist.core.target_label_state = saved_label_state
        merge_assist.rollback_confirmation_denial = saved_rollback


# --------------------------------------------------------------------------- #
# The durable, non-material card record
# --------------------------------------------------------------------------- #
def test_claim_intent_supersedes_pre_mutation_state_for_outcome_selection():
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        merge_assist._write(
            directory / "assist-resolved.json",
            {"status": "resolved"},
        )
        intent = {
            "status": "claim-intent",
            "push_outcome": merge_assist.PUSH_OUTCOME_UNCERTAIN,
            "binding": {"confirmation_label_may_be_present": True},
        }
        merge_assist._write(directory / "assist-claim-intent.json", intent)
        selected = merge_assist.select_outcome_state(directory)
        check(
            "record: durable claim intent supersedes the pre-mutation resolution",
            selected == directory / "assist-claim-intent.json"
            and merge_assist._load(selected) == intent,
        )


def pushed_record():
    return merge_assist.build_record(
        source_mode=core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        original_head_sha="a" * 40,
        base_sha="b" * 40,
        phase=merge_assist.PHASE_AWAITING_CONFIRMATION,
        conflicted_paths=["notes.md"],
        resolution_head_sha="c" * 40,
        digest="d" * 64,
    )


def test_record_reports_deferred_card_write():
    state = {
        "status": "pushed",
        "binding": {
            "source_mode": core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "card_issue": 12,
        },
        "conflicted_paths": ["notes.md"],
        "resolution_head_sha": "c" * 40,
        "resolution_digest": "d" * 64,
    }
    outputs = {}
    saved_load = merge_assist._load
    saved_record = merge_assist.render_card.record_merge_assist
    saved_output = merge_assist._output
    merge_assist._load = lambda path, default=None: state
    captured = []
    merge_assist.render_card.record_merge_assist = (
        lambda issue, record: captured.append(record) or "deferred"
    )
    merge_assist._output = lambda name, value: outputs.__setitem__(name, value)
    try:
        merge_assist.cmd_record(type("Args", (), {"state": "state.json"})())
        uncertain_state = {
            "status": "target-claimed",
            "reason": "push state persistence failed",
            "binding": dict(
                state["binding"], confirmation_label_may_be_present=True
            ),
            "conflicts": [{"path": "notes.md"}],
        }
        merge_assist._load = lambda path, default=None: uncertain_state
        merge_assist.cmd_record(type("Args", (), {"state": "state.json"})())
    finally:
        merge_assist._load = saved_load
        merge_assist.render_card.record_merge_assist = saved_record
        merge_assist._output = saved_output
    check(
        "record: a deferred secondary card write is reported honestly",
        outputs == {"status": "record-deferred", "card_outcome": "deferred"},
    )
    check(
        "record: a target-claimed fallback records an uncertain push",
        captured[1]["push_outcome"] == merge_assist.PUSH_OUTCOME_UNCERTAIN,
    )


def test_card_record():
    record = pushed_record()
    check(
        "record: a pushed record round-trips through the strict reader",
        render_card.normalize_merge_assist(record) == record,
    )
    escalated = merge_assist.build_record(
        source_mode=core.PUSHABILITY_SAME_REPO,
        original_head_sha="a" * 40,
        base_sha="",
        phase=merge_assist.PHASE_ESCALATED,
        escalation_reason="conflicted path is in the unconditional exclusion set",
    )
    check(
        "record: an escalated record round-trips and keeps its reason",
        render_card.normalize_merge_assist(escalated) == escalated,
    )
    check(
        "record: a pushed record without a resolution head refuses",
        raises(
            lambda: merge_assist.build_record(
                source_mode=core.PUSHABILITY_SAME_REPO,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                phase=merge_assist.PHASE_AWAITING_CONFIRMATION,
            )
        ),
    )
    check(
        "record: an ineligible source can never carry a pushed record",
        raises(
            lambda: merge_assist.build_record(
                source_mode=core.PUSHABILITY_FORK_REJECT,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                phase=merge_assist.PHASE_AWAITING_CONFIRMATION,
                resolution_head_sha="c" * 40,
            )
        ),
    )
    unverified = merge_assist.build_record(
        source_mode=core.PUSHABILITY_UNVERIFIED,
        original_head_sha="a" * 40,
        base_sha="",
        phase=merge_assist.PHASE_ESCALATED,
        escalation_reason="the source branch policy could not be verified",
    )
    check(
        "record: an escalation may honestly record an unverified source",
        render_card.normalize_merge_assist(unverified) == unverified,
    )
    check(
        "record: an unknown source mode is never recorded",
        raises(
            lambda: merge_assist.build_record(
                source_mode="something-else",
                original_head_sha="a" * 40,
                base_sha="",
                phase=merge_assist.PHASE_ESCALATED,
                escalation_reason="x",
            )
        ),
    )
    malformed = {
        "wrong version": dict(record, version=1),
        "wrong mode": dict(record, mode="landing-branch"),
        "unknown phase": dict(record, phase="merging"),
        "unknown source mode": dict(record, source_mode="anything"),
        "short sha": dict(record, resolution_head_sha="c" * 7),
        "non-hex digest": dict(record, resolution_digest="z" * 64),
        "oversized path list": dict(record, conflicted_paths=["p"] * 21),
        "blank path": dict(record, conflicted_paths=[" "]),
        "escalation without a reason": dict(
            record, phase=merge_assist.PHASE_ESCALATED, escalation_reason=""
        ),
        "unknown push outcome": dict(record, push_outcome="probably-pushed"),
        "awaiting with uncertain push": dict(
            record, push_outcome=merge_assist.PUSH_OUTCOME_UNCERTAIN
        ),
        "not an object": [record],
    }
    for label, value in malformed.items():
        check(
            "record: %s reads as untrusted" % label,
            render_card.normalize_merge_assist(value) is None,
        )
    check(
        "record: both adjacent heads keep the record bound",
        render_card.merge_assist_bound_heads(record) == frozenset({"a" * 40, "c" * 40}),
    )
    state = {"merge_assist": record, "head_sha": "c" * 40}
    check(
        "record: the resolution head matches",
        render_card.merge_assist_status(state, "c" * 40)[0] == "matching",
    )
    check(
        "record: the decided head still matches",
        render_card.merge_assist_status(state, "a" * 40)[0] == "matching",
    )
    check(
        "record: a genuine contributor push makes it stale",
        render_card.merge_assist_status(state, "e" * 40)[0] == "stale",
    )
    check(
        "record: malformed same-head state fails closed",
        render_card.merge_assist_status(
            {"merge_assist": {"version": 9}}, "c" * 40
        )[0]
        == "malformed",
    )
    check(
        "record: an absent record is absent",
        render_card.merge_assist_status({}, "c" * 40)[0] == "absent",
    )
    carried = render_card.carry_merge_assist({"head_sha": "c" * 40}, state)
    check(
        "record: a still-binding record survives a refresh",
        carried.get("merge_assist") == record,
    )
    dropped = render_card.carry_merge_assist({"head_sha": "e" * 40}, state)
    check(
        "record: a new contributor head clears it on refresh",
        "merge_assist" not in dropped,
    )
    check(
        "record: it is never a material refresh field",
        "merge_assist" not in render_card.MATERIAL_FIELDS,
    )


def test_card_section_and_body():
    record = pushed_record()
    body = "\n".join(
        [
            "## Decision needed",
            "",
            render_card.DECISION_START,
            "### Your decision",
            render_card.DECISION_END,
            "",
            '<!-- wheelhouse-state: {"head_sha": "%s", "kind": "pr-review"} -->' % ("c" * 40),
        ]
    )
    pre_refresh = render_card.body_with_merge_assist(
        body.replace('"%s"' % ("c" * 40), '"%s"' % ("a" * 40)), record
    )
    check(
        "section: pre-refresh projection is visible but inert",
        "### Assisted merge" in pre_refresh
        and "will become confirmable after the next refresh" in pre_refresh
        and "tick `Merge it` again" not in pre_refresh,
    )
    updated = render_card.body_with_merge_assist(body, record)
    check(
        "section: the refreshed record explains the resolution and next step",
        "### Assisted merge" in updated
        and "exact-old-SHA safeguard" in updated
        and "tick `Merge it` again" in updated
        and record["resolution_head_sha"] in updated,
    )
    check(
        "section: it is inserted before the decision section",
        updated.index("### Assisted merge") < updated.index(render_card.DECISION_START),
    )
    check(
        "section: the record is persisted in the hidden state block",
        (core.parse_state_block(updated) or {}).get("merge_assist") == record,
    )
    check(
        "section: re-applying the same record is idempotent",
        render_card.body_with_merge_assist(updated, record) == updated,
    )
    other = dict(record, original_head_sha="9" * 40, resolution_head_sha="8" * 40)
    check(
        "section: a record for another head never rewrites the card",
        render_card.body_with_merge_assist(body, other) == body,
    )
    check(
        "section: a malformed record never rewrites the card",
        render_card.body_with_merge_assist(body, {"version": 1}) == body,
    )
    escalated = merge_assist.build_record(
        source_mode=core.PUSHABILITY_SAME_REPO,
        original_head_sha="c" * 40,
        base_sha="",
        phase=merge_assist.PHASE_ESCALATED,
        escalation_reason="the resolver declined",
        conflicted_paths=["notes.md"],
    )
    escalation_body = render_card.body_with_merge_assist(body, escalated)
    check(
        "section: a pre-label escalation says the target is unchanged",
        "before changing the target" in escalation_body
        and "No resolution was pushed" in escalation_body
        and "contributor was not contacted" in escalation_body
        and "the resolver declined" in escalation_body,
    )
    post_label = merge_assist.build_record(
        source_mode=core.PUSHABILITY_SAME_REPO,
        original_head_sha="c" * 40,
        base_sha="",
        phase=merge_assist.PHASE_ESCALATED,
        escalation_reason="the push was refused",
        conflicted_paths=["notes.md"],
        confirmation_label_may_be_present=True,
    )
    post_label_body = render_card.body_with_merge_assist(body, post_label)
    check(
        "section: a proven-not-pushed escalation reports possible label state",
        "No resolution was pushed" in post_label_body
        and core.AWAITING_CAPTAIN_CONFIRM_LABEL in post_label_body
        and "remove it" in post_label_body,
    )
    uncertain = merge_assist.build_record(
        source_mode=core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        original_head_sha="c" * 40,
        base_sha="",
        phase=merge_assist.PHASE_ESCALATED,
        escalation_reason="push state persistence failed",
        conflicted_paths=["notes.md"],
        confirmation_label_may_be_present=True,
        push_outcome=merge_assist.PUSH_OUTCOME_UNCERTAIN,
    )
    uncertain_body = render_card.body_with_merge_assist(body, uncertain)
    check(
        "section: an uncertain push directs inspection without a false claim",
        "may or may not have been pushed" in uncertain_body
        and "Inspect the pull request's current head" in uncertain_body
        and "No resolution was pushed" not in uncertain_body,
    )
    proven_pushed = merge_assist.build_record(
        source_mode=core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        original_head_sha="c" * 40,
        base_sha="",
        phase=merge_assist.PHASE_ESCALATED,
        escalation_reason="post-push recording failed",
        conflicted_paths=["notes.md"],
        confirmation_label_may_be_present=True,
        push_outcome=merge_assist.PUSH_OUTCOME_PUSHED,
    )
    proven_pushed_body = render_card.body_with_merge_assist(body, proven_pushed)
    check(
        "section: a proven push is reported without uncertainty",
        "The resolution was pushed" in proven_pushed_body
        and "may or may not have been pushed" not in proven_pushed_body,
    )
    check(
        "section: an escalation never offers a confirmation instruction",
        "tick `Merge it` again" not in escalation_body,
    )


def test_render_binds_the_record_to_the_card_head():
    item = {
        "repo": "demo",
        "number": 7,
        "kind": "pr-review",
        "title": "Add a thing",
        "author": "contributor",
        "head_sha": "c" * 40,
        "bucket": "merge-ready",
        "comp": "pass",
        "tests": "green",
        "url": "https://example.invalid/pr/7",
        "merge_assist": pushed_record(),
    }
    card = render_card.render(item)
    check("render: a bound record renders its section", "### Assisted merge" in card["body"])
    check(
        "render: a bound record is persisted as non-material state",
        (core.parse_state_block(card["body"]) or {}).get("merge_assist")
        == item["merge_assist"],
    )
    moved = render_card.render(dict(item, head_sha="e" * 40))
    check(
        "render: a record for a superseded head is dropped entirely",
        "### Assisted merge" not in moved["body"]
        and "merge_assist" not in (core.parse_state_block(moved["body"]) or {}),
    )
    issue = render_card.render(
        dict(item, kind="issue-triage", bucket="issue-triage")
    )
    check(
        "render: the record never appears on a non-PR card",
        "### Assisted merge" not in issue["body"],
    )


# --------------------------------------------------------------------------- #
# Routing: a conflicted captain merge enters the assisted path, or does not
# --------------------------------------------------------------------------- #
def test_do_merge_routing():
    calls = {"merge": 0}
    source = {"slug": "owner/demo"}

    def fake_rest(path, method="GET", fields=None, **kwargs):
        if method == "PUT":
            calls["merge"] += 1
            raise RuntimeError("HTTP 405: Pull Request is not mergeable (merge conflict)")
        if re.search(r"/pulls/\d+/files", path):
            return []
        if re.search(r"/pulls/\d+/commits", path):
            return []
        if re.search(r"/pulls/\d+$", path):
            return {
                "state": "open",
                "merged": False,
                "head": {"sha": "head", "repo": {"full_name": source["slug"]}},
                "base": {"sha": "base"},
                "changed_files": 0,
                "commits": 0,
                "user": {"login": "contributor", "id": 5},
            }
        return {}

    saved_rest = apply_decision.core.gh_rest
    saved_enabled = apply_decision._assisted_merge_enabled
    saved_label_state = apply_decision.core.target_label_state
    saved_graphql = apply_decision.core.gh_graphql_pr
    saved_derive = apply_decision.core.derive_pushability
    apply_decision.core.gh_rest = fake_rest
    apply_decision.core.target_label_state = lambda *args: False
    apply_decision.core.gh_graphql_pr = lambda *args: {}
    apply_decision.core.derive_pushability = lambda value: {
        "mode": core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        "source": {"head_sha": "head"},
    }
    try:
        apply_decision._assisted_merge_enabled = lambda repo: False
        message, terminal, assist = apply_decision.do_merge(
            "owner", "demo", 1, "head", return_assist=True
        )
        check(
            "routing: with assist disabled the captain-facing manual copy is kept",
            terminal == "none"
            and assist is False
            and "captain must resolve" in message,
        )
        apply_decision._assisted_merge_enabled = lambda repo: True
        message, terminal, assist = apply_decision.do_merge(
            "owner", "demo", 1, "head", return_assist=True
        )
        check(
            "routing: a same-repository conflict starts the assisted path",
            terminal == "none" and assist is True,
        )
        source["slug"] = "contributor/demo"
        message, terminal, assist = apply_decision.do_merge(
            "owner", "demo", 1, "head", return_assist=True
        )
        check(
            "routing: an editable fork conflict starts the assisted path",
            terminal == "none" and assist is True,
        )
        check(
            "routing: the captain is told their commits are not rewritten",
            "not rewritten" in message and "second decision" in message,
        )
        check(
            "routing: the card stays actionable, never blocked",
            terminal == "none",
        )
    finally:
        apply_decision.core.gh_rest = saved_rest
        apply_decision.core.target_label_state = saved_label_state
        apply_decision.core.gh_graphql_pr = saved_graphql
        apply_decision.core.derive_pushability = saved_derive
        apply_decision._assisted_merge_enabled = saved_enabled


def test_confirmation_routing_and_auto_merge_holds():
    check(
        "confirmation: every draft remains outside the worklist",
        core.classify(
            True,
            "pass",
            "green",
            True,
            False,
            labels=[{"name": core.AWAITING_CAPTAIN_CONFIRM_LABEL}],
        )
        == "draft",
    )
    saved_rest = core.gh_rest
    try:
        core.gh_rest = lambda path: {"name": core.AWAITING_CAPTAIN_CONFIRM_LABEL}
        present = core.target_label_state(
            "owner", "demo", 7, core.AWAITING_CAPTAIN_CONFIRM_LABEL
        )
        core.gh_rest = lambda path: (_ for _ in ()).throw(
            RuntimeError("HTTP 404: Not Found")
        )
        absent = core.target_label_state(
            "owner", "demo", 7, core.AWAITING_CAPTAIN_CONFIRM_LABEL
        )
        core.gh_rest = lambda path: (_ for _ in ()).throw(
            RuntimeError("HTTP 503: unavailable")
        )
        unreadable = core.target_label_state(
            "owner", "demo", 7, core.AWAITING_CAPTAIN_CONFIRM_LABEL
        )
    finally:
        core.gh_rest = saved_rest
    check(
        "confirmation: exact label reads distinguish absence from outage",
        present is True and absent is False and unreadable is None,
    )

    record = pushed_record()
    held, reason = auto_merge._assisted_confirmation_hold(
        {"merge_assist": record}, record["resolution_head_sha"]
    )
    malformed, _ = auto_merge._assisted_confirmation_hold(
        {"merge_assist": {"version": 2}}, record["resolution_head_sha"]
    )
    check(
        "confirmation: preclaim denies current and malformed records",
        held and "confirmation" in reason and malformed,
    )
    for pr, expected in (
        ({"labels": [{"name": core.AWAITING_CAPTAIN_CONFIRM_LABEL}], "labels_truncated": False}, True),
        ({"labels": [], "labels_truncated": True}, True),
        ({"labels": []}, True),
        ({"labels": [], "labels_truncated": False}, False),
    ):
        label_held, _ = auto_merge._bulk_confirmation_label_hold(pr)
        check("confirmation: preclaim label completeness is fail-closed", label_held is expected)

    saved_label_state = auto_merge.core.target_label_state
    auto_merge.core.target_label_state = lambda *args: True
    try:
        guard = auto_merge.final_auto_merge_guard(
            {"issue": 1}, "owner", "demo", 7, "card-token"
        )
        allowed, reason = guard({"labels": []})
        check("confirmation: G7 denies target label", not allowed and "confirmation" in reason)
        auto_merge.core.target_label_state = lambda *args: None
        allowed, reason = guard({"labels": []})
        check("confirmation: G7 denies unreadable label state", not allowed and "re-read" in reason)
    finally:
        auto_merge.core.target_label_state = saved_label_state

    head = record["resolution_head_sha"]
    calls = []
    cleanup_fails = {"value": False}
    proof_mode = {"value": "valid"}
    pr_reads = {"count": 0}

    def fake_rest(path, method="GET", fields=None, **kwargs):
        if method == "PUT":
            calls.append("merge")
            return {"sha": "m" * 40}
        if method == "DELETE":
            calls.append("remove-label")
            if cleanup_fails["value"]:
                raise json.JSONDecodeError("cleanup response malformed", "{", 1)
            return None
        if "/pulls/7/commits" in path:
            if proof_mode["value"] == "unreadable":
                raise RuntimeError("commit list unavailable")
            return [[{"sha": record["original_head_sha"]}, {"sha": head}]]
        if "/commits/%s" % head in path:
            if kwargs.get("paginate"):
                return [{"files": []}]
            parents = [
                {"sha": record["original_head_sha"]},
                {"sha": record["base_sha"]},
            ]
            if proof_mode["value"] == "not-resolution":
                parents = parents[:1]
            return {"sha": head, "parents": parents}
        if "/commits/%s" % record["original_head_sha"] in path:
            return [{"files": []}]
        if "/compare/%s..." % record["base_sha"] in path:
            if proof_mode["value"] == "base-moved-final" and path.endswith("..." + "e" * 40):
                return {
                    "status": "diverged",
                    "merge_base_commit": {"sha": "f" * 40},
                }
            return {
                "status": "identical",
                "merge_base_commit": {"sha": record["base_sha"]},
            }
        if "/files" in path or "/commits" in path:
            return []
        if path.endswith("/pulls/7"):
            pr_reads["count"] += 1
            base_sha = (
                "e" * 40
                if proof_mode["value"] == "base-moved-final" and pr_reads["count"] > 1
                else record["base_sha"]
            )
            return {
                "state": "open",
                "merged": False,
                "labels": [],
                "head": {"sha": head, "repo": {"full_name": "owner/demo"}},
                "base": {"sha": base_sha},
                "changed_files": 0,
                "commits": 2,
                "user": {"login": "owner", "id": 1},
            }
        return {}

    saved_rest = apply_decision.core.gh_rest
    saved_label_state = apply_decision.core.target_label_state
    apply_decision.core.gh_rest = fake_rest
    apply_decision.core.target_label_state = lambda *args: True
    try:
        for card_record in (None, {"version": 2}, record):
            calls.clear()
            message, terminal = apply_decision.do_merge(
                "owner",
                "demo",
                7,
                record["original_head_sha"],
                merge_assist_record=card_record,
            )
            check(
                "confirmation: a recordless pre-refresh click stays non-terminal",
                terminal == "none"
                and "next refresh" in message
                and "merge" not in calls,
            )
        calls.clear()
        _, terminal = apply_decision.do_merge(
            "owner", "demo", 7, head, merge_assist_record=None
        )
        check(
            "confirmation: live proof permits merge without a card record",
            terminal == "resolved" and calls == ["merge", "remove-label"],
        )
        check(
            "confirmation: authoritative label proof overrides an omitted embedded label",
            "remove-label" in calls,
        )
        for mode in ("not-resolution", "unreadable"):
            calls.clear()
            proof_mode["value"] = mode
            message, terminal = apply_decision.do_merge(
                "owner", "demo", 7, head, merge_assist_record=None
            )
            check(
                "confirmation: %s live proof denies non-terminally" % mode,
                terminal == "none"
                and "appears stale" in message
                and "merge" not in calls,
            )
        calls.clear()
        proof_mode["value"] = "base-moved-final"
        pr_reads["count"] = 0
        message, terminal = apply_decision.do_merge(
            "owner", "demo", 7, head, merge_assist_record=None
        )
        check(
            "confirmation: final live-base ancestry proof denies a raced base",
            terminal == "none"
            and "appears stale" in message
            and "merge" not in calls,
        )
        calls.clear()
        proof_mode["value"] = "valid"
        pr_reads["count"] = 0
        apply_decision.core.target_label_state = lambda *args: None
        message, terminal = apply_decision.do_merge(
            "owner", "demo", 7, head, merge_assist_record=None
        )
        check(
            "confirmation: unreadable authoritative label state denies every merge",
            terminal == "error" and "could not verify" in message and "merge" not in calls,
        )
        label_reads = {"count": 0}

        def malformed_final_label(*args):
            label_reads["count"] += 1
            if label_reads["count"] == 2:
                raise json.JSONDecodeError("malformed", "{", 1)
            return True

        apply_decision.core.target_label_state = malformed_final_label
        calls.clear()
        message, terminal = apply_decision.do_merge(
            "owner", "demo", 7, head, merge_assist_record=None
        )
        check(
            "confirmation: malformed final label state denies cleanly",
            terminal == "error"
            and "could not be verified" in message
            and "merge" not in calls,
        )
        apply_decision.core.target_label_state = lambda *args: True
        calls.clear()
        cleanup_fails["value"] = True
        _, terminal = apply_decision.do_merge(
            "owner", "demo", 7, head, merge_assist_record=None
        )
        check(
            "confirmation: label cleanup decode failure does not fail the merge",
            terminal == "resolved" and calls == ["merge", "remove-label"],
        )
    finally:
        apply_decision.core.gh_rest = saved_rest
        apply_decision.core.target_label_state = saved_label_state


def test_malformed_label_reads_fail_closed_at_every_boundary():
    malformed = json.JSONDecodeError("malformed", "{", 1)
    saved_rest = core.gh_rest
    saved_load = merge_assist._load
    saved_plan = merge_assist.verified_push_plan
    saved_fail = merge_assist._fail
    saved_write = merge_assist._write
    saved_apply = merge_assist.apply_confirmation_denial
    failures = []

    def fake_rest(path, method="GET", fields=None, **kwargs):
        if "/issues/7/labels/" in path:
            raise malformed
        if path.endswith("/pulls/7"):
            return {
                "state": "open",
                "merged": False,
                "head": {"sha": "a" * 40},
                "base": {"sha": "b" * 40},
            }
        raise AssertionError((path, method))

    core.gh_rest = fake_rest
    try:
        held, reason = auto_merge._live_confirmation_label_hold(
            "owner", "demo", 7
        )
        check(
            "labels: malformed preclaim evidence holds cleanly",
            held and "could not be re-read" in reason,
        )

        guard = auto_merge.final_auto_merge_guard(
            {"issue": 1}, "owner", "demo", 7, "card-token"
        )
        allowed, reason = guard({"labels": []})
        check(
            "labels: malformed G7 evidence holds before claiming further work",
            not allowed and "could not be re-read" in reason,
        )

        binding = {
            "owner": "owner",
            "repo": "demo",
            "number": 7,
            "head_sha": "a" * 40,
            "source_mode": core.PUSHABILITY_PERSONAL_FORK_EDITABLE,
        }
        merge_assist._load = lambda path, default=None: {
            "status": "resolved",
            "binding": binding,
            "resolution_head_sha": "c" * 40,
        }
        merge_assist.verified_push_plan = lambda *args: {"target_ref": "refs/heads/topic"}
        merge_assist._fail = lambda value, reason, path: failures.append(
            ("fail", str(reason), value)
        )
        merge_assist._write = lambda path, value: failures.append(
            ("write", value["status"], value)
        )
        args = type(
            "Args",
            (),
            {
                "state": "state.json",
                "repo_dir": "repo",
                "intent_out": "intent.json",
                "out": "out.json",
                "fork_credential_present": True,
            },
        )()
        merge_assist.cmd_claim_target(args)
        check(
            "labels: malformed assisted-merge kill-switch evidence denies after intent without mutation",
            [event[0] for event in failures] == ["write", "fail"]
            and failures[0][1] == "claim-intent"
            and "could not be verified" in failures[1][1]
            and "no target mutation was attempted" in failures[1][1]
            and failures[1][2]["confirmation_label_may_be_present"] is False,
        )

        message, terminal = apply_decision.do_merge(
            "owner", "demo", 7, "a" * 40
        )
        check(
            "labels: malformed manual confirmation evidence denies cleanly",
            terminal == "error"
            and "could not verify" in message
            and "No merge was attempted" in message,
        )
    finally:
        core.gh_rest = saved_rest
        merge_assist._load = saved_load
        merge_assist.verified_push_plan = saved_plan
        merge_assist._fail = saved_fail
        merge_assist._write = saved_write
        merge_assist.apply_confirmation_denial = saved_apply


def test_configuration_is_opt_in_and_fail_closed():
    check(
        "config: assisted merge is off in shipped code when the key is absent",
        core._assisted_merge_enabled({}, None) is False,
    )
    check(
        "config: a per-repo false overrides a global true",
        core._assisted_merge_enabled({"assisted_merge": False}, True) is False,
    )
    check(
        "config: a per-repo true overrides a global false",
        core._assisted_merge_enabled({"assisted_merge": True}, False) is True,
    )
    check(
        "config: a non-boolean value is not an opt-in",
        core._assisted_merge_enabled({"assisted_merge": "yes"}, True) is False,
    )
    check(
        "config: an invalid file cap fails closed to the minimum",
        core._assisted_merge_max_files({}, 0) == core.ASSISTED_MERGE_MAX_FILES_MIN
        and core._assisted_merge_max_files({}, True) == core.ASSISTED_MERGE_MAX_FILES_MIN,
    )
    check(
        "config: an invalid line cap fails closed to the minimum",
        core._assisted_merge_max_lines({}, 99999) == core.ASSISTED_MERGE_MAX_LINES_MIN,
    )
    check(
        "config: valid caps are honoured, globally and per repository",
        core._assisted_merge_max_files({}, 5) == 5
        and core._assisted_merge_max_files({"assisted_merge_max_conflict_files": 2}, 5) == 2
        and core._assisted_merge_max_lines({"assisted_merge_max_conflict_lines": 50}, 200) == 50,
    )
    shipped = core.load_config()
    check(
        "config: this repository has not enabled assisted merge yet",
        shipped["assisted_merge"] is False,
    )
    check(
        "config: the target kill-switch label is defined",
        core.NO_ASSISTED_MERGE_LABEL == "wheelhouse:no-assisted-merge",
    )


# --------------------------------------------------------------------------- #
# Static workflow and credential-isolation contracts
# --------------------------------------------------------------------------- #
def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


def steps_of(document):
    result = []
    for job in document.get("jobs", {}).values():
        result.extend(job.get("steps", []) or [])
    return result


def test_workflow_credential_isolation():
    workflows = {
        path.name: workflow(path.name)
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    }
    assist = workflows["merge-assist.yml"]
    push_steps = [
        step
        for step in steps_of(assist)
        if "ASSISTED_MERGE_PUSH_TOKEN" in json.dumps(step.get("env") or {})
    ]
    all_push_steps = [
        (name, step)
        for name, document in workflows.items()
        for step in steps_of(document)
        if "ASSISTED_MERGE_PUSH_TOKEN" in json.dumps(step.get("env") or {})
    ]
    check(
        "isolation: exactly one workflow step receives the push credential",
        len(all_push_steps) == 1 and all_push_steps[0][0] == "merge-assist.yml",
    )
    check("isolation: exactly one assist step receives the push credential", len(push_steps) == 1)
    push = push_steps[0]
    resolve_steps = {
        step.get("id"): step for step in assist["jobs"]["resolve"]["steps"]
        if step.get("id")
    }
    claim_target = resolve_steps["claim_target"]
    check(
        "isolation: target claim receives no push credential",
        "WHEELHOUSE_ASSIST_PUSH_TOKEN" not in (claim_target.get("env") or {}),
    )
    check(
        "isolation: the fork push step receives only the dedicated fork credential",
        push.get("id") == "push"
        and (push.get("env") or {}).get("WHEELHOUSE_ASSIST_PUSH_TOKEN")
        == "${{ secrets.ASSISTED_MERGE_PUSH_TOKEN }}",
    )
    same_repo_push = resolve_steps["push_same_repo"]
    check(
        "isolation: the same-repository push step receives only FLEET_TOKEN",
        (same_repo_push.get("env") or {}).get("WHEELHOUSE_ASSIST_PUSH_TOKEN")
        == "${{ secrets.FLEET_TOKEN }}"
        and "ASSISTED_MERGE_PUSH_TOKEN" not in json.dumps(same_repo_push),
    )
    check(
        "isolation: the push step never receives a card or model credential",
        "CLAUDE_CODE_OAUTH_TOKEN" not in json.dumps(push.get("env") or {})
        and "READONLY_TOKEN" not in json.dumps(push.get("env") or {}),
    )
    model_job = assist["jobs"]["model"]
    check(
        "isolation: the model job receives only the Claude subscription token",
        set(model_job.get("secrets") or {}) == {"CLAUDE_CODE_OAUTH_TOKEN"},
    )
    check(
        "isolation: the model job runs in the separate read-only model workflow",
        model_job.get("uses") == "./.github/workflows/claude-model.yml"
        and model_job["permissions"] == {"actions": "read", "contents": "read"},
    )
    check(
        "isolation: the fleet token is never handed to the model job",
        "FLEET_TOKEN" not in json.dumps(model_job),
    )
    check(
        "isolation: the assist is serialized per target pull request",
        assist["concurrency"]["cancel-in-progress"] is False
        and "${{ inputs.number }}" in assist["concurrency"]["group"],
    )
    check(
        "isolation: only the owner or this repository's own dispatch may start it",
        "github.repository_owner" in str(assist["jobs"]["prepare"].get("if"))
        and "github-actions[bot]" in str(assist["jobs"]["prepare"].get("if")),
    )
    prepare_steps = {
        step.get("id"): step for step in assist["jobs"]["prepare"]["steps"]
        if step.get("id")
    }
    check(
        "isolation: every owned card-write step uses the default token",
        all(
            "github.token" in str((step.get("env") or {}).get("GH_TOKEN", ""))
            for step in (
                prepare_steps["claim"],
                prepare_steps["record_escalation"],
                resolve_steps["record_outcome"],
            )
        ),
    )
    check(
        "isolation: both owned target-bind steps use the fleet token",
        "FLEET_TOKEN" in str((prepare_steps["bind"].get("env") or {}).get("GH_TOKEN", ""))
        and "FLEET_TOKEN" in str((resolve_steps["bind"].get("env") or {}).get("GH_TOKEN", "")),
    )
    check("isolation: the workflow is dispatch-only", set(assist[True]) == {"workflow_dispatch"})
    check(
        "isolation: the runner never gets contents write",
        assist["permissions"]["contents"] == "read",
    )


def test_model_step_is_read_only():
    model = workflow("claude-model.yml")
    steps = [
        step
        for step in steps_of(model)
        if str(step.get("id")) == "merge_resolve"
    ]
    check("model: the resolution step exists exactly once", len(steps) == 1)
    step = steps[0]
    check(
        "model: it is pinned to the same reviewed action commit",
        step["uses"]
        == "anthropics/claude-code-action@af0559ee4f514d1ef21826982bed13f7edc3c35e",
    )
    check(
        "model: it exposes only read tools - no Write, no Bash, no search",
        "--allowedTools Read,Grep,Glob\n" in step["with"]["claude_args"]
        and "Bash" not in step["with"]["claude_args"]
        and "Write" not in step["with"]["claude_args"],
    )
    check(
        "model: it keeps the subprocess environment scrub",
        (step.get("env") or {}).get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB") == "1",
    )
    check(
        "model: it never receives a search or fleet credential",
        "READONLY_TOKEN" not in json.dumps(step)
        and "FLEET_TOKEN" not in json.dumps(step),
    )
    check(
        "model: it uses the default token for the action's own GitHub calls",
        step["with"]["github_token"] == "${{ github.token }}",
    )
    check(
        "model: only this repository's own bot may trigger it",
        step["with"]["allowed_bots"] == "github-actions[bot]",
    )


def test_runtime_action_registration():
    from agent_runtime import config as runtime_config
    from agent_runtime.size_budget import SIZE_BUDGETS
    from agent_runtime.task_builder import ACTION_LIMITS

    check(
        "runtime: the action is registered exactly once",
        "merge.resolve-conflicts" in runtime_config.ACTIONS
        and "merge.resolve-conflicts" not in runtime_config.SCHEMA_REPAIR_ACTIONS,
    )
    check(
        "runtime: it has an explicit size budget and task limits",
        "merge.resolve-conflicts" in SIZE_BUDGETS
        and "merge.resolve-conflicts" in ACTION_LIMITS,
    )
    check(
        "runtime: it is bound to its own output schema",
        SIZE_BUDGETS["merge.resolve-conflicts"].schema_file
        == "merge-resolve-v1.schema.json",
    )
    selection = runtime_config.resolve_selection("merge.resolve-conflicts")
    check(
        "runtime: it resolves to the pinned production Claude profile",
        selection["profileName"] == runtime_config.PRIMARY_PROFILE
        and selection["fallback"] == "none",
    )
    schema = json.loads(
        (
            ROOT / "agent_runtime" / "schemas" / "actions" / "merge-resolve-v1.schema.json"
        ).read_text()
    )
    check(
        "runtime: the schema admits only the fixed selection vocabulary",
        schema["properties"]["resolutions"]["items"]["properties"]["selection"]["enum"]
        == list(merge_assist.SELECTIONS),
    )
    check(
        "runtime: the schema has no field through which the model can supply text lines",
        set(schema["properties"]["resolutions"]["items"]["properties"])
        == {"file", "hunk", "selection", "rationale"}
        and schema["properties"]["resolutions"]["items"]["additionalProperties"] is False,
    )


def main():
    test_parsing()
    test_rendering_has_zero_novel_lines()
    test_admission()
    test_result_boundary()
    test_end_to_end_resolution()
    test_end_to_end_escalations()
    test_conflict_inventory_binding()
    test_bind_is_fork_only_and_kill_switch_is_exact()
    test_push_confinement()
    test_confirmation_denial_transaction()
    test_claim_intent_supersedes_pre_mutation_state_for_outcome_selection()
    test_record_reports_deferred_card_write()
    test_card_record()
    test_card_section_and_body()
    test_render_binds_the_record_to_the_card_head()
    test_do_merge_routing()
    test_confirmation_routing_and_auto_merge_holds()
    test_malformed_label_reads_fail_closed_at_every_boundary()
    test_configuration_is_opt_in_and_fail_closed()
    test_workflow_credential_isolation()
    test_model_step_is_read_only()
    test_runtime_action_registration()
    if _failures:
        print("%d FAILED: %s" % (len(_failures), ", ".join(_failures)))
        raise SystemExit(1)
    print("all assisted merge tests passed")


if __name__ == "__main__":
    main()
