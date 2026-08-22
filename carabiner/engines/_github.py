"""GitHub Actions workflow security. Native -- this is our own code.

Workflows are the most commonly exploited and least commonly scanned part of a
modern repo, and they are plain YAML, so there is no excuse for wrapping
something. Prior art to read before extending this: `zizmor`. If it turns out
strictly better on some check, delete that check and wrap it.
"""

from __future__ import annotations

import pathlib
import re

import yaml

from ..finding import Finding

WORKFLOWS = ".github/workflows"

# A pinned action is 40 hex characters. Everything else -- tags, branches,
# `@main`, `@v4` -- is mutable and can be repointed at new code by whoever
# controls the repository.
_SHA = re.compile(r"^[0-9a-f]{40}$")

# Attacker-controlled context values, named explicitly rather than pattern-matched.
#
# The first version matched anything under github.event ending in title/body/ref
# and so on. Across 33 well-known repositories that produced three findings and
# two were wrong: tokio's `pull_request.base.ref` is the *target* branch in the
# maintainer's own repo, and nlohmann/json's `pull_request.user.login` is a
# GitHub username, whose charset cannot carry a shell metacharacter. Only the
# fields an outsider can actually put arbitrary text into belong here.
#
# Sources of free-form text from an anonymous contributor:
_ANON = (
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.comment.body", "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title", "github.event.discussion.body",
    "github.event.pull_request.head.ref", "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.head_commit.message", "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.pages", "github.head_ref",
)
# Free-form, but only from someone who can already trigger the workflow. Real,
# and a lower bar to reach than the list above -- reported one level down.
_DISPATCH = "github.event.inputs."

_INJECTABLE = re.compile(
    "|".join(re.escape(x) for x in _ANON).replace(r"\.", r"\s*\.\s*"), re.I)
_INJECTABLE_DISPATCH = re.compile(re.escape(_DISPATCH), re.I)


def available(root: pathlib.Path) -> bool:
    return (root / WORKFLOWS).is_dir()


def _triggers(doc: dict) -> set[str]:
    """YAML 1.1 parses a bare `on:` key as the boolean True, so a workflow's
    trigger block lands under `True` rather than `"on"`. Every hand-rolled
    Actions parser gets this wrong once."""
    raw = doc.get("on", doc.get(True))
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return set(raw)
    if isinstance(raw, dict):
        return set(raw)
    return set()


def _steps(doc: dict):
    for job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for step in (job.get("steps") or []):
            if isinstance(step, dict):
                yield job_name, job, step


def _perm_writes(perms) -> list[str]:
    if perms == "write-all":
        return ["write-all"]
    if isinstance(perms, dict):
        return [f"{k}: {v}" for k, v in perms.items() if v == "write"]
    return []


def run(root: pathlib.Path) -> list[Finding]:
    out: list[Finding] = []
    for wf in sorted((root / WORKFLOWS).glob("*.y*ml")):
        rel = str(wf.relative_to(root))
        try:
            doc = yaml.safe_load(wf.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError as e:
            out.append(Finding("ci", "CI000", "low", rel,
                               "workflow is not parseable YAML",
                               fix="fix the syntax; carabiner skipped this file",
                               snippet=str(e)[:120]))
            continue
        if not isinstance(doc, dict):
            continue

        triggers = _triggers(doc)
        risky_trigger = "pull_request_target" in triggers or \
                        "workflow_run" in triggers

        # CI001 -- the canonical secret-theft path. pull_request_target runs
        # with repository secrets AND a write token; checking out the PR head
        # then executes the attacker's code with both in scope.
        if risky_trigger:
            for job_name, _job, step in _steps(doc):
                uses = str(step.get("uses", ""))
                ref = str((step.get("with") or {}).get("ref", ""))
                if uses.startswith("actions/checkout") and (
                        "github.event.pull_request" in ref or "head" in ref.lower()):
                    # A job-level `if:` comparing the PR author is a real
                    # mitigation -- a login is not attacker-settable. Discourse
                    # gates exactly this workflow to dependabot. Still reported,
                    # because these guards are easy to write wrongly, but not at
                    # the severity reserved for an open door.
                    guard = str(_job.get("if", ""))
                    guarded = bool(re.search(r"(user\.login|github\.actor)", guard))
                    out.append(Finding(
                        "ci", "CI001", "high" if guarded else "critical", rel,
                        f"job '{job_name}' runs on pull_request_target and checks "
                        "out the PR head -- untrusted code runs with your secrets"
                        + (" (a job-level `if:` restricts who triggers it, which "
                           "lowers but does not remove the risk)" if guarded else ""),
                        fix="use `pull_request`, or split into an untrusted build "
                            "job and a privileged job that never checks out the head",
                        snippet=f"ref: {ref}", line=None))

        # CI004/CI005 -- token blast radius.
        if "permissions" not in doc:
            out.append(Finding(
                "ci", "CI004", "medium", rel,
                "no top-level `permissions:` -- the workflow inherits the "
                "repository default, which on older repos is write-all",
                fix="add `permissions: {contents: read}` at the top level and "
                    "widen only the jobs that need it",
                snippet="permissions: <absent>"))
        else:
            for w in _perm_writes(doc["permissions"]):
                out.append(Finding(
                    "ci", "CI005", "medium", rel,
                    f"top-level write permission granted ({w})",
                    fix="move the write scope onto the single job that needs it",
                    snippet=f"permissions {w}"))

        for job_name, job, step in _steps(doc):
            # CI002 -- script injection. The PR title becomes shell.
            script = str(step.get("run", ""))
            m = _INJECTABLE.search(script)
            if m:
                out.append(Finding(
                    "ci", "CI002", "high", rel,
                    f"job '{job_name}' interpolates attacker-controlled context "
                    "directly into a `run:` block -- a crafted PR title or branch "
                    "name executes as shell on your runner",
                    fix="pass it through `env:` and reference \"$VAR\" quoted in "
                        "the script; the value is then data, not code",
                    snippet=m.group(0)))
            elif _INJECTABLE_DISPATCH.search(script):
                d = _INJECTABLE_DISPATCH.search(script)
                out.append(Finding(
                    "ci", "CI002", "medium", rel,
                    f"job '{job_name}' interpolates a workflow_dispatch input "
                    "into a `run:` block -- free-form text, though it takes "
                    "someone who can already trigger the workflow",
                    fix="pass it through `env:` and reference \"$VAR\" quoted",
                    snippet=script[d.start():script.find("}}", d.start()) + 2
                                   if "}}" in script[d.start():] else d.start() + 40]))

            # CI003 -- mutable action references.
            uses = str(step.get("uses", ""))
            if uses and not uses.startswith(("./", "docker://")):
                ref = uses.partition("@")[2]
                if not ref or not _SHA.match(ref):
                    out.append(Finding(
                        "ci", "CI003", "medium", rel,
                        f"action `{uses}` is pinned to a mutable ref -- whoever "
                        "controls that repo can repoint the tag at new code",
                        fix="pin to a full 40-character commit SHA and let "
                            "Dependabot bump it",
                        # Job name is part of the snippet so two jobs pinning the
                        # same action stay two findings -- they are two places to
                        # fix, and collapsing them hides one.
                        snippet=f"{job_name}: {uses}"))

        # CI007 -- anyone's PR executes on your hardware.
        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            runs_on = job.get("runs-on")
            flat = runs_on if isinstance(runs_on, str) else " ".join(
                map(str, runs_on or []))
            if "self-hosted" in flat:
                out.append(Finding(
                    "ci", "CI007", "high" if risky_trigger else "low", rel,
                    f"job '{job_name}' uses a self-hosted runner"
                    + (" on an untrusted trigger" if risky_trigger else ""),
                    fix="use ephemeral runners; a persistent self-hosted runner "
                        "on a public repo executes every stranger's PR",
                    snippet=f"runs-on: {flat}"))
    return out
