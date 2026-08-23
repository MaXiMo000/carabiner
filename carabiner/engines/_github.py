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

# Who published the action matters more than whether it is pinned. GitHub
# tag-protects its own action repos; a stranger's `@master` can be repointed at
# new code tonight. Treating those two identically produced 1470 findings across
# 60 repositories, 49% of everything the tool reported, and almost none of it
# worth anyone's afternoon.
FIRST_PARTY_OWNERS = {"actions", "github"}

# Classified by shape, not by a list of branch names. A hardcoded list of
# main/master/develop missed `stable`, `nightly`, `cargo-hack` and `wasm-pack`
# in tokio alone -- all branches of the actions they reference, all moving.
_VERSION_TAG = re.compile(r"^v?\d+(\.\d+)*$", re.I)


def _pin_severity(uses: str, ref: str) -> tuple[str, str]:
    """-> (severity, why).

    A moving branch from a third party is the finding worth acting on. A version
    tag is what nearly every project uses and flagging it at any real severity
    buries the branch refs that matter.
    """
    first_party = uses.split("/", 1)[0].lower() in FIRST_PARTY_OWNERS
    versioned = bool(_VERSION_TAG.match(ref))
    if not versioned and not first_party:
        return "medium", ("tracks a moving branch in someone else's repository "
                          "-- what runs here can change tonight without a diff "
                          "on your side")
    if not versioned:
        return "low", "tracks a moving branch rather than a fixed commit"
    return "info", ("a version tag; pin to a SHA for full supply-chain hygiene, "
                    "though the owner would have to move the tag deliberately")


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


def _step_text(step: dict) -> str:
    """Everything in a step that could reference a context, flattened."""
    import json as _json
    try:
        return _json.dumps(step)
    except (TypeError, ValueError):
        return str(step)


def run(root: pathlib.Path) -> list[Finding]:
    out: list[Finding] = []
    for wf in sorted((root / WORKFLOWS).glob("*.y*ml")):
        rel = wf.relative_to(root).as_posix()
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

        # ---- the untrusted-trigger family -------------------------------
        # pull_request_target and workflow_run both run in the context of the
        # base repository, with its secrets and a write token, while the code
        # being handled belongs to whoever opened the pull request. Everything
        # below is only a finding because of that combination.
        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict) or not risky_trigger:
                continue
            steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
            blob = " ".join(_step_text(s) for s in steps) + _step_text(
                {k: v for k, v in job.items() if k != "steps"})

            # CI006 -- a real secret in reach of code the attacker supplied.
            secrets_used = set(re.findall(
                r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", blob))
            secrets_used.discard("GITHUB_TOKEN")
            if secrets_used and any("uses" in s and "checkout" in str(s.get("uses", ""))
                                    for s in steps):
                out.append(Finding(
                    "ci", "CI006", "high", rel,
                    f"job '{job_name}' runs on an untrusted trigger, checks out "
                    f"code, and has repository secrets in scope "
                    f"({', '.join(sorted(secrets_used)[:3])}) -- anything the "
                    "checked-out code executes can read them",
                    fix="split it: an unprivileged job that handles the PR code, "
                        "and a privileged job that never checks it out",
                    snippet=", ".join(sorted(secrets_used)[:3])))

            # CI008 -- checkout leaves the token in .git/config unless told not
            # to, and every later step in the job can read it.
            for st in steps:
                if "checkout" not in str(st.get("uses", "")):
                    continue
                with_ = st.get("with") or {}
                if str(with_.get("persist-credentials", "")).lower() != "false":
                    out.append(Finding(
                        "ci", "CI008", "high", rel,
                        f"job '{job_name}' checks out on an untrusted trigger "
                        "without `persist-credentials: false` -- the token stays "
                        "in .git/config and any later step, including one running "
                        "the contributor's build scripts, can read it",
                        fix="set `persist-credentials: false` on the checkout, or "
                            "do not check out untrusted code in a privileged job",
                        snippet="persist-credentials not disabled"))
                    break

            # CI010 -- a cache written from an untrusted trigger is a cache the
            # attacker can poison for later privileged runs.
            if any("actions/cache" in str(s.get("uses", "")) for s in steps):
                out.append(Finding(
                    "ci", "CI010", "medium", rel,
                    f"job '{job_name}' restores and saves a cache on an untrusted "
                    "trigger -- a poisoned entry is replayed into later runs",
                    fix="use actions/cache/restore with a read-only key here, and "
                        "save the cache only from trusted branches",
                    snippet="actions/cache on an untrusted trigger"))

        # CI009 -- `secrets: inherit` hands every repository secret to another
        # workflow file, including whatever that file grows into later.
        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if str(job.get("secrets", "")).lower() != "inherit":
                continue
            called = str(job.get("uses", ""))
            # Inheriting into your own reusable workflow crosses no trust
            # boundary -- same repository, same secrets, same reviewers. Every
            # one of these in a 60-repo corpus was local, and flagging them
            # would have added 106 findings that mean nothing. The risk is
            # handing every secret to a workflow someone else controls.
            if called.startswith("./") or not called:
                continue
            out.append(Finding(
                "ci", "CI009", "high" if risky_trigger else "medium", rel,
                f"job '{job_name}' calls `{called}` with `secrets: inherit` -- a "
                "workflow in another repository receives every secret you have, "
                "including ones added long after this line was written",
                fix="pass named secrets explicitly under `secrets:`",
                snippet=called))

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
                    sev, why = _pin_severity(uses, ref)
                    out.append(Finding(
                        "ci", "CI003", sev, rel,
                        f"action `{uses}` is not pinned to a commit -- {why}",
                        fix="pin to a full 40-character commit SHA and let "
                            "Dependabot bump it",
                        # Deliberately NOT keyed on the job: one unpinned action
                        # reference is one decision, however many steps use it.
                        # tokio reaches dtolnay/rust-toolchain@stable 34 times in
                        # a single workflow, and 34 identical lines is a wall,
                        # not a report. Dedup in the CLI collapses these.
                        snippet=uses))

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
