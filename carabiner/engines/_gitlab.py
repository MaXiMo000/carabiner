"""GitLab CI security. Native, same as the GitHub side.

The vulnerabilities are the same shapes with different spellings: a merge
request title is attacker-controlled input on GitLab exactly as a pull request
title is on GitHub, and interpolating it into `script:` runs it as shell.

Hardcoded credentials in `variables:` are deliberately NOT checked here -- the
secrets engine already finds those, and two engines reporting one problem is how
a tool loses trust.
"""

from __future__ import annotations

import pathlib
import re

import yaml

from ..finding import Finding

CONFIG_NAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")

# Keys that are configuration, not jobs.
RESERVED = {"stages", "variables", "include", "default", "workflow", "image",
            "services", "before_script", "after_script", "cache", "types"}

SCRIPT_KEYS = ("script", "before_script", "after_script")

# Attacker-controlled predefined variables. A branch name and an MR title are
# both chosen by whoever opens the merge request, including from a fork.
# CI_COMMIT_REF_SLUG is deliberately absent: GitLab sanitises it, so it is safe.
_INJECTABLE = re.compile(
    r"\$\{?(CI_COMMIT_(MESSAGE|TITLE|DESCRIPTION|REF_NAME|BRANCH|TAG|AUTHOR)"
    r"|CI_MERGE_REQUEST_(TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|LABELS))\b")

# A pinned image is a digest. A tag -- including no tag, which means :latest --
# can be repointed at new content under the same name.
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def available(root: pathlib.Path) -> bool:
    return any((root / n).exists() for n in CONFIG_NAMES)


def _scripts(job: dict):
    for key in SCRIPT_KEYS:
        val = job.get(key)
        if isinstance(val, str):
            yield val
        elif isinstance(val, list):
            for line in val:
                if isinstance(line, str):
                    yield line


def _image_names(node) -> list[str]:
    out = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict) and isinstance(node.get("name"), str):
        out.append(node["name"])
    elif isinstance(node, list):
        for item in node:
            out.extend(_image_names(item))
    return out


def run(root: pathlib.Path) -> list[Finding]:
    path = next((root / n for n in CONFIG_NAMES if (root / n).exists()), None)
    if path is None:
        return []
    rel = str(path.relative_to(root))
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError as e:
        return [Finding("ci", "GL000", "low", rel,
                        "GitLab CI config is not parseable YAML",
                        fix="fix the syntax; carabiner skipped this file",
                        snippet=str(e)[:120])]
    if not isinstance(doc, dict):
        return []

    out: list[Finding] = []

    # GL002 -- a remote include with no pinned ref is someone else's code
    # running in your pipeline, changeable without your knowledge.
    includes = doc.get("include")
    for inc in (includes if isinstance(includes, list) else [includes]):
        if isinstance(inc, str) and inc.startswith(("http://", "https://")):
            out.append(Finding(
                "ci", "GL002", "medium", rel,
                "remote `include:` pulls pipeline config from a URL that can "
                "change without notice",
                fix="vendor the file, or use `project:` + `ref:` pinned to a "
                    "commit SHA",
                snippet=inc))
        elif isinstance(inc, dict):
            if inc.get("remote"):
                out.append(Finding(
                    "ci", "GL002", "medium", rel,
                    "remote `include:` pulls pipeline config from a URL that "
                    "can change without notice",
                    fix="vendor the file, or use `project:` + `ref:` pinned to "
                        "a commit SHA",
                    snippet=str(inc.get("remote"))))
            elif inc.get("project") and not inc.get("ref"):
                out.append(Finding(
                    "ci", "GL002", "medium", rel,
                    f"`include:` from project {inc['project']} has no `ref:` -- "
                    "it tracks that project's default branch",
                    fix="pin `ref:` to a commit SHA",
                    snippet=str(inc.get("project"))))

    jobs = {k: v for k, v in doc.items()
            if k not in RESERVED and not k.startswith(".")
            and isinstance(v, dict)}
    # `default:` and top level carry images too, and they apply to every job.
    scopes = list(jobs.items())
    for key in ("default",):
        if isinstance(doc.get(key), dict):
            scopes.append((key, doc[key]))
    if "image" in doc or "services" in doc:
        scopes.append(("<top-level>", {k: doc[k] for k in ("image", "services")
                                       if k in doc}))

    for name, job in scopes:
        # GL001 -- the merge request title becomes shell.
        for line in _scripts(job):
            m = _INJECTABLE.search(line)
            if m:
                out.append(Finding(
                    "ci", "GL001", "high", rel,
                    f"job '{name}' interpolates attacker-controlled CI context "
                    "into a script -- a crafted merge request title or branch "
                    "name executes as shell on your runner",
                    fix="assign it to a variable via `variables:` and reference "
                        '"$VAR" quoted; the value is then data, not code',
                    snippet=m.group(0)))

        # GL003 -- mutable base images.
        for field in ("image", "services"):
            for img in _image_names(job.get(field)):
                if not _DIGEST.search(img):
                    tag = img.rpartition(":")[2] if ":" in img.rpartition("/")[2] \
                        else "latest (implicit)"
                    out.append(Finding(
                        "ci", "GL003", "medium", rel,
                        f"job '{name}' uses `{field}: {img}` -- tag '{tag}' is "
                        "mutable and can be repointed at different content",
                        fix="pin the image by digest: image@sha256:<64 hex>",
                        snippet=f"{name}: {field}: {img}"))
    return out
