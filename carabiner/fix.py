"""`carabiner fix`: pin every action to the commit its tag points at today.

CI003 (an action referenced by a tag or branch) was about half of every
finding across the repositories carabiner has been run on, and fixing it by
hand is tedious: look up each tag's commit, paste forty hex characters, keep
the tag as a comment so Dependabot can still bump it. That is mechanical and
changes nothing about what runs today, so it is automated.

What is deliberately NOT automated: adding `permissions:` or
`persist-credentials: false`. Both can break a job that pushes, comments or
publishes, and only a person who knows the job can tell. Those stay findings.

Lines are rewritten in place -- never a YAML round-trip -- so comments,
quoting and layout survive exactly.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request

from .engines._github import _SHA, _own_slug, _repo_of

# `uses: owner/repo[/path]@ref`, optionally quoted, optionally commented.
_USES = re.compile(
    r"""^(?P<lead>\s*(?:-\s*)?uses:\s*)(?P<q>["']?)"""
    r"""(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<ref>[^\s"'#]+)(?P=q)"""
    r"""(?P<tail>\s*(?:#\s?(?P<comment>.*))?)$""")


def _files(root: pathlib.Path) -> list[pathlib.Path]:
    gh = root / ".github"
    found = sorted((gh / "workflows").glob("*.y*ml"))
    found += sorted(p for p in (gh / "actions").rglob("action.y*ml")) if (gh / "actions").is_dir() else []
    return found


def _api_sha(repo: str, ref: str) -> str | None:
    """The commit a ref points at, peeled through annotated tags."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github.sha", "User-Agent": "carabiner",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
            sha = r.read().decode().strip()
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    return sha if _SHA.match(sha) else None


def plan(root: pathlib.Path, resolve=_api_sha) -> tuple[list[dict], list[dict]]:
    """(changes, unresolved). Nothing is written here."""
    own = _own_slug(root)
    cache: dict[tuple[str, str], str | None] = {}
    changes, unresolved = [], []
    for path in _files(root):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = _USES.match(line)
            if not m or _SHA.match(m["ref"]):
                continue
            repo = _repo_of(f"{m['action']}@{m['ref']}")
            if own and repo == own:
                continue  # your own action: nothing crosses a trust boundary
            key = (repo, m["ref"])
            if key not in cache:
                cache[key] = resolve(repo, m["ref"])
            sha = cache[key]
            where = {"path": path.relative_to(root).as_posix(), "line": number,
                     "uses": f"{m['action']}@{m['ref']}"}
            if sha is None:
                unresolved.append(where)
                continue
            # The tag stays as a comment: Dependabot reads `# v4` to keep
            # bumping a pinned action, and a person reads it to know what it is.
            note = m["ref"] + (f" -- {m['comment'].strip()}" if m["comment"] and
                               m["comment"].strip() != m["ref"] else "")
            new = f"{m['lead']}{m['q']}{m['action']}@{sha}{m['q']}  # {note}"
            changes.append({**where, "old": line, "new": new, "sha": sha})
    return changes, unresolved


def apply(root: pathlib.Path, changes: list[dict]) -> None:
    by_file: dict[str, dict[int, str]] = {}
    for c in changes:
        by_file.setdefault(c["path"], {})[c["line"]] = c["new"]
    for rel, lines in by_file.items():
        path = root / rel
        raw = path.read_bytes().decode("utf-8")
        newline = "\r\n" if "\r\n" in raw else "\n"
        text = raw.splitlines()
        for number, new in lines.items():
            text[number - 1] = new
        path.write_bytes((newline.join(text) + (newline if raw.endswith(("\n", "\r\n")) else "")).encode("utf-8"))


def run(root: pathlib.Path, dry_run: bool, as_json: bool = False) -> int:
    changes, unresolved = plan(root)
    if as_json:
        print(json.dumps({"changes": changes, "unresolved": unresolved}, indent=2))
    else:
        for c in changes:
            print(f"  {c['path']}:{c['line']}\n    - {c['old'].strip()}\n    + {c['new'].strip()}")
        for u in unresolved:
            print(f"  {u['path']}:{u['line']}  could not resolve {u['uses']} -- left as it is")
        verb = "would pin" if dry_run else "pinned"
        print(f"\n{verb} {len(changes)} action reference(s)"
              + (f"; {len(unresolved)} could not be resolved (set GITHUB_TOKEN if rate-limited)"
                 if unresolved else ""))
    if not dry_run:
        apply(root, changes)
    # A reference that could not be pinned is still a finding: say so in the
    # exit code rather than reporting the job done.
    return 1 if unresolved else 0
