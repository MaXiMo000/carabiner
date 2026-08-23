"""Secrets. Wraps gitleaks -- never reimplements it.

gitleaks is better at this than anything written here would be, and its rule
set is maintained by people who do nothing else. carabiner's job is to
normalize the output, sort history findings from working-tree ones, and put
them in the ratchet.

History matters more than the working tree: a secret deleted in a later commit
is still in the pack file and still needs rotating. Deleting the file is not
remediation, which is why those are reported one severity higher.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile

from . import _tool

from ..finding import Finding
from .repo import _is_fixture

REQUIRES = "gitleaks"
INSTALL = "brew install gitleaks   (or https://github.com/gitleaks/gitleaks/releases)"

# gitleaks exits 1 when it finds leaks, 0 when clean. Anything else is a real
# failure. Not treating 1 as success is how a wrapper silently reports "clean".
_LEAKS_FOUND = 1


def _bin() -> str | None:
    return shutil.which(REQUIRES)


def available(root: pathlib.Path) -> bool:
    return _bin() is not None


def missing(root: pathlib.Path) -> str | None:
    """Install hint if this engine could contribute but cannot run."""
    return None if _bin() else INSTALL


def _parse(payload: list[dict], in_history: bool) -> list[Finding]:
    """Split out from the subprocess call so it is testable without the binary.

    Fields are read defensively: gitleaks' JSON schema has moved between
    majors, and an engine that raises on an unknown key takes the whole scan
    down with it.
    """
    out = []
    for item in payload or []:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID") or item.get("Rule") or "unknown")
        path = str(item.get("File") or item.get("file") or "?")
        line = item.get("StartLine") or item.get("startLine")
        commit = str(item.get("Commit") or "")[:8]
        out.append(Finding(
            engine="secrets",
            rule=f"SECRET-{rule}",
            # A match under tests/ or examples/ is usually a fixture. Still
            # reported -- real keys do land there -- one level down.
            severity=("critical" if in_history else "high")
                     if not _is_fixture(pathlib.PurePosixPath(path).parts[:-1])
                     else ("high" if in_history else "medium"),
            path=path,
            line=int(line) if isinstance(line, int) else None,
            message=(str(item.get("Description") or "credential detected")
                     + (f" (in history, commit {commit})" if in_history else "")),
            fix=("rotate the credential now, then purge it from history with "
                 "git-filter-repo -- it is in the pack file and deleting the "
                 "file does not remove it"
                 if in_history else
                 "remove it from the file and rotate the credential; assume it "
                 "is already compromised"),
            # gitleaks --redact already masks this; Finding redacts again on
            # construction. Two layers, because one is a promise.
            snippet=str(item.get("Match") or item.get("Secret") or "")))
    return out


def _err(detail: str) -> Finding:
    return _tool.error("secrets", REQUIRES, detail)


def _scan(binary: str, root: pathlib.Path, history: bool) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "gitleaks.json"
        if _tool.supports(binary, "\n  dir "):
            cmd = [binary, "git" if history else "dir", str(root)]
        else:
            cmd = [binary, "detect", "--source", str(root)]
            if not history:
                cmd.append("--no-git")
        cmd += ["--no-banner", "--redact", "--exit-code", str(_LEAKS_FOUND),
                "--report-format", "json", "--report-path", str(report)]
        _, err = _tool.invoke(cmd, ok_codes=(0, _LEAKS_FOUND))
        if err:
            return [_err(err)]
        if not report.exists():
            return []
        try:
            return _parse(json.loads(report.read_text(encoding="utf-8", errors="replace") or "[]"), history)
        except (json.JSONDecodeError, ValueError) as e:
            return [_err(f"unparseable report: {e}")]


def _scan_staged(binary: str, root: pathlib.Path) -> list[Finding]:
    """gitleaks' own pre-commit mode. Filtering a whole-tree scan afterwards
    saves nothing -- the work has already happened -- so diff mode has to stop
    the scan being done, not hide its results."""
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "gitleaks.json"
        cmd = [binary, "git", "--staged", str(root), "--no-banner", "--redact",
               "--exit-code", str(_LEAKS_FOUND),
               "--report-format", "json", "--report-path", str(report)]
        _, err = _tool.invoke(cmd, ok_codes=(0, _LEAKS_FOUND))
        if err:
            return [_err(err)]
        if not report.exists():
            return []
        try:
            return _parse(json.loads(report.read_text(encoding="utf-8", errors="replace") or "[]"), False)
        except (json.JSONDecodeError, ValueError) as e:
            return [_err(f"unparseable report: {e}")]


def run(root: pathlib.Path, full: bool = False,
        changed: set[str] | None = None) -> list[Finding]:
    """History scanning is `full` only.

    Rewalking every commit is seconds, not milliseconds, and a pre-commit hook
    that costs seconds gets uninstalled inside a week. The working tree is
    checked on every commit; history is checked in CI.
    """
    binary = _bin()
    if not binary:
        return []
    if changed is not None:
        # Only what is about to be committed. Whole-tree scanning here is what
        # made --diff slower than a full scan in the first implementation.
        return _scan_staged(binary, root)
    findings = _scan(binary, root, history=False)
    if full and (root / ".git").exists():
        findings += _scan(binary, root, history=True)
    if changed is not None:
        findings = [f for f in findings
                    if f.path in changed or f.rule == "ENGINE-ERROR"]
    return findings
