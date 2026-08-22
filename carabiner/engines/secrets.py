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

from ..finding import Finding

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
            severity="critical" if in_history else "high",
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


def _scan(binary: str, root: pathlib.Path, history: bool) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "gitleaks.json"
        cmd = [binary, "detect", "--no-banner", "--redact",
               "--source", str(root),
               "--report-format", "json", "--report-path", str(report)]
        if not history:
            cmd.append("--no-git")
        try:
            # Argument list, never shell=True: a repo path is attacker-controlled
            # input in the CI threat model. Bounded time, bounded output.
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                               check=False)
        except (OSError, subprocess.SubprocessError):
            return []
        if r.returncode not in (0, _LEAKS_FOUND) or not report.exists():
            return []
        try:
            return _parse(json.loads(report.read_text() or "[]"), history)
        except (json.JSONDecodeError, ValueError):
            return []


def run(root: pathlib.Path) -> list[Finding]:
    binary = _bin()
    if not binary:
        return []
    findings = _scan(binary, root, history=False)
    if (root / ".git").exists():
        findings += _scan(binary, root, history=True)
    return findings
