"""Shared discipline for shelling out to a scanner.

Extracted the moment there were two wrappers, because the rule that matters
here must not exist in two copies that can drift: **a tool that failed is not a
repo that is clean.** gitleaks removing `detect` in 8.24 turned a broken
invocation into a silent empty result, and CI only caught it because an
integration test asserted a finding. One copy of that logic, one place to fix.
"""

from __future__ import annotations

import subprocess

from ..finding import Finding

_HELP_CACHE: dict[tuple[str, str], bool] = {}


def supports(binary: str, needle: str) -> bool:
    """Does `binary --help` mention `needle`?

    Scanner CLIs move between majors -- gitleaks dropped `detect`, osv-scanner
    moved behind `scan`. Probing beats parsing a version string, which lies as
    soon as someone ships a fork or a distro patch.
    """
    key = (binary, needle)
    if key not in _HELP_CACHE:
        try:
            r = subprocess.run([binary, "--help"], capture_output=True, text=True,
                               timeout=20, check=False)
            _HELP_CACHE[key] = needle in (r.stdout + r.stderr)
        except (OSError, subprocess.SubprocessError):
            _HELP_CACHE[key] = False
    return _HELP_CACHE[key]


def error(engine: str, tool: str, detail: str) -> Finding:
    """The finding that refuses to let a broken scanner look like a clean repo."""
    return Finding(
        engine=engine, rule="ENGINE-ERROR", severity="low", path=tool,
        message=f"{tool} did not run cleanly, so this check did NOT happen: {detail}",
        fix="run the command by hand to see the failure; do not read this scan "
            "as evidence that the repo is clean",
        snippet=detail[:120])


def invoke(cmd: list[str], ok_codes: tuple[int, ...], timeout: int = 180):
    """-> (stdout, error_detail). Exactly one of them is meaningful.

    Argument list, never shell=True: a repo path is attacker-controlled input in
    the CI threat model.
    """
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           check=False)
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except OSError as e:
        return "", str(e)
    if r.returncode not in ok_codes:
        return "", (r.stderr or r.stdout or "").strip()[-160:] or f"exit {r.returncode}"
    return r.stdout, ""
