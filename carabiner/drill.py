"""The drill: verify controls fire, rather than that they are configured.

Everything else in carabiner reads files. This reads outcomes. A pre-commit hook
listed in `.pre-commit-config.yaml` that nobody ran `pre-commit install` for is
the single most common "we have secret scanning" that does not -- and it is
invisible to every static checker, including ours, because the configuration is
perfect. The only way to know is to plant a credential and see what happens.

The governing rule, same as the engines: **a drill that could not run never
reports as passing.** Unverified is not secure, and a green check you did not
earn is worse than no check.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import urllib.error
import urllib.request

from .finding import Finding

API = "https://api.github.com"

# Obviously synthetic, structurally valid enough for a scanner's private-key
# rule, and not a credential to anything. Assembled rather than written out so
# this file does not itself contain the literal marker.
_CANARY_MARKER = "-----BEGIN" + " RSA PRIVATE KEY-----"
_CANARY_BODY = "MIIEowIBAAKCAQEA" + "cArAbInErDrIlLnOtArEaLkEy0123456789" * 4
CANARY = f"{_CANARY_MARKER}\n{_CANARY_BODY}\n-----END" + " RSA PRIVATE KEY-----\n"


def _finding(rule, severity, message, fix, snippet="") -> Finding:
    return Finding("drill", rule, severity, "<drill>", message, fix=fix,
                   snippet=snippet)


def _unverified(rule, what, why) -> Finding:
    """Could not check is not the same as fine. Never silently pass."""
    return _finding(rule, "low", f"{what} could NOT be verified: {why}",
                    "this is not a pass -- check it by hand, or grant the "
                    "access the drill needs")


# ------------------------------------------------------------- local drill --

def hook_fires(root: pathlib.Path) -> list[Finding]:
    """Plant a credential and see whether the commit hooks actually stop it."""
    cfg = root / ".pre-commit-config.yaml"
    installed = (root / ".git" / "hooks" / "pre-commit").exists()

    if not cfg.exists():
        return [_finding(
            "DRILL001", "medium", "no pre-commit hooks are configured",
            "add .pre-commit-config.yaml with a secret scanner; the cheapest "
            "control there is, and the only one that runs before the secret "
            "leaves your laptop")]

    if not installed:
        return [_finding(
            "DRILL002", "high",
            "pre-commit hooks are configured but NOT installed -- the config "
            "looks right and nothing runs",
            "run `pre-commit install`; until then every hook in that file is "
            "decorative")]

    if not shutil.which("pre-commit"):
        return [_unverified("DRILL003", "hook execution",
                            "the `pre-commit` binary is not on PATH")]

    # Local-only ignore first, so a crash cannot leave a committable canary.
    canary = root / ".carabiner-drill-canary.key"
    exclude = root / ".git" / "info" / "exclude"
    try:
        if exclude.parent.is_dir():
            body = exclude.read_text() if exclude.exists() else ""
            if canary.name not in body:
                exclude.write_text(body.rstrip("\n") + f"\n{canary.name}\n")
        canary.write_text(CANARY)
        r = subprocess.run(["pre-commit", "run", "--files", str(canary)],
                           cwd=root, capture_output=True, text=True,
                           timeout=180, check=False)
        if r.returncode == 0:
            return [_finding(
                "DRILL004", "critical",
                "a planted private key passed the installed pre-commit hooks -- "
                "secret scanning is configured, installed, and not catching "
                "credentials",
                "add a secret scanner to .pre-commit-config.yaml (gitleaks has "
                "an official hook) and re-run `carabiner drill`")]
        return []
    except (OSError, subprocess.SubprocessError) as e:
        return [_unverified("DRILL003", "hook execution", str(e))]
    finally:
        canary.unlink(missing_ok=True)


# --------------------------------------------------------------- API drills --

def _slug(root: pathlib.Path) -> str | None:
    try:
        r = subprocess.run(["git", "remote", "get-url", "origin"], cwd=root,
                           capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?\s*$", r.stdout.strip())
    return m.group(1) if m else None


def _get(path: str, token: str):
    """-> (payload, error). Never raises; an unreachable API is 'unverified'."""
    req = urllib.request.Request(
        f"{API}{path}",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "carabiner"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, str(e)


def github_controls(root: pathlib.Path) -> list[Finding]:
    # Token from the environment only. There is deliberately no --token flag:
    # argv is world-readable via /proc and CI logs echo commands.
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    slug = _slug(root)
    if not slug:
        return [_unverified("DRILL010", "GitHub controls",
                            "no GitHub remote found")]
    if not token:
        return [_unverified("DRILL010", "GitHub controls",
                            "set $GITHUB_TOKEN to let the drill check push "
                            "protection, branch protection and token defaults")]

    out: list[Finding] = []
    repo, err = _get(f"/repos/{slug}", token)
    if err:
        return [_unverified("DRILL010", "GitHub controls", err)]

    # DRILL011 -- push protection: the control that stops the secret before it
    # ever reaches the server.
    sec = (repo.get("security_and_analysis") or {})
    pp = ((sec.get("secret_scanning_push_protection") or {}).get("status"))
    if pp is None:
        out.append(_unverified("DRILL011", "secret scanning push protection",
                               "not reported for this repository"))
    elif pp != "enabled":
        out.append(_finding(
            "DRILL011", "high", "secret scanning push protection is disabled",
            "Settings -> Code security -> enable push protection; it blocks the "
            "push rather than telling you afterwards", snippet=str(pp)))

    # DRILL012 -- the default workflow token. CI004 checks what a workflow
    # declares; only the API says what it inherits when it declares nothing.
    perms, err = _get(f"/repos/{slug}/actions/permissions/workflow", token)
    if err:
        out.append(_unverified("DRILL012", "default workflow permissions", err))
    elif perms.get("default_workflow_permissions") == "write":
        out.append(_finding(
            "DRILL012", "high",
            "the repository default GITHUB_TOKEN is read/WRITE -- every workflow "
            "without an explicit permissions block runs with write access",
            "Settings -> Actions -> set the default to read-only and widen per "
            "job", snippet="default_workflow_permissions: write"))

    # DRILL013 -- protection on the default branch, and whether it is real.
    branch = repo.get("default_branch") or "main"
    prot, err = _get(f"/repos/{slug}/branches/{branch}/protection", token)
    if err == "HTTP 404":
        out.append(_finding(
            "DRILL013", "high",
            f"the default branch '{branch}' has no protection rule -- CI cannot "
            "gate what can be pushed to directly",
            "require a PR and at least one passing status check before merge"))
    elif err:
        out.append(_unverified("DRILL013", "branch protection", err))
    else:
        checks = ((prot.get("required_status_checks") or {}).get("contexts")
                  or (prot.get("required_status_checks") or {}).get("checks") or [])
        if not checks:
            out.append(_finding(
                "DRILL014", "high",
                f"'{branch}' is protected but requires NO status checks -- the "
                "security workflow runs, fails, and the PR merges anyway",
                "mark the security job a required check; a workflow that cannot "
                "block a merge is a notification, not a gate"))
        if (prot.get("allow_force_pushes") or {}).get("enabled"):
            out.append(_finding(
                "DRILL015", "medium",
                f"force pushes are allowed to '{branch}'",
                "disable force pushes; they rewrite the history your audit trail "
                "depends on"))
        if not (prot.get("enforce_admins") or {}).get("enabled"):
            out.append(_finding(
                "DRILL016", "low",
                f"branch protection on '{branch}' does not apply to admins",
                "enable 'Do not allow bypassing the above settings' -- a rule "
                "with exceptions is a default, not a control"))
    return out


def run(root: pathlib.Path, offline: bool = False) -> list[Finding]:
    out = hook_fires(root)
    if offline:
        out.append(_unverified("DRILL010", "GitHub controls",
                               "--offline was requested"))
    else:
        out.extend(github_controls(root))
    return out
