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
#
# `+` between two literals is not enough: CPython constant-folds it at compile
# time, so the "split" marker still lands whole in this module's own compiled
# .pyc as a single marshaled string -- gitleaks matched exactly that, in
# carabiner/__pycache__/drill.*.pyc, on carabiner's own repo. `str.join` is a
# runtime call the compiler does not fold, so the halves stay separate all the
# way through compilation. Verified with `dis.dis`, not assumed.
_CANARY_MARKER = "".join(("-----BEGIN", " RSA PRIVATE KEY-----"))
_CANARY_BODY = "".join(("MIIEowIBAAKCAQEA", "cArAbInErDrIlLnOtArEaLkEy0123456789" * 4))
CANARY = "".join((_CANARY_MARKER, "\n", _CANARY_BODY, "\n-----END", " RSA PRIVATE KEY-----\n"))


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
            body = exclude.read_text(encoding="utf-8", errors="replace") if exclude.exists() else ""
            if canary.name not in body:
                exclude.write_text(body.rstrip("\n") + f"\n{canary.name}\n", encoding="utf-8")
        canary.write_text(CANARY, encoding="utf-8")
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

def origin_slug(root: pathlib.Path) -> str | None:
    """`owner/repo` from the origin remote.

    Also read by the CI engine, which has to know which repository it is
    scanning before it can tell a stranger's action from this repository's
    own. Public for that reason rather than because the drills needed it.
    """
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
    slug = origin_slug(root)
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

    # DRILL024 -- secret scanning itself, not just its push-time block: with
    # it off, a secret already in the history is never reported at all.
    ss = ((sec.get("secret_scanning") or {}).get("status"))
    if ss == "disabled":
        out.append(_finding(
            "DRILL024", "medium", "secret scanning is disabled",
            "Settings -> Code security -> enable secret scanning; it reports "
            "credentials already in the history, which push protection never sees",
            snippet="secret_scanning: disabled"))

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
    if not err and perms.get("can_approve_pull_request_reviews"):
        out.append(_finding(
            "DRILL023", "high",
            "workflows can approve pull requests -- a required review can be "
            "satisfied by a bot, including on a PR that changed the workflow",
            "Settings -> Actions -> uncheck 'Allow GitHub Actions to create and "
            "approve pull requests'", snippet="can_approve_pull_request_reviews: true"))

    # DRILL017 -- Dependabot alerts: the cheapest control there is, and one
    # people believe is on because the config file exists.
    alerts, err = _get(f"/repos/{slug}/vulnerability-alerts", token)
    if err == "HTTP 404":
        out.append(_finding(
            "DRILL017", "medium", "Dependabot vulnerability alerts are disabled",
            "Settings -> Code security -> enable Dependabot alerts; a "
            "dependabot.yml in the repo does not switch them on"))
    elif err and err != "HTTP 204":
        out.append(_unverified("DRILL017", "Dependabot alerts", err))

    # DRILL018 -- a SARIF upload that fails is a Security tab that stays empty
    # while CI stays green. Ask what actually arrived.
    analyses, err = _get(f"/repos/{slug}/code-scanning/analyses?per_page=1", token)
    if err == "HTTP 404":
        out.append(_finding(
            "DRILL018", "medium",
            "no code scanning results have ever been received -- if a workflow "
            "uploads SARIF, that upload is failing silently",
            "check the upload-sarif step; a rejected SARIF file does not fail "
            "the job that produced it"))
    elif err:
        out.append(_unverified("DRILL018", "code scanning results", err))
    elif isinstance(analyses, list) and analyses:
        created = str(analyses[0].get("created_at", ""))[:10]
        tool = ((analyses[0].get("tool") or {}).get("name")) or "?"
        out.append(_finding(
            "DRILL018", "info",
            f"code scanning last received results from {tool} on {created}",
            "informational -- confirms the upload path works"))

    # DRILL013 -- protection on the default branch, and whether it is real.
    # Two mechanisms can protect a branch: classic protection rules and
    # rulesets. Reading only the classic endpoint called a branch protected
    # by a ruleset "unprotected" -- a false HIGH on exactly the repos that
    # had moved to the newer mechanism.
    branch = repo.get("default_branch") or "main"
    prot, prot_err = _get(f"/repos/{slug}/branches/{branch}/protection", token)
    rules, rules_err = _get(f"/repos/{slug}/rules/branches/{branch}", token)
    if prot_err and prot_err != "HTTP 404":
        out.append(_unverified("DRILL013", "branch protection", prot_err))
        return out
    if rules_err and rules_err != "HTTP 404":
        rules = []  # classic protection alone is still checkable
    policy = branch_policy(None if prot_err else prot, rules if isinstance(rules, list) else [])
    if policy is None:
        out.append(_finding(
            "DRILL013", "high",
            f"the default branch '{branch}' has no protection rule or ruleset -- CI "
            "cannot gate what can be pushed to directly",
            "require a PR and at least one passing status check before merge"))
        return out

    where = f"'{branch}' ({policy['source']})"
    if not policy["checks"]:
        out.append(_finding(
            "DRILL014", "high",
            f"{where} requires NO status checks -- the security workflow runs, "
            "fails, and the PR merges anyway",
            "mark the security job a required check; a workflow that cannot "
            "block a merge is a notification, not a gate"))
    if not policy["requires_pr"]:
        out.append(_finding(
            "DRILL019", "high",
            f"{where} doesn't require a pull request -- changes can be pushed "
            "straight to it, past every review and check",
            "require a pull request before merging"))
    elif policy["approvals"] == 0:
        out.append(_finding(
            "DRILL020", "medium",
            f"{where} requires a pull request but zero approvals -- authors can "
            "merge their own changes",
            "require at least one approving review"))
    if policy["force_push_allowed"]:
        out.append(_finding(
            "DRILL015", "medium",
            f"force pushes are allowed to '{branch}'",
            "disable force pushes; they rewrite the history your audit trail "
            "depends on"))
    if policy["admins_enforced"] is False:
        out.append(_finding(
            "DRILL016", "low",
            f"branch protection on '{branch}' does not apply to admins",
            "enable 'Do not allow bypassing the above settings' -- a rule "
            "with exceptions is a default, not a control"))

    # DRILL021/022 -- CODEOWNERS that looks like a gate and isn't. GitHub
    # silently ignores a line with an unknown owner or bad syntax, and the
    # whole file only gates anything when code-owner review is required.
    codeowners = next((c for c in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
                       if (root / c).is_file()), None)
    if codeowners:
        errors, err = _get(f"/repos/{slug}/codeowners/errors", token)
        if err:
            out.append(_unverified("DRILL021", "CODEOWNERS validity", err))
        elif (errors or {}).get("errors"):
            lines = [f"line {e.get('line')}: {e.get('message', e.get('kind', '?')).splitlines()[0]}"
                     for e in errors["errors"]][:5]
            out.append(_finding(
                "DRILL021", "medium",
                f"{codeowners} has {len(errors['errors'])} line(s) GitHub ignores "
                "-- those paths have no code owner at all",
                "fix the owners GitHub can't resolve (a typo'd team, a user "
                "without write access)", snippet="; ".join(lines)))
        if not policy["code_owner_review"]:
            out.append(_finding(
                "DRILL022", "medium",
                f"{codeowners} exists but {where} doesn't require code-owner "
                "review -- the owners are notified, never required",
                "enable 'Require review from Code Owners'"))
    return out


def branch_policy(prot: dict | None, rules: list) -> dict | None:
    """One view of a branch's protection, from classic protection (the
    /protection response) and/or the rulesets that apply to it (the
    /rules/branches response). None if neither protects it. Where both do,
    the stronger requirement wins -- GitHub enforces both.

    admins_enforced is None for a ruleset-only branch: its bypass list isn't
    in the rules response, so it's reported as unknown, never as fine."""
    if not prot and not rules:
        return None
    sources = [name for name, present in (("protection rule", prot), ("ruleset", rules)) if present]
    policy = {"source": " + ".join(sources), "requires_pr": False, "approvals": 0,
              "code_owner_review": False, "checks": [], "force_push_allowed": True,
              "admins_enforced": None}
    if prot:
        reviews = prot.get("required_pull_request_reviews")
        if reviews is not None:
            policy["requires_pr"] = True
            policy["approvals"] = reviews.get("required_approving_review_count", 0) or 0
            policy["code_owner_review"] = bool(reviews.get("require_code_owner_reviews"))
        rsc = prot.get("required_status_checks") or {}
        policy["checks"] += list(rsc.get("contexts") or []) + [
            c.get("context") for c in rsc.get("checks") or [] if c.get("context")]
        policy["force_push_allowed"] = bool((prot.get("allow_force_pushes") or {}).get("enabled"))
        policy["admins_enforced"] = bool((prot.get("enforce_admins") or {}).get("enabled"))
    for rule in rules:
        params = rule.get("parameters") or {}
        kind = rule.get("type")
        if kind == "pull_request":
            policy["requires_pr"] = True
            policy["approvals"] = max(policy["approvals"], params.get("required_approving_review_count", 0) or 0)
            policy["code_owner_review"] |= bool(params.get("require_code_owner_review"))
        elif kind == "required_status_checks":
            policy["checks"] += [c.get("context") for c in params.get("required_status_checks") or []
                                 if c.get("context")]
        elif kind == "non_fast_forward":
            policy["force_push_allowed"] = False
    return policy


def run(root: pathlib.Path, offline: bool = False) -> list[Finding]:
    out = hook_fires(root)
    if offline:
        out.append(_unverified("DRILL010", "GitHub controls",
                               "--offline was requested"))
    else:
        out.extend(github_controls(root))
    return out
