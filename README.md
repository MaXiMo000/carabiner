# carabiner

> A carabiner is the piece of gear that locks the system together and is rated
> to catch a fall. It is also the only piece you check *before* you need it.

Make any repository secure by default in one command, keep it that way, and
prove the protections actually fire.

```
$ carabiner scan
  CRITICAL CI001  .github/workflows/pr.yml
           job 'hello' runs on pull_request_target and checks out the PR head
           -- untrusted code runs with your secrets
           fix: use `pull_request`, or split into an untrusted build job and a
                privileged job that never checks out the head

  2 new, 340 accepted (carabiner debt)   0.02s
```

## Why another one

Every scanner already exists and is free — gitleaks, Trivy, Semgrep,
OSV-Scanner. They are excellent and carabiner does not reimplement any of them.
And the median repository runs none of them, for three specific reasons:

1. **Setup is per-tool, per-language, per-CI.** A two-hour job you do once.
2. **The first run returns 400 findings and everyone gives up.** The gate gets
   turned off, and the tool now has *negative* value — it looks like coverage.
3. **A configured control is not a working control.** The hook is in
   `.pre-commit-config.yaml` but nobody ran `pre-commit install`.

## The three things that aren't a wrapper

**The ratchet.** `carabiner lock` accepts every existing finding into a
baseline. From then on CI fails only on what's *new*. You can adopt this in a
ten-year-old repo on a Tuesday afternoon, and security only tightens from
there. Accepted findings stay visible via `carabiner debt` — the debt is
tracked, not deleted.

Findings are fingerprinted on `(engine, rule, path, normalized snippet)`, never
on line numbers. Adding an import at the top of a file must not resurrect 400
accepted findings; that's why baseline features elsewhere get abandoned.

**The drill.** `carabiner drill` doesn't read configuration — it attacks the
repo. It plants a private key and checks the installed pre-commit hooks actually
stop it; asks GitHub whether push protection is really on; and verifies the
security workflow is a *required* check rather than one that runs, fails, and
merges anyway.

```
$ carabiner drill
  HIGH     DRILL002  pre-commit hooks are configured but NOT installed --
                     the config looks right and nothing runs
  HIGH     DRILL012  the repository default GITHUB_TOKEN is read/WRITE
```

A drill that could not run **never reports as passing** — no token, no network,
no `pre-commit` binary all produce "could NOT be verified", not a green check.
Unverified is not secure. Drills are also never ratcheted: a control that
stopped working is a regression today, not pre-existing debt to accept.

> Most security tools check your configuration. carabiner checks your defenses
> by trying to get past them.

**One normalized model.** Every engine reports into one `Finding`. Deduplicated
across engines — Trivy and OSV-Scanner both read your lockfile, and a developer
shown the same CVE twice trusts the tool less each time — and emitted as SARIF
so findings land in the PR Security tab.

## Status

Phase 0. Native engines only (`ci`, `repo`) — no external tools required, and
they still find real problems. Scanner wrappers are Phase 1, the drill is
Phase 3. See [PLAN.md](PLAN.md).

```bash
python3 -m carabiner.cli scan --root /path/to/repo
python3 -m carabiner.cli lock --root /path/to/repo   # ratchet
python3 -m carabiner.cli debt --root /path/to/repo
```

## Engines

| Engine | Checks | Needs |
|---|---|---|
| `ci` (GitHub Actions) | CI001 `pull_request_target` + PR-head checkout · CI002 script injection from `github.event` into `run:` · CI003 unpinned actions · CI004/5 token blast radius · CI007 self-hosted runners | nothing |
| `ci` (GitLab CI) | GL001 script injection from merge-request title or branch name · GL002 unpinned remote `include:` · GL003 mutable image/service tags | nothing |
| `repo` | REPO001 `.gitignore` gaps · REPO002 committed key material · REPO003 no SECURITY.md · REPO004 credentials in git remotes | nothing |

## What it will never do

No SaaS. No dashboard. No account. No telemetry. No AI. No auto-rewriting your
security config. And it never reimplements a scanner that already exists —
the value is the ratchet, the drill, and the normalized model.

Dependencies: PyYAML and the standard library. That is the whole list, on
purpose — every dependency is a package a security auditor now implicitly
vouches for.
