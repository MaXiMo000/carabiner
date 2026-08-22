# carabiner

> A carabiner is the piece of gear that locks the system together and is rated
> to catch a fall. It is also the only piece you check *before* you need it.

Make any repository secure by default in one command, keep it that way, and
prove the protections actually fire.

**→ [maximo000.github.io/carabiner](https://maximo000.github.io/carabiner/)**

```bash
pip install carabiner-sec        # the command it installs is `carabiner`
```

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
tracked, not deleted — and `--expires 90` puts a deadline on it, because
without one "accepted" quietly means "forever".

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
across engines, keeping the worse severity — two scanners reporting one CVE is
one finding, and a developer shown the same problem twice trusts the tool less
each time. Emitted as SARIF so findings land in the PR Security tab.

## Adopt it

```bash
carabiner init          # detect, configure, ratchet. Once per repo.
carabiner scan          # what is new. Pre-commit and CI. Under 2s.
carabiner scan --all    # every engine, whole history. CI cadence.
carabiner drill         # prove the controls fire. After init, and weekly.
carabiner debt          # what you carry, since when, and what is overdue.
carabiner lock --expires 90   # accept it, but only for 90 days.
```

`init` prints every file it will write before writing it, and `--dry-run` writes
nothing. A security tool that silently rewrites your config has no business
asking to be trusted.

## In CI

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: MaXiMo000/carabiner@v0.1.5
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: carabiner.sarif
```

Findings land in the PR's Security tab, tracked across commits by the same
stable fingerprint the ratchet uses — so reformatting a file does not report
everything as new.

Add `args: --all --summary carabiner.md` and post that file as a PR comment to
get one short line per PR — `2 new · 1 fixed · 340 accepted` — instead of the
whole backlog restated every time.

## Anywhere else — GitLab CI, Jenkins, CircleCI

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/maximo000/carabiner:0.1.5 scan --all
```

The image bundles gitleaks and osv-scanner, runs as a non-root user, pins its
base by digest, checksum-verifies every binary it downloads, and ships with a
build-provenance attestation.

## As a pre-commit hook

```yaml
repos:
  - repo: https://github.com/MaXiMo000/carabiner
    rev: v0.1.5
    hooks:
      - id: carabiner
```

The fast path is budgeted under 2 seconds. Anything slower gets uninstalled from
pre-commit inside a week — the observed failure mode of every pre-commit
security tool — so the budget is enforced by a test, not a goal.

## Engines

| Engine | Checks | Needs |
|---|---|---|
| `ci` — GitHub Actions | CI001 `pull_request_target` + PR-head checkout · CI002 script injection from `github.event` into `run:` · CI003 unpinned actions · CI004/5 token blast radius · CI007 self-hosted runners | nothing |
| `ci` — GitLab CI | GL001 script injection from a merge-request title or branch name · GL002 unpinned remote `include:` · GL003 mutable image and service tags | nothing |
| `repo` | REPO001 `.gitignore` gaps · REPO002 committed key material · REPO003 no disclosure policy · REPO004 credentials in git remotes | nothing |
| `secrets` | working tree every commit; history behind `--all` and one severity higher, because deleting the file is not remediation | `gitleaks` |
| `deps` | lockfile advisories across PyPI, npm, Go, Maven, crates.io and more; ids normalised to CVE so two scanners cannot report one problem twice | `osv-scanner` |

A missing scanner degrades to an install hint, never a crash. And a scanner that
*fails* produces a finding saying the check did not happen — a tool that errors
is not a repo that is clean.

## Known limits, stated plainly

- The `ci` engine covers GitHub Actions and GitLab CI. Jenkins, CircleCI and
  Bitbucket get the other engines and nothing from that one.
- The published Docker image is `linux/amd64` only.

Tested on Linux and Windows, Python 3.10 and 3.13. `--offline` is enforced by a
test that blocks socket creation and asserts a full scan still completes — the
claim is checked, not documented.

## What it will never do

No SaaS. No dashboard. No account. No telemetry. No AI. No auto-rewriting your
security config. And it never reimplements a scanner that already exists —
the value is the ratchet, the drill, and the normalized model.

Dependencies: PyYAML and the standard library. That is the whole list, on
purpose — every dependency is a package a security auditor now implicitly
vouches for.

## License

MIT. See [SECURITY.md](SECURITY.md) to report a vulnerability.
