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
each time. Emitted as SARIF so findings land in the PR Security tab — which is exactly why `snippet` is scrubbed in `Finding.__post_init__` rather than at each call site: a credential that reaches a finding reaches a code-scanning alert. Token-shaped runs are shortened to first4…last4, and a credential in a URL is removed outright. That second rule deliberately over-reaches, because a redactor is the one place in this tool where a false positive is cheaper than a false negative.

`--json`'s shape is [`schema/finding.schema.json`](schema/finding.schema.json)
— versioned (`schema_version`, bumped only on a breaking change), so a
downstream consumer isn't trusting an implicit contract. This is what
[invariant](https://github.com/MaXiMo000/invariant)'s `receipt` check type
demonstrates for a different pair of tools: read one project's evidence,
assert on it from another.

## Adopt it

```bash
carabiner init          # detect, configure, ratchet. Once per repo.
carabiner scan          # what is new. Pre-commit and CI.
carabiner scan --diff   # only what this commit touches. The pre-commit path.
carabiner scan --all    # every engine, whole history. CI cadence.
carabiner drill         # prove the controls fire. After init, and weekly.
carabiner scan --info   # also list informational findings (hidden by default).
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
  - uses: MaXiMo000/carabiner@v0.2.1
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
docker run --rm -v "$PWD:/repo:ro" ghcr.io/maximo000/carabiner:0.2.1 scan --all
```

The image bundles gitleaks and osv-scanner, runs as a non-root user, pins its
base by digest, checksum-verifies every binary it downloads, and ships with a
build-provenance attestation.

## As a pre-commit hook

```yaml
repos:
  - repo: https://github.com/MaXiMo000/carabiner
    rev: v0.2.1
    hooks:
      - id: carabiner
```

The fast path measured **0.41s–0.83s** across ten well-known repositories
(requests, flask, fastapi, express, axios, prettier, gin, ripgrep, bat) and
**2.3s** on a 302MB monorepo (next.js). Anything slower gets uninstalled from
pre-commit inside a week, which is why `deps` runs only under `--all`: its OSV
lookups cost 0.7–9.3s on those same repos and are the only thing that ever blew
the budget.

## Engines

| Engine | Checks | Needs |
|---|---|---|
| `ci` — GitHub Actions | CI001 `pull_request_target` + PR-head checkout · CI002 script injection from `github.event` into `run:` · CI003 unpinned actions · CI004/5 token blast radius · CI006 secrets in reach of checked-out contributor code · CI007 self-hosted runners · CI008 `persist-credentials` left on · CI009 `secrets: inherit` across repos · CI010 cache poisoning · CI011 ships artefacts on a tag without creating a Release | nothing |
| `ci` — GitLab CI | GL001 script injection from a merge-request title or branch name · GL002 unpinned remote `include:` · GL003 mutable image and service tags | nothing |
| `repo` | REPO001 `.gitignore` gaps · REPO002 committed key material · REPO003 no disclosure policy · REPO004 credentials in git remotes | nothing |
| `ci` — Jenkins / CircleCI / Azure | JEN001 Groovy interpolation into `sh` · JEN002 literal credential in a pipeline · CIR001 `@volatile` orb · CIR002 pipeline parameter into a run step · AZP001 branch name into a script | nothing |
| `kubernetes` | K8S001 `hostNetwork`/`hostPID`/`hostIPC` · K8S002 privileged container · K8S003 privilege escalation · K8S004 nothing preventing root · K8S005 a literal credential in `env` | nothing |
| `docker` | DOCK001 final stage never drops root · DOCK002 untagged or `:latest` base · DOCK003 credential baked into `ARG`/`ENV` · DOCK004 remote script piped into a shell · DOCK005 TLS verification disabled at build time · DOCK006 copies the whole build context with no `.dockerignore`, so `.git` and every secret ever committed to it ship inside the image | nothing |
| `secrets` | working tree every commit; history behind `--all` and one severity higher, because deleting the file is not remediation | `gitleaks` |
| `deps` | lockfile advisories across PyPI, npm, Go, Maven, crates.io and more; ids normalised to CVE so two scanners cannot report one problem twice | `osv-scanner` |

**Severity is calibrated against real repositories.** Across 60 public projects
the default output is a median of **9 findings per repo**; another ~800
informational ones are counted but not listed until you ask with `--info`. A
version tag on an action is informational; a *moving branch* in someone else's
repository is not. A private key under `tests/` is reported lower than one in
`config/`.

**Re-run since, on a different sample.** 30 popular, unrelated public repos —
Python, JS/TS, Go, Rust, Ruby, Java — shallow-cloned fresh and scanned with
`--all`, gitleaks and osv-scanner installed. 28 of 30 produced at least one new
finding; `expressjs/express` and `spf13/cobra` scanned clean. Median scan time
was **10.5s**, osv-scanner's live lookup included. The single largest number —
3,339, on `facebook/react` — came from a sprawling, decade-old monorepo with
dozens of workflow files and an equally old lockfile: real surface area, not a
scanner malfunction.

The dominant rule by far was `SECRET-*`, on all but a handful of the 30 —
almost none of it a live credential. `psf/requests` ships four real TLS
private keys under `tests/certs/`, used by its own mTLS test suite; the
`tests/` demotion above puts each at `medium` in the working tree, `high` only
once history is in scope, exactly as designed. That is the pattern across the
sample: a raw secrets scanner flags something in nearly every mature codebase,
and almost all of it is a fixture, an example JWT in a doc, or a placeholder —
precisely the noise the ratchet exists to keep out of a team's way, not a
one-off blind spot in this particular tool. The signal worth a maintainer's
time was elsewhere: unpinned actions, a missing top-level `permissions:`
block, and dependency advisories on old transitive pins, all real and all
still there after the fixtures are filtered out.

**A repository referencing its own action is not reported at all.** Moving that
tag needs push access to the repository being scanned — the same access that
would let someone rewrite the workflow outright — so no boundary is crossed and
there is nothing to pin against. It is also the universal shape for an action
repository: the only honest way to test the tag your users consume is to consume
it. CI003 resolves the repository from `$GITHUB_REPOSITORY`, falling back to the
origin remote. The exemption is that repository, never the action: the same
`owner/action@v1` referenced from anywhere else is a third party and still
reported.

A missing scanner degrades to an install hint, never a crash. And a scanner that
*fails* produces a finding saying the check did not happen — a tool that errors
is not a repo that is clean. That rule covers a native engine raising too, not
just a wrapped one exiting non-zero: one engine's bug is reported and every
other engine still runs, rather than the whole scan going down with it.

## Known limits, stated plainly

- The `ci` engine covers GitHub Actions and GitLab CI. Jenkins, CircleCI and
  Bitbucket get the other engines and nothing from that one.
- The published Docker image is `linux/amd64` only.
- The fast path scans the whole working tree, not just changed files, so a very
  large monorepo can exceed the 2s target.
- The `secrets` engine's working-tree scan skips `node_modules`, `.venv`,
  `__pycache__`, `dist`, `build`, `vendor`, `target` and `.git` — generated or
  vendored content that has no business being read as source, and that
  gitleaks' non-git scan mode has no `.gitignore` of its own to tell it to
  skip. Measured, not theoretical: a compiled `.pyc` embedded a string this
  project's own `drill.py` deliberately split across a concatenation to keep
  out of a scanner's sight in the `.py` source, because CPython folds that
  concatenation back into one literal at compile time. If one of those
  directories is ever *actually committed* to a repo, `--all`'s history scan
  still finds what's in it — a real secret checked into `node_modules` is a
  problem regardless of what carabiner shows on a pre-commit run.

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
