# carabiner — plan

> A carabiner is the piece of gear that locks the system together and is rated
> to catch a fall. It is also the only piece you check *before* you need it.

One command makes any repository — any language, any stack — secure by default,
and keeps it that way. Then it proves the protections actually fire.

**Name check before release:** PyPI, npm, GitHub org, and `brew`. Fallbacks in
priority order: `belay`, `firedrill`, `pawl`. CLI keeps a two-letter alias `cb`.

---

## 1. The problem, stated precisely

Every scanner in this space already exists and is free. gitleaks finds secrets.
Trivy finds vulnerable containers. Semgrep finds bad code. OSV-Scanner finds bad
dependencies. They are excellent and you should never reimplement them.

And the median repository on GitHub runs **none of them**.

Not because developers don't care. Because of three specific, fixable failures:

**Failure 1 — setup is per-tool, per-language, per-CI.**
Securing one repo means reading five READMEs, writing four config files, and
knowing which tools apply to your stack. It's a two-hour job you do once and
never repeat, so it never happens on repo number two.

**Failure 2 — the first run returns 400 findings and everybody gives up.**
This is the real killer. Point any scanner at a codebase older than a year and
it produces a wall of findings about code nobody has touched in three years.
The team cannot fix 400 things this sprint, so they turn the gate off, and the
tool now has *negative* value: it looks like coverage and provides none.

**Failure 3 — a configured control is not a working control.**
The hook is in `.pre-commit-config.yaml` but nobody ran `pre-commit install`,
so it never executes. The workflow exists but `permissions:` is unset, so it
runs with a write-scoped token. Branch protection is "on" but admins can force
push. Everyone checks that security is *configured*. Nobody checks that it
*fires*.

carabiner attacks all three, in that order of importance.

---

## 2. The three things that make it not-a-wrapper

Orchestrating scanners is commodity. These three are the product.

### 2.1 The ratchet — installable in a legacy repo on a Tuesday afternoon

On `carabiner init`, the tool runs everything once and writes every existing
finding into `.carabiner/baseline.json` as **accepted**. From that moment CI
fails only on findings that are **new**.

The consequence is the whole pitch: you can adopt carabiner in a ten-year-old
codebase without a cleanup sprint, and security can only get tighter from there.
Never looser — a ratchet turns one way.

Baseline entries carry a `first_seen` commit and an optional `expires` date, so
"accepted" doesn't silently mean "forever." `carabiner debt` prints the
outstanding backlog, sorted by severity and age. The debt is *visible* instead
of being deleted by a `--no-verify`.

Findings are matched by a **stable fingerprint** — `(engine, rule, path,
normalized_snippet)` — not by line number. Reformatting a file, or adding an
import at the top, must not resurrect 400 accepted findings. This is the single
hardest engineering problem in the tool and the reason most baseline features
in other tools are unusable.

### 2.2 The drill — proving the control fires

`carabiner drill` does not read configuration. It attacks the repo:

| Drill | What it does | What it catches |
|---|---|---|
| `secret-hook` | writes a canary — a syntactically valid, non-live AWS key — to a temp file and runs the installed pre-commit hook against it | hook configured but never `install`ed; hook silently erroring; gitleaks binary missing on this machine |
| `push-protection` | queries the GitHub API for secret-scanning push protection state | "we have secret scanning" that was never enabled |
| `branch-protection` | queries required reviews, required checks, admin enforcement, force-push allowance | protection that admins bypass |
| `workflow-token` | inspects the effective `GITHUB_TOKEN` permissions of each workflow | default write-all tokens — the most exploited CI misconfiguration there is |
| `ci-gate` | confirms the security workflow is a **required** check, not merely present | the workflow that runs, fails, and merges anyway |

The canary is generated with a documented non-routable prefix and asserted
never to be a live credential. It is written to a temp path, never committed,
and deleted in a `finally`. That constraint is a test, not a comment.

**This is the unique claim, and it belongs on the first screen of the README:**
*Most security tools check your configuration. carabiner checks your defenses by
trying to get past them.*

### 2.3 One normalized findings model

gitleaks, Trivy, Semgrep, pip-audit and npm audit each report in their own
shape, and two of them will report the same CVE twice. carabiner normalizes
everything into one `Finding`, deduplicates across engines, and emits:

- a human table (default),
- **SARIF** → GitHub code scanning, so findings land in the PR's Security tab,
- JUnit XML for non-GitHub CI,
- JSON for anything else.

Deduplication is a real feature: Trivy and OSV-Scanner both read your lockfile,
and a developer shown the same CVE twice trusts the tool less each time.

---

## 3. What it will never do

Written down so it stays not-done.

- **Never reimplement a scanner.** gitleaks is better at secrets than anything
  written here will ever be. carabiner orchestrates, normalizes, ratchets and
  verifies. The one exception is §4.4, which nothing else covers well.
- **No SaaS, no dashboard, no account.** It is a binary and a config file.
  Findings never leave the machine unless the user pipes them somewhere.
- **No auto-fix of security controls.** It writes suggestions and, on `init`,
  writes config files it shows you first. It does not silently rewrite your
  workflows.
- **No AI.** A security tool that occasionally invents a finding is worse than
  none.
- **No agent, no daemon, no telemetry.** "Bot" means it runs in CI, not that it
  phones home.

---

## 4. Engine roster

Each engine is a module exposing `available() -> bool` and `run(ctx) ->
list[Finding]`. Missing tools degrade to a printed install hint, never a crash.
A repo with zero external tools installed still gets §4.4 and §4.5, which is
what makes the first run useful rather than a shopping list.

### 4.1 secrets — wraps `gitleaks`
Working tree and full history. History matters: a secret deleted in a later
commit is still in the pack file and still compromised. `init` warns loudly if
history findings exist, because the remediation is rotation, not deletion.

### 4.2 deps — wraps `osv-scanner`

**Revised during Phase 1, down from four tools to one.** osv-scanner reads
lockfiles for PyPI, npm, Go, Maven, crates.io, RubyGems and more out of the same
OSV database pip-audit and npm audit draw from, so shipping four parsers is four
times the maintenance for the same findings. Add pip-audit only if someone
reports a case osv-scanner genuinely misses.

Advisory ids are normalized to a canonical form (CVE, then GHSA, then the native
id) before becoming findings. Without that, one vulnerability reported by two
scanners is two fingerprints and the developer sees the same problem twice --
which costs trust faster than a missed finding does.

### 4.3 container — wraps `trivy`
Only if a `Dockerfile` or `compose.yml` exists. Image CVEs, plus Dockerfile
misconfiguration (running as root, `latest` base tags, secrets in `ENV`).

### 4.4 ci — **native, no wrapper. This is our own code.**

**GitLab pulled forward from Phase 5.** Covering one CI host made
"universal" untrue in the place the tool is most original: a GitLab repo
interpolating a merge-request title into `script:` has the identical
vulnerability to CI002 and got nothing. The engine now dispatches by host
(`_github.py`, `_gitlab.py`) and is named `ci` because that is what it
checks; rule prefixes CI*/GL* keep the host visible in every finding.

GitHub Actions is the most commonly exploited and least commonly scanned part
of a modern repo, and it is plain YAML. Native checks:

| ID | Finding | Why it matters |
|---|---|---|
| CI001 | `pull_request_target` with a checkout of the PR head | The canonical way third-party PRs steal your secrets. Critical. |
| CI002 | `${{ github.event.* }}` interpolated into a `run:` block | Script injection — a PR *title* becomes shell on your runner |
| CI003 | Action referenced by tag or branch, not a commit SHA | Tags are mutable; a compromised action re-tags and you run it. Not reported when the action is *this* repository's own — moving that tag needs the push access that could rewrite the workflow anyway |
| CI004 | No top-level `permissions:` block | Falls back to the repo default, historically write-all |
| CI005 | `permissions: write-all` or `contents: write` without cause | Blast radius |
| CI006 | Secret passed to a step that also runs untrusted code | Exfiltration path |
| CI007 | Self-hosted runner on a public repo | Anyone's PR executes on your hardware |
| CI008 | `persist-credentials` left on with a subsequent untrusted step | Token theft |

Prior art to read before building: `zizmor` covers part of this space and is
good. Read it, and either differentiate or wrap it — do not accidentally
duplicate it. If wrapping is the honest answer, wrap it and say so.

### 4.5 repo — native
`.gitignore` covers `.env`/`*.pem`/credential patterns; `SECURITY.md` exists;
a `LICENSE` exists; lockfiles are committed; no world-readable key material in
the tree; `.git/config` has no embedded credentials.

Cheap, instant, always available, and catches the failure that actually loses
people their AWS bill.

### 4.6 code — wraps `semgrep --config auto`, diff-only in CI
Slowest engine. Off by default in the pre-commit profile, on in the CI profile.

---

## 5. Interface

Speed determines cadence. Cadence determines whether a tool survives.

| Command | Target | Cadence |
|---|---|---|
| `carabiner init` | writes config, runs everything, ratchets the baseline | once per repo |
| `carabiner scan` | fast engines on changed files only, **< 2s** | pre-commit, every commit |
| `carabiner scan --all` | every engine, whole tree | CI, every PR |
| `carabiner drill` | verifies the controls fire | CI weekly, and after `init` |
| `carabiner lock` | re-ratchet: accept current findings deliberately | when you consciously accept debt |
| `carabiner debt` | print accepted findings by severity and age | sprint planning |
| `carabiner report --sarif` | machine output | CI |

**The 2-second budget on `scan` is a hard requirement, not a goal.** Anything
slower is uninstalled from pre-commit inside a week — that is the observed
failure mode of every pre-commit security tool. It is enforced by a test that
fails the build if the fast path exceeds budget on the fixture repo.

### Config — `.carabiner.yml`

```yaml
version: 1
profile: standard          # minimal | standard | paranoid
engines:
  secrets:   {enabled: true,  fail_on: medium}
  deps:      {enabled: true,  fail_on: high}
  ci:        {enabled: true,  fail_on: high}
  repo:      {enabled: true,  fail_on: medium}
  container: {enabled: auto}
  code:      {enabled: false}

ignore:
  - path: tests/fixtures/**
    reason: "deliberately vulnerable corpus"   # required; no reason -> rejected
```

Every suppression requires a written reason. An ignore without one is a config
error, not a warning. It is the only process the tool imposes and it is what
separates a tool people keep from a tool people route around.

---

## 6. Distribution — universal means the runtime is invisible

Reach is a packaging problem, not a code problem. Four surfaces, one codebase:

1. **GitHub Action** — `uses: <org>/carabiner@v1`. Where 90% of usage happens.
   The Python runtime is invisible here; that is the point.
2. **Docker image** — `docker run --rm -v $PWD:/repo ghcr.io/<org>/carabiner`.
   For GitLab CI, Jenkins, CircleCI, and anyone without Python.
3. **pre-commit hook** — a `.pre-commit-hooks.yaml` in the repo makes it one
   entry in someone's existing config. Highest-leverage distribution channel in
   the entire Python ecosystem.
4. **pipx / uvx** — `uvx carabiner scan` for local use.

Python is fine given surfaces 1–3 hide it. Revisit a Go rewrite only if adoption
data shows the runtime is the blocker — not before. That is a real fork in the
road worth a line in the README so contributors don't argue about it.

---

## 7. Security of carabiner itself

It is a security tool that reads your whole repository and, in drill mode, holds
a GitHub token. Its own posture is the credential.

**Findings never leave the machine.** No telemetry, no update check, no network
call except the ones an engine explicitly needs (CVE databases, the GitHub API
for drills). Every network call is listed in the README, and `--offline`
disables all of them and is tested to make zero connections.

**Secrets are never printed.** Findings carry a *fingerprint* and a redacted
snippet — first four and last four characters. The `Finding` type physically has
no field capable of holding a raw secret. A test asserts the field set, so
removing that protection requires changing the data model in a visible diff.
Console, SARIF and JSON output all go through one redactor with one test.

**Never mutates the repo without showing you first.** `init` prints every file
it will write and diffs anything that exists. `--dry-run` on everything.

**Credentials never touch argv.** Tokens come from `$GITHUB_TOKEN` or `gh auth`
only. A `--token` flag is deliberately not implemented, and the error says why:
`/proc/*/cmdline` is world-readable and CI logs echo commands.

**Least privilege in the Action.** Ships with `permissions: {contents: read,
security-events: write}` — the minimum for SARIF upload — and the README says
never to run it on `pull_request_target`. The tool that flags CI001 must not
commit CI001.

**Supply chain.** Dependencies: PyYAML and the standard library. That is the
list. Hash-pinned lockfile, `--require-hashes` in CI, PyPI trusted publishing
via OIDC (no long-lived token), Sigstore attestations, SBOM on every release,
`pip-audit` as a release gate, Actions pinned to SHAs. The project runs
carabiner on carabiner, and a finding fails its own build.

**Subprocess discipline.** Every wrapped scanner is invoked with an argument
list — never `shell=True`, never string interpolation — with a timeout and a
bounded output buffer. A repo path is attacker-controlled input in the CI
threat model; treat it that way.

**SECURITY.md** with a real contact and a 90-day coordinated disclosure policy,
present from commit one.

---

## 8. Testing strategy

Correctness is not "does it run." It is "does it find exactly the right issues
in a repo whose issues we already know."

`tests/fixtures/` holds deliberately broken repositories, one per finding class,
each with an `expected.json`:

```
tests/fixtures/
  ci_pull_request_target/     -> CI001
  ci_script_injection/        -> CI002
  ci_unpinned_action/         -> CI003
  ci_no_permissions/          -> CI004
  repo_env_not_ignored/       -> REPO001
  repo_committed_key/         -> REPO003
  clean/                      -> ZERO findings, and this is the important one
```

The suite asserts the finding set in **both directions**. A false positive fails
the build exactly as hard as a false negative, because a noisy security tool
gets disabled and a disabled tool is worse than none.

Plus:
- **Ratchet property test** — reformat a fixture file, shift every line, rename
  the file; the accepted baseline must still suppress. This is where baseline
  implementations usually break, so it is tested hardest.
- **Redaction test** — plant a canary, run every output format, assert the
  canary appears in none of them.
- **Performance test** — `scan` on the fixture repo must finish under budget.
- **Offline test** — `--offline` opens zero sockets.

---

## 9. Roadmap

Each phase is usable on its own. Nothing is scaffolding for a later phase.

### Phase 0 — the spine *(this session)*
`Finding` + fingerprint, the ratchet, the native `ci` and `repo` engines, human
output, a fixture suite. Runs with zero external tools installed and still finds
real problems.
**Exit:** `carabiner scan` on a fixture repo produces exactly the expected
findings; `clean/` produces none.

### Phase 1 — the wrappers *(week 1)*
`secrets` (gitleaks), `deps` (pip-audit / npm audit / osv-scanner), `container`
(trivy). Graceful degradation, cross-engine dedup, `init` writing the baseline.
**Exit:** `carabiner init` on a real third-party repo completes in under a
minute and leaves a green CI.

### Phase 2 — the CI surface *(week 2)*
SARIF, the GitHub Action, `.pre-commit-hooks.yaml`, the Docker image, exit-code
gating, JUnit.
**Exit:** findings appear in a stranger's PR Security tab with five lines of
YAML. Tag `v0.1.0`, publish.

### Phase 3 — the drill *(weeks 3–4)*
The differentiator. Canary hook test, push protection, branch protection,
workflow token, required-check verification.
**Exit:** the drill catches a configured-but-uninstalled pre-commit hook in a
fixture repo. Blog post: *"Your pre-commit hook isn't running."*

### Phase 4 — debt and reporting *(week 5)*
`carabiner debt`, expiring baseline entries, trend output, a PR comment
summarising what changed rather than restating the whole backlog.
**Exit:** a PR comment that says "2 new, 1 fixed, 340 accepted" and nothing more.

### Phase 5 — reach *(weeks 6–9)*
GitLab CI and Jenkins templates, `--offline` air-gapped mode, monorepo support,
language coverage for Go / Rust / Java / Ruby lockfiles, `carabiner init` on the
top 20 language templates as a test matrix.
**Exit:** works on a stock Rails, Next.js, and Spring Boot repo with no config.

### Phase 6 — the writeup *(week 10)*
Post: *"I scanned N public repos. X% had a security workflow that couldn't
fail the build."* Gather that number honestly with the tool; it is a real
finding and the best possible launch. Submit to a conference CFP.

**Long-term, only if earned:** an OpenSSF Scorecard integration, a `carabiner
attest` producing an in-toto provenance statement, and a compliance export that
maps findings to SOC 2 / ISO 27001 controls — auditors ask for exactly that
artifact and no free tool produces it.

---

## 10. How this stays honest about prior art

Read these before writing a line of the corresponding engine, and say plainly in
the README how carabiner differs:

| Project | Overlap | Expected differentiation |
|---|---|---|
| MegaLinter | bundles many linters incl. security | no ratchet, no drill, enormous, slow |
| Trunk.io | bundles + baseline | commercial, closed, account required |
| OpenSSF Scorecard | scores repo posture | scores, doesn't gate or ratchet |
| Allstar | enforces repo policy | GitHub App, org-level, no scanning |
| zizmor | GitHub Actions security | narrow — wrap it rather than duplicate |
| DefectDojo | normalizes and dedups findings | heavy server, not a CLI |
| pre-commit | hook orchestration | generic, no security opinion, no baseline |

If, after reading, some engine is strictly worse than an existing tool, **delete
the engine and wrap that tool.** The value is in §2, not in the wrappers.

---

## 11. What this lets you say

- *"How do you keep a codebase secure day to day?"* — A ratchet: existing debt
  is visible and accepted, new debt fails the build. Here's the tool.
- *"What's the most exploited CI misconfiguration?"* — `pull_request_target`
  with a PR-head checkout, and script injection from `github.event` into `run:`.
  Here's the engine that finds both.
- *"How do you know your security controls work?"* — I attack them on a
  schedule. Configured is not the same as working.
