# tenantproof — plan

A CI tool that **proves** Postgres tenant isolation holds, instead of checking
that someone remembered to type `ENABLE ROW LEVEL SECURITY`.

Working name: `tenantproof`. Alternatives if PyPI is taken: `rlsprobe`, `pgtenant`.
Check availability before you get attached to one.

---

## 1. The thesis

Every RLS linter in existence reads `pg_catalog` and tells you a policy exists.
None of them tell you the policy **applies**. The distance between those two
sentences is where every real multi-tenant leak lives.

You already wrote this down in Recur's `schema.sql`:

> `pg_class` still cheerfully reports `relrowsecurity = true` while every policy
> below is inert.

That comment is the product. Here is the gap, stated as a table — this goes at
the top of the README, because it is the whole pitch:

| Catalog says | Reality | Static linter sees |
|---|---|---|
| `relrowsecurity = true` | app connects as superuser → policies inert | ✅ pass |
| `relrowsecurity = true` | app owns the table, no `FORCE` → owner bypasses | ⚠️ sometimes |
| policy exists | `USING (true)` — enforces nothing | ⚠️ sometimes |
| policy exists | `USING` set, no `WITH CHECK` → you can plant rows in another tenant | ❌ miss |
| policy exists for SELECT | nothing for `UPDATE`/`DELETE` | ❌ miss |
| policy exists | a `SECURITY DEFINER` function reads straight through it | ❌ miss |
| policy exists | a view owned by a privileged role bypasses it (`security_invoker` off) | ❌ miss |
| policy exists | pooled connection carries tenant A's GUC into tenant B's request | ❌ miss — not in the catalog at all |
| policy exists | FK integrity checks bypass RLS → cross-tenant existence oracle | ❌ miss |

The last three are invisible to any tool that only reads the catalog, because
they are not properties of the schema. They are properties of the **running
system**. That is the moat.

**One-line positioning:** *Linters check that RLS is configured. tenantproof
checks that Alice cannot read Bob's rows — by trying.*

---

## 2. What exists, and why this isn't it

| Thing | What it does | Why it isn't this |
|---|---|---|
| Supabase `splinter` | catalog lints: `rls_disabled_in_public`, `policy_exists_rls_disabled` | static only, Supabase-shaped, no probing |
| `pgTAP` | a test framework with `policies_are()` assertions | you write every assertion yourself, per table, forever |
| Hand-rolled tests | what you did in Recur | doesn't survive the next migration; nobody generalizes it |
| Semgrep / CodeQL | app-layer taint | never looks at the database |

Verify this list yourself before the README claims novelty — check GitHub for
`rls test`, `postgres tenant isolation`, `rls lint`. If someone shipped it in
the last year, adjust the positioning to "the dynamic one" rather than "the
only one." The dynamic engine is defensible either way.

---

## 3. Threat model — the vulnerability classes the tool exists to catch

This section *is* the security plan. Each class gets a check ID, a detection
engine, and a fixture in the vuln corpus. Nothing ships without all three.

### Class A — the policy is inert

| ID | Vulnerability | Engine |
|---|---|---|
| A1 | App role is `SUPERUSER` or `BYPASSRLS` | static + runtime |
| A2 | App role owns the tables and `FORCE ROW LEVEL SECURITY` is not set | static + probe |
| A3 | `ENABLE` set but zero policies → deny-all, which is an outage, not security (report as WARN, it's a liveness bug) | static |
| A4 | Table has the tenant column but RLS is not enabled at all | static |
| A5 | Policy `USING (true)` or a predicate not referencing the tenant key | static + probe |

### Class B — the write side is open

The most under-tested half. `USING` governs what you can *see*; `WITH CHECK`
governs what you can *create*. A policy with only `USING` lets a tenant insert
rows branded as somebody else, and update their own rows into another tenant's
namespace. Recur gets this right; most codebases don't.

| ID | Vulnerability | Engine |
|---|---|---|
| B1 | `USING` without `WITH CHECK` on a permissive `ALL` policy | static + probe |
| B2 | Policy exists for `SELECT` only, silence on `INSERT`/`UPDATE`/`DELETE` | static + probe |
| B3 | `UPDATE` can reassign the tenant column to another tenant | probe |
| B4 | `INSERT` can plant a row owned by another tenant | probe |

### Class C — bypass paths around the policy

| ID | Vulnerability | Engine |
|---|---|---|
| C1 | `SECURITY DEFINER` function reads/writes a tenant table | static (flag) + probe (execute it as tenant A, count tenant B rows) |
| C2 | View over a tenant table without `security_invoker = true` (PG15+) or any view at all on PG<15 | static + probe |
| C3 | Foreign key integrity checks bypass RLS → cross-tenant **existence oracle** | probe |
| C4 | `GRANT` to `PUBLIC` on a tenant table | static |
| C5 | Sequence readable cross-tenant → leaks row counts and ID ranges (`SELECT last_value FROM x_id_seq`) | static + probe |
| C6 | Materialized view over tenant data — RLS does not apply to matview contents at all | static |
| C7 | Trigger function running as definer that writes across tenants | static (flag) |

**C3 deserves its own paragraph, because it is the sharpest finding in the
tool and it is probably live in Recur right now.**

Postgres runs referential-integrity checks as an internal operation that does
not go through RLS. So a tenant can attempt an insert referencing an ID they
cannot see, and the *success or failure* of that insert tells them whether the
row exists in another tenant. In Recur: `subscription.merchant_id REFERENCES
merchant(id)`. Alice inserts a subscription pointing at `merchant_id = 500`.
FK violation → Bob has no merchant 500. Success → he does, and Alice now holds
a row pointing into his data.

The reads stay safe — RLS still hides the joined row — but the oracle is real
and the dangling cross-tenant reference is a correctness problem. **I have not
run this against Recur. Verify it before you write it in a README.** If it
confirms, that is your before/after: *"I ran it against the app I'd already
written nine isolation tests for. It found a tenth."*

Mitigation the tool should recommend: a composite FK — `REFERENCES merchant
(id, user_id)` with `user_id` carried on the child and a `UNIQUE (id, user_id)`
on the parent. Makes the FK check itself tenant-scoped.

### Class D — runtime context hygiene (no static tool can see these)

| ID | Vulnerability | Engine |
|---|---|---|
| D1 | Pooled connection carries the tenant GUC into the next borrower | runtime |
| D2 | GUC set with transaction scope while the app commits mid-unit-of-work → silent zero-row results | runtime |
| D3 | `current_setting('x.y')` without `missing_ok` → policy **errors** instead of denying | static + runtime |
| D4 | `''::bigint` cast on an unset GUC raises instead of returning NULL (the `NULLIF` bug) | static + runtime |
| D5 | Unset tenant returns *all* rows rather than none — failure is open, not closed | probe |
| D6 | `SET ROLE`/`SET LOCAL` leaking across a transaction-pooling PgBouncer | runtime |

D3 and D4 are the ones you personally hit and documented. An erroring policy is
not a denying policy — and if any code path catches that exception broadly, the
error becomes a bypass. Nobody else's tool checks this.

### Class E — drift over time

| ID | Vulnerability | Engine |
|---|---|---|
| E1 | A migration adds a table with a tenant column and no policy | baseline diff |
| E2 | A policy's predicate changed since the approved baseline | baseline diff |
| E3 | A new role gained `BYPASSRLS` | baseline diff |
| E4 | A grant widened | baseline diff |

E is where the query-plan-baseline idea comes back, pointed at security instead
of performance. Same mechanism — snapshot, commit, diff, fail the build — but
the thing being protected is tenant isolation, which nobody ignores when it goes
red. Plan regressions get muted in CI. Tenant leaks don't.

---

## 4. Architecture

Three engines, cheapest first, each independently runnable.

```
tenantproof/
  cli.py          argparse. three verbs: check, baseline, explain
  config.py       tenantproof.yml -> typed settings, with defaults
  introspect.py   one pass over pg_catalog -> a Schema model
  engines/
    static.py     rules over the Schema model. no data touched.
    probe.py      two synthetic tenants, the adversarial matrix
    runtime.py    connection/pool/GUC hygiene
  findings.py     Finding: id, severity, object, evidence, fix. NEVER a row value.
  report/
    human.py      the default table
    sarif.py      GitHub code scanning
    junit.py      generic CI
  corpus/         deliberately vulnerable fixture schemas + expected findings
```

### Engine 1 — static

Pure catalog reads: `pg_policy`, `pg_class.relrowsecurity`/`relforcerowsecurity`,
`pg_roles.rolbypassrls`/`rolsuper`, `pg_proc.prosecdef`, `pg_class.reloptions`
for `security_invoker`, `information_schema.role_table_grants`, `pg_depend` for
sequence ownership.

Zero data read. Safe against production. This is the only engine allowed to run
with `--target production`.

### Engine 2 — probe

The generalization of `test_tenancy.py`. Given the tenant column and GUC from
config:

1. Create two synthetic tenants (`tenant_a`, `tenant_b`) — or adopt two existing
   IDs supplied in config for a schema too constrained to seed.
2. Topologically sort tables by FK dependency; seed one minimal row per tenant
   per table, filling NOT NULL columns with type-appropriate junk.
3. For every (table × command × direction), run the adversarial operation as
   tenant A against tenant B's row and assert the closed outcome:

```
SELECT  unscoped                -> A's rows only
SELECT  WHERE tenant = B        -> 0 rows
SELECT  via JOIN to B's parent  -> 0 rows
INSERT  branded as B            -> rejected
UPDATE  SET tenant = B          -> rejected
UPDATE  WHERE tenant = B        -> 0 rows affected
DELETE  WHERE tenant = B        -> 0 rows affected
SELECT  with GUC unset          -> 0 rows (closed, not open)
SELECT  with GUC = ''           -> 0 rows, no exception
SELECT  with GUC = 'not-a-number' -> denied, not error
FK      referencing B's id      -> rejected (C3 oracle)
```

That is roughly 11 checks × N tables, derived, not hand-written. Recur's nine
become ~77 automatically.

Everything runs inside a transaction that is **always** rolled back, or against
a scratch database created and dropped by the tool. Two layers, because one is
a promise and two is a design.

### Engine 3 — runtime

Takes the app's own DSN and pool settings. Opens a connection, sets the GUC,
returns it to the pool, borrows again, reads the GUC back. Checks
`rolbypassrls` on the connected role. Detects PgBouncer in front (via
`SHOW pool_mode` or the `application_name` round-trip) and warns about
transaction-pooling with session-scoped `set_config`.

D1 is one query and catches the single worst bug in multi-tenant Python. It is
also the check that only exists because you hit it.

### Config

```yaml
# tenantproof.yml
tenant_column: user_id
tenant_setting: recur.user_id     # the GUC the policies read
app_role: recur_app               # the role that must NOT bypass
severity_gate: high               # exit 1 at or above this

exempt:
  - object: public.app_user
    check: A4
    reason: "identity table, not tenant-scoped; admin() reads it deliberately"
    # no reason -> the exemption is rejected. deliberate.
```

Exemptions requiring a written reason is the one piece of process the tool
enforces, and it is the difference between a tool people keep and a tool people
`--no-verify` around.

---

## 5. Security of the tool itself

It is a security tool that wants a database connection. Its own posture is the
credential.

**Data never leaves the database.**
The `Finding` type carries `object_name`, `check_id`, `severity`, `sqlstate`,
and `row_count: int`. It has no field capable of holding a row value. That is
enforced by the type, not by review — someone who wants to leak data has to
change the data model, which shows up in a diff. Write that as a one-line
docstring on the class and a test that asserts the field set.

**Never mutates the target.**
- `--target production` → static engine only, hard-refuses to run probe/runtime.
- Probe engine runs in an explicit transaction with `ROLLBACK` in a `finally`,
  *and* refuses to run unless the database name matches a scratch pattern or
  `--i-know-this-is-not-production` is passed.
- Set `default_transaction_read_only` on the static engine's session. Belt,
  braces, and a second pair of braces.

**Credentials never touch argv.**
DSN comes from `$TENANTPROOF_DSN` or `$DATABASE_URL` only. A `--dsn` flag is
*deliberately not implemented*, and the error message says why: `/proc/*/cmdline`
is world-readable, CI logs echo commands, shell history persists. This is a
30-second decision that signals more security judgment than a page of prose.

**Least privilege for the tool's own role.**
Document a `tenantproof_auditor` role: `pg_read_all_settings`, `SELECT` on
catalogs, nothing else, for static mode. Ship the `CREATE ROLE` snippet. Most
security tools ask for superuser and hope you don't notice.

**Supply chain.**
- Dependencies: `psycopg[binary]` and the standard library. That is the whole
  list. Every added dependency is a package a tenant-isolation auditor now
  implicitly vouches for.
- `requirements.lock` with hashes, `pip install --require-hashes` in CI.
- PyPI **trusted publishing** (OIDC from GitHub Actions, no long-lived token).
- Sigstore attestations on release artifacts; SBOM via `pip-audit --format
  cyclonedx` in the release job.
- `dependabot` on, `pip-audit` as a CI gate.
- Pin GitHub Actions to commit SHAs, not tags. A tag is mutable.

**The GitHub Action's own threat model.**
It receives a DSN as a secret. Therefore: never echo it, `mask` it explicitly,
never run on `pull_request_target` (that's how third-party PRs steal secrets),
and the README must say in bold: *do not point this at production; point it at
the ephemeral CI database your migrations just built.*

**Responsible disclosure.**
`SECURITY.md` with a real contact and a 90-day policy. If the tool finds a
class-of-bug affecting a popular framework's default template, that is a
coordinated disclosure, not a tweet. Behave accordingly — it is also the best
possible portfolio event.

---

## 6. Testing strategy — the vuln corpus

The tool's correctness is not "does it run." It is **"does it find exactly the
right holes in a schema whose holes we know."**

`corpus/` holds one directory per vulnerability, each with `schema.sql` and
`expected.json`:

```
corpus/
  A1_superuser_app_role/
  A2_owner_no_force/
  A5_using_true/
  B1_no_with_check/
  B2_select_only_policy/
  C1_security_definer_reader/
  C2_view_without_security_invoker/
  C3_fk_existence_oracle/
  D3_current_setting_no_missing_ok/
  D4_empty_string_cast_raises/
  D5_unset_tenant_returns_all/
  clean_reference/            <- must produce ZERO findings
```

CI matrix: PG 13, 14, 15, 16, 17 × every corpus entry. The test asserts the
exact finding set — both directions. **A false positive fails the build as hard
as a false negative**, because a security tool that cries wolf gets disabled,
and a disabled tool has negative value.

`clean_reference/` is the most important fixture. Make it Recur's schema.

---

## 7. Roadmap

Each phase ends in something usable. Nothing is scaffolding for a later phase.

### Phase 0 — the corpus and the static engine *(one weekend)*
The corpus first, TDD-style: write the vulnerable schemas and the expected
findings *before* the detector. Then `introspect.py` + `static.py` + a human
table. Ship `tenantproof check --static`.
**Exit:** finds A1–A5, B1–B2, C4 across the corpus on PG16. Zero findings on
`clean_reference`.

### Phase 1 — the probe engine *(week 1 — this is the ship point)*
Synthetic tenants, dependency-ordered seeding, the adversarial matrix. Dogfood
against Recur.
**Exit:** Recur's nine hand-written checks are reproduced by derivation, plus at
least one finding they didn't cover. Tag `v0.1.0`, publish to PyPI, post it.

### Phase 2 — CI surface *(week 2)*
SARIF output, a composite GitHub Action, JUnit XML, exit-code gating, the
exemption file.
**Exit:** findings appear in a PR's Security tab. `uses: ritish/tenantproof@v0`
works in a stranger's repo with five lines.

### Phase 3 — the deep checks *(weeks 3–5)*
C1, C2, C3, C5, C6, D1, D2, D6. This is the phase that makes it uncopyable —
each of these is a day of Postgres semantics most people never learn.
**Exit:** the FK oracle check confirmed against a fixture and against Recur.

### Phase 4 — baseline and drift *(week 6)*
`tenantproof baseline > .tenantproof/baseline.json`, committed. `check --diff`
fails on new unpoliced tables, widened predicates, new BYPASSRLS roles.
**Exit:** add a table to Recur in a migration, forget the policy, watch CI go
red before the PR merges.

### Phase 5 — framework adapters *(weeks 7–9)*
Auto-detect tenant column and GUC for: Supabase (`auth.uid()`), Django
(`django-multitenant`, `search_path` schemes), SQLAlchemy/Alembic, Rails
(`acts_as_tenant`). Each adapter is a config generator, not a code path —
`tenantproof init` writes the YAML and you read it.
**Exit:** `tenantproof init` produces correct config on a stock Supabase project.

### Phase 6 — the writeup *(week 10)*
Blog post: **"Your RLS policies are enabled. That doesn't mean they're on."**
Lead with the catalog-lies table, close with the Recur before/after. Submit to
PyCon India / a Postgres meetup. Post to r/PostgreSQL, Lobsters, HN — HN on a
Tuesday morning US time, with the vuln table as the hook, not the tool.

**Long-term, only if it earns it:** a `pg_tenantproof` extension exposing the
probe matrix as SQL functions; a "tenant isolation report" PDF for compliance
folks (SOC 2 auditors will ask for exactly this artifact).

---

## 8. Dogfooding on Recur — the README's before/after

Run it against Recur at HEAD. Expected outcome, to be confirmed:

| Check | Prediction | Why |
|---|---|---|
| A1 app role bypass | **pass** | `NOSUPERUSER NOBYPASSRLS`, deliberately |
| A2 FORCE | **pass** | you set it, and documented why |
| B1 WITH CHECK | **pass** | both clauses present |
| D3/D4 GUC handling | **pass** | `missing_ok` + `NULLIF`, the two bugs most people ship |
| D1 pool reset | **pass** | the `reset=` callback |
| C3 FK oracle | **likely FAIL** | `subscription.merchant_id`, `price_change.subscription_id`, `raw_transaction.account_id` — plain FKs, not tenant-composite |
| C5 sequence leak | **likely FAIL** | `GRANT USAGE, SELECT ON ALL SEQUENCES` lets any tenant read `last_value` and learn your row counts |
| A4 identity tables | **finding, then exempt** | `app_user`/`session`/`email_token`/`oauth_*` are not tenant-scoped by design — this is what the reason-required exemption file is for |

Two real findings against a codebase that already took tenant isolation
seriously enough to write adversarial tests. That's the story. Confirm it
before you tell it.

Then fix both in Recur — composite FKs, and revoke sequence `SELECT` (keep
`USAGE`, which is all `nextval` needs) — and Recur's README gets a line too.

---

## 9. Adoption

Portfolio apps get zero stars; portfolio tools get used — but only if the first
run is free.

- `pipx run tenantproof check` against a `docker run postgres` must work with
  **zero config** for the common case (a `user_id` column and a GUC it can find
  by reading the policies themselves).
- The README opens with the catalog-lies table, then a 20-line quickstart, then
  the vuln classes. No architecture diagram above the fold.
- An asciinema cast of it finding the FK oracle in a stock Supabase project.
  Assuming it does — check first.
- Answer every issue in 24h for the first three months. That is the entire
  growth strategy.

---

## 10. Explicitly not doing this

Written down so it stays not-done:

- No web dashboard, no SaaS, no hosted anything.
- No rule DSL / plugin API. Rules are Python functions in a list until someone
  files an issue asking to add one from outside.
- No ORM/static app analysis. The database is the source of truth; app-layer
  scanning is a different tool and a crowded one.
- No MySQL/MSSQL. RLS is a Postgres story.
- No auto-fix. It writes `ALTER TABLE` suggestions as text; a tool that mutates
  your security policy unattended is a vulnerability with a changelog.
- No AI/LLM anything. A deterministic security tool that occasionally
  hallucinates is worse than no tool.

---

## 11. What this lets you answer in an interview

- *"How do you guarantee tenant isolation?"* — Not with a WHERE clause. With
  RLS, a NOBYPASSRLS role, FORCE, and a probe suite that tries to break it on
  every commit. Here's the tool.
- *"What's a subtle Postgres behavior that bit you?"* — Referential integrity
  checks bypass RLS. Here's the existence oracle it creates and the composite-FK
  fix.
- *"How do you catch security regressions before production?"* — Baseline diff:
  a migration that adds a tenant table without a policy fails the build.
- *"Tell me about something you built that other people use."* — Stars, issues,
  and a disclosure, hopefully.

---

## 12. Order of operations

1. Deploy Recur.
2. Edit the resume.
3. Phase 0 of this.

In that order. This document will still be here.

---

## 13. Why this is not a universal security tool

Recorded so the question stays answered.

**The temptation:** make it cover every language, every cloud, every service —
one tool everybody runs on everything.

**Why it loses.** A security tool's only asset is trust: when it reports a
finding you believe it enough to go look. Trust is bought with depth. Breadth
spends it — broad coverage means a shallow rule per surface, shallow rules
produce noise, noise gets the tool muted, and a muted tool is worse than no
tool because it looks like coverage. That is the same argument as §6's "a false
positive fails the build as hard as a false negative," applied to product scope.

**And the field is occupied.** Free and mature already: Prowler and ScoutSuite
(AWS/Azure/GCP/K8s misconfiguration), Trivy (containers, IaC, SBOM, secrets),
Checkov (IaC), Semgrep and CodeQL (multi-language SAST), OSV-Scanner
(dependencies), Steampipe (SQL over cloud APIs). Commercially: the CNAPP
category — Wiz, Orca, Prisma Cloud — hundreds of engineers each. Cloud APIs
change weekly; maintaining universal coverage *is* the product, and it is a
funded team's permanent job. A solo 60%-of-Prowler gets zero users.

**What does generalize: the method, not the surface.**

Almost every tool listed above is a linter — it reads configuration and
pattern-matches. Very few execute the adversarial case and check the outcome.
*Prove the control works, don't check that it's configured* is the thesis, and
it extends:

| Surface | The lint everyone ships | The proof nobody ships |
|---|---|---|
| Postgres RLS | `relrowsecurity = true` | seed two tenants, try to cross |
| Cloud IAM | parse the policy JSON | `iam:SimulatePrincipalPolicy` on the real principal |
| App authz | grep for the decorator | replay every route with tenant B's token, assert 403 |

That is a **family** — three tools sharing a findings model and SARIF writer,
built over years — not one binary. Each member has to earn its existence by
being the best at its one question. Caveat before starting the IAM one: AWS
Access Analyzer's custom policy checks already occupy part of that ground.
Research first; the RLS field is the empty one.

**The reframe on reach.** Universal adoption doesn't come from covering
everything. It comes from being the definitive answer to one question a very
large number of people have. Postgres RLS is the security model of every
Supabase project, every multi-tenant B2B SaaS, and a large share of Django and
Rails apps — and RLS misconfiguration is one of the most common ways they leak
customer data. Nobody owns that question today.

Being the tool Supabase links from their RLS docs beats being a worse Prowler.
