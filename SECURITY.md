# Security policy

Report vulnerabilities privately via GitHub Security Advisories on this
repository (Security -> Report a vulnerability). Do not open a
public issue.

- Acknowledgement within 72 hours.
- Coordinated disclosure window: 90 days, negotiable for a hard fix.
- If a finding affects a widely used framework's default template, it is a
  coordinated disclosure with that project, not a tweet.

## What carabiner touches

carabiner reads your repository and, in `drill` mode, uses a GitHub token.

- **No telemetry, no update check, no analytics.** Ever.
- Findings never leave the machine unless you pipe them somewhere.
- `--offline` disables every network call. Engines that reach out are not run
  at all, and a test blocks socket creation outright and asserts a full scan
  still completes — the claim is enforced, not documented.
- Secrets are redacted structurally: `Finding.snippet` is scrubbed in
  `__post_init__`, so a Finding holding a raw credential cannot be constructed.
  See `tests/test_carabiner.py::test_redaction_is_structural`.
- Tokens are read from `$GITHUB_TOKEN` only. There is deliberately no `--token`
  flag: `/proc/*/cmdline` is world-readable and CI logs echo commands.
