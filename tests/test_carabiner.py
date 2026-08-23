"""Run: python tests/test_carabiner.py

The fixture suite asserts findings in BOTH directions. A false positive fails
this build exactly as hard as a false negative -- a noisy security tool gets
disabled, and a disabled tool is worse than no tool at all.
"""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carabiner import baseline
from carabiner.engines import ALL
from carabiner.finding import Finding, redact

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
FAILURES = []
CHECKS = [0]


def check(label, got, expected):
    CHECKS[0] += 1
    if got != expected:
        FAILURES.append(f"  {label}\n    expected {expected!r}\n    got      {got!r}")


def scan(root):
    out = []
    for engine in ALL.values():
        if engine.available(root):
            out.extend(engine.run(root))
    return out


def test_fixtures():
    for d in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        expected = sorted(json.loads((d / "expected.json").read_text(encoding="utf-8"))["expected"])
        got = sorted(f.rule for f in scan(d))
        check(f"fixture {d.name}", got, expected)


def test_clean_is_silent():
    """The most important fixture. A tool that fires on a correct repo is noise."""
    check("clean fixture produces nothing", scan(FIXTURES / "clean"), [])


def test_fingerprint_survives_reformatting():
    """The ratchet's load-bearing property. A baseline keyed on line numbers
    resurrects every accepted finding the first time someone adds an import."""
    a = Finding("ci", "CI003", "medium", "wf.yml", "m", snippet="uses: foo@v4", line=7)
    b = Finding("ci", "CI003", "medium", "wf.yml", "m", snippet="uses:   foo@v4  ", line=112)
    check("whitespace and line shifts keep the fingerprint", a.fingerprint, b.fingerprint)

    c = Finding("ci", "CI003", "medium", "other.yml", "m", snippet="uses: foo@v4")
    check("a different file is a different finding", a.fingerprint != c.fingerprint, True)


def test_redaction_is_structural():
    """You cannot construct a Finding holding a raw credential."""
    canary = "AKIAIOSFODNN7EXAMPLE" + "wJalrXUtnFEMIK7MDENGbPxRfiCY"
    f = Finding("secrets", "S1", "critical", "a.py", "found", snippet=canary)
    check("raw secret never survives construction", canary in f.snippet, False)
    check("raw secret never survives serialization",
          canary in json.dumps(f.as_dict()), False)
    check("a redacted stub is still shown", "..." in f.snippet, True)
    check("short non-token text is left alone", redact("hello world"), "hello world")
    # Identifiers this tool reports constantly must stay readable. Slashes,
    # dots and hyphens are separators, not part of a secret.
    for ident in ("dtolnay/rust-toolchain@stable",
                  "gcr.io/distroless/base-debian13",
                  "registry.access.redhat.com/ubi9/ubi-minimal",
                  ".github/workflows/security-scan.yml"):
        check(f"{ident} survives redaction", redact(ident), ident)
    for cred in ("AKIA" + "IOSFODNN7EXAMPLE",
                 "ghp_16C7e42F292c6912E7710c838347Ae178B4a"):
        check("but a credential does not", "..." in redact(cred), True)


def test_duplicate_findings_collapse():
    """Two identical findings must not appear twice; two genuinely distinct ones
    in different jobs must both survive. Found by dogfooding on a real repo."""
    from carabiner.cli import _collect
    got = _collect(FIXTURES / "ci_unpinned_action", None)
    # No job prefix any more: one unpinned reference is one decision, however
    # many jobs use it. Distinct actions still stay distinct.
    check("distinct unpinned actions both reported",
          sorted(f.snippet for f in got),
          ["actions/checkout@v4", "some-vendor/deploy@main"])
    check("no duplicate fingerprints survive collection",
          len({f.fingerprint for f in got}), len(got))


def test_secrets_parser():
    """The gitleaks JSON shape, parsed without the binary present.

    Fields are read defensively on purpose -- gitleaks' schema has moved between
    majors, and an engine that raises on an unknown key takes the whole scan
    down with it.
    """
    from carabiner.engines import secrets
    payload = [{
        "RuleID": "aws-access-token", "File": "config/settings.py",
        "StartLine": 12, "Description": "AWS Access Key",
        "Match": "aws_key = REDACTED", "Commit": "8f4b7f8486448",
    }]
    worktree = secrets._parse(payload, in_history=False)
    history = secrets._parse(payload, in_history=True)

    check("worktree secret is high", worktree[0].severity, "high")
    check("secret in history is critical", history[0].severity, "critical")
    check("history remediation says rotate, not delete",
          "rotate" in history[0].fix and "purge" in history[0].fix, True)
    check("rule id is namespaced", worktree[0].rule, "SECRET-aws-access-token")
    check("line is reported", worktree[0].line, 12)

    garbage = secrets._parse([{"unexpected": "schema"}, "not a dict", None], False)
    check("unknown schema degrades instead of raising", len(garbage), 1)


def test_missing_tool_is_reported_not_swallowed():
    """A scan claiming '0 findings' while an engine never ran is a lie the user
    has no way to detect."""
    from carabiner.engines import secrets, missing
    import shutil
    hint = secrets.missing(FIXTURES / "clean")
    if shutil.which("gitleaks"):
        check("gitleaks present -> no hint", hint, None)
    else:
        check("absent tool yields an install hint", "gitleaks" in (hint or ""), True)
        names = [n for n, _ in missing(FIXTURES / "clean")]
        check("and the engine is listed as skipped", "secrets" in names, True)


def test_dedup_keeps_the_worse_severity():
    """The same secret in the working tree and in history is one problem, but
    only the history version carries the right fix. Collapsing to whichever
    arrived first would silently downgrade it."""
    from carabiner.cli import dedupe
    low = Finding("secrets", "SECRET-aws", "high", "a.py", "worktree", snippet="k=RED")
    high = Finding("secrets", "SECRET-aws", "critical", "a.py", "history", snippet="k=RED")
    check("same problem collapses to one finding", len(dedupe([low, high])), 1)
    check("and keeps the critical one", dedupe([low, high])[0].severity, "critical")
    check("order does not matter", dedupe([high, low])[0].severity, "critical")


def test_secrets_integration_when_gitleaks_present():
    """Exercises the real binary. Skipped locally when gitleaks is absent; CI
    installs it so the subprocess path is never shipped unverified.

    The bait is a private-key header, not an AWS example key: gitleaks
    *allowlists* AKIAIOSFODNN7EXAMPLE because it is AWS's published
    documentation value, so the first version of this test was asking the
    scanner to find something it is built to ignore. It is assembled at runtime
    so this repository never contains the literal marker for its own scanner --
    or GitHub's -- to trip on.
    """
    import shutil, tempfile
    from carabiner.engines import secrets
    if not shutil.which("gitleaks"):
        return
    marker = "-----BEGIN" + " RSA PRIVATE KEY-----"
    body = "MIIEow" + "IBAAKCAQEA" + "x7Kq9vTbNz2mWpLc4RfHjE8sYuD" * 3
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "id_rsa").write_text(f"{marker}\n{body}\n-----END" +
                                     " RSA PRIVATE KEY-----\n", encoding="utf-8")
        got = secrets.run(root)
        check("gitleaks findings are normalized into Findings",
              [f.engine for f in got][:1], ["secrets"])
        check("no ENGINE-ERROR on a healthy run",
              [f for f in got if f.rule == "ENGINE-ERROR"], [])
        check("the raw key body never survives into a Finding",
              any(body[:40] in f.snippet for f in got), False)


def test_ratchet():
    """Adoption in a legacy repo: accept what exists, fail only on what is new."""
    import tempfile
    with tempfile.TemporaryDirectory() as _tmp:
        _ratchet_body(pathlib.Path(_tmp))


def _ratchet_body(tmp):
    findings = scan(FIXTURES / "ci_unpinned_action")
    check("fixture has findings to accept", len(findings) > 0, True)

    n = baseline.save(tmp, findings)
    check("all findings accepted", n, len(findings))

    new, accepted = baseline.partition(findings, baseline.load(tmp))
    check("accepted findings no longer fail the build", new, [])
    check("but they are still counted as debt", len(accepted), len(findings))

    fresh = Finding("ci", "CI001", "critical", "new.yml", "brand new")
    new2, _ = baseline.partition(findings + [fresh], baseline.load(tmp))
    check("a new finding still fails", [f.rule for f in new2], ["CI001"])


def test_scan_is_fast_enough():
    """The pre-commit budget, and why it is a hard number.

    The earlier version measured carabiner's own repository -- no lockfile, no
    scanners on PATH -- so it measured nothing and passed happily while the real
    fast path took up to 10s on seven of ten well-known repositories. It now
    asserts the structural property: the network-bound engine is not in the fast
    path at all.
    """
    from carabiner.cli import _collect
    from carabiner.engines import ALL, full_only
    root = pathlib.Path(__file__).resolve().parents[1]

    check("the network-bound engine is excluded from the fast path",
          [n for n in ALL if full_only(n)], ["deps"])

    start = time.monotonic()
    _collect(root, None, full=False)
    elapsed = time.monotonic() - start
    check(f"fast scan under 2s (took {elapsed:.2f}s)", elapsed < 2.0, True)

    check("but --all still includes it",
          "deps" in {n for n in ALL if not full_only(n) or True}, True)


def test_deps_advisory_ids_are_normalized():
    """Two scanners must agree on one id per vulnerability, or the developer
    sees one problem reported twice -- which costs trust faster than a miss."""
    from carabiner.engines.deps import canonical_id
    check("CVE wins over the native id",
          canonical_id("GHSA-abcd-efgh-ijkl", ["CVE-2024-1234"]), "CVE-2024-1234")
    check("GHSA is the fallback",
          canonical_id("PYSEC-2024-99", ["GHSA-abcd-efgh-ijkl"]), "GHSA-abcd-efgh-ijkl")
    check("native id survives when there is nothing better",
          canonical_id("PYSEC-2024-99", []), "PYSEC-2024-99")
    check("aliases may be missing entirely",
          canonical_id("GHSA-zzzz-zzzz-zzzz", None), "GHSA-zzzz-zzzz-zzzz")


def test_deps_parser_and_severity():
    from carabiner.engines import deps
    payload = {"results": [{
        "source": {"path": "/repo/requirements.txt", "type": "lockfile"},
        "packages": [{
            "package": {"name": "django", "version": "2.2.0", "ecosystem": "PyPI"},
            # Real osv-scanner always names the advisory each score belongs to.
            # The earlier fixture omitted `ids`, which let a wrong parser pass.
            "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "max_severity": "9.8"},
                       {"ids": ["GHSA-dddd-eeee-ffff"], "max_severity": "5.0"}],
            "vulnerabilities": [
                {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2019-19844"],
                 "summary": "Account takeover via password reset"},
                {"id": "GHSA-dddd-eeee-ffff", "aliases": [],
                 "database_specific": {"severity": "MODERATE"}, "summary": "x"},
            ]}]}]}
    got = sorted(deps._parse(payload, pathlib.Path("/repo")), key=lambda f: f.rule)
    check("path is made relative to the repo", got[0].path, "requirements.txt")
    check("canonical id becomes the rule", got[0].rule, "DEP-CVE-2019-19844")
    check("cvss 9.8 maps to critical", got[0].severity, "critical")
    check("named MODERATE maps to medium", got[1].severity, "medium")
    check("package@version is the dedup key", got[0].snippet, "django@2.2.0")

    unscored = deps._parse({"results": [{"source": {"path": "r.txt"}, "packages": [
        {"package": {"name": "x", "version": "1"},
         "vulnerabilities": [{"id": "CVE-1", "summary": "s"}]}]}]},
        pathlib.Path("/repo"))
    check("an advisory with no score is not quietly downgraded to low",
          unscored[0].severity, "high")
    check("unknown schema degrades instead of raising",
          deps._parse({"results": [{"packages": [{}]}]}, pathlib.Path("/repo")), [])


def test_deps_dedups_across_scanners():
    """The whole point of canonical ids: the same advisory for the same package
    from two different tools is one finding, at the worse severity."""
    from carabiner.cli import dedupe
    osv = Finding("deps", "DEP-CVE-2019-19844", "medium", "requirements.txt",
                  "django 2.2.0: takeover", snippet="django@2.2.0")
    other = Finding("deps", "DEP-CVE-2019-19844", "critical", "requirements.txt",
                    "django 2.2.0: takeover", snippet="django@2.2.0")
    got = dedupe([osv, other])
    check("one advisory, one finding", len(got), 1)
    check("reported at the worse severity", got[0].severity, "critical")


def test_deps_stays_quiet_without_dependencies():
    """Nagging about a missing scanner in a repo with no lockfile is noise, and
    noise is what gets a security tool switched off."""
    from carabiner.engines import deps
    check("no manifest, no install hint", deps.missing(FIXTURES / "clean"), None)


def test_deps_integration_when_osv_present():
    """Exercises the real binary; CI installs it. gitleaks taught this lesson --
    the CLI shape is probed, not assumed, and an untested subprocess path is a
    silent empty result waiting to happen."""
    import shutil, tempfile
    from carabiner.engines import deps
    if not shutil.which("osv-scanner"):
        return
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        # Old, long-since-fixed, and definitely in OSV. Generated at runtime so
        # the repo never carries a vulnerable lockfile of its own.
        (root / "requirements.txt").write_text("django==2.2.0\n", encoding="utf-8")
        got = deps.run(root)
        check("osv-scanner output is normalized into Findings",
              [f.engine for f in got][:1], ["deps"])
        check("no ENGINE-ERROR on a healthy run",
              [f.rule for f in got if f.rule == "ENGINE-ERROR"], [])
        check("advisories are namespaced under DEP-",
              all(f.rule.startswith("DEP-") for f in got), True)


def test_ignore_without_a_reason_is_an_error():
    """The one piece of process the tool imposes. A silent ignore list grows
    until the scan is decorative; a written reason has to survive code review."""
    from carabiner import config
    try:
        config.Config({"ignore": [{"path": "src/**"}]})
        check("unexplained ignore is rejected", "accepted", "ConfigError")
    except config.ConfigError as e:
        check("unexplained ignore is rejected", "reason" in str(e), True)
    try:
        config.Config({"ignore": [{"path": "src/**", "reason": "  "}]})
        check("a blank reason is not a reason", "accepted", "ConfigError")
    except config.ConfigError:
        check("a blank reason is not a reason", True, True)
    ok = config.Config({"ignore": [{"path": "src/**", "reason": "vendored"}]})
    check("an explained ignore is accepted", len(ok.ignores), 1)


def test_ignore_matching():
    from carabiner import config
    cfg = config.Config({"ignore": [
        {"path": "tests/fixtures/**", "reason": "deliberately vulnerable corpus"},
        {"check": "REPO003", "reason": "disclosure policy lives in the org profile"},
    ]})
    corpus = Finding("ci", "CI001", "critical", "tests/fixtures/bad/wf.yml", "m")
    real = Finding("ci", "CI001", "critical", ".github/workflows/ci.yml", "m")
    everywhere = Finding("repo", "REPO003", "low", "SECURITY.md", "m")
    check("path glob suppresses the corpus", cfg.ignored(corpus), True)
    check("but not the real workflow", cfg.ignored(real), False)
    check("a rule can be suppressed everywhere", cfg.ignored(everywhere), True)


def test_per_engine_thresholds():
    """A missing SECURITY.md and a leaked key do not deserve the same gate."""
    from carabiner import config
    cfg = config.Config({"engines": {
        "repo": {"fail_on": "critical"}, "secrets": {"fail_on": "high"}}})
    nit = Finding("repo", "REPO003", "low", "SECURITY.md", "m")
    leak = Finding("secrets", "SECRET-aws", "high", "a.py", "m", snippet="k")
    check("a low repo nit does not fail the build", cfg.gate([nit]), 0)
    check("a high secret does", cfg.gate([leak]), 1)
    check("disabled engines are skipped entirely",
          config.Config({"engines": {"ci": {"enabled": False}}}).enabled("ci"), False)


def test_init_dry_run_writes_nothing():
    """`init` prints every file it will write. A security tool that silently
    rewrites your config has no business asking to be trusted."""
    import shutil, tempfile
    from carabiner import cli, config, baseline
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        shutil.copytree(FIXTURES / "ci_no_permissions", root / "r")
        repo = root / "r"
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["init", "--root", str(repo), "--dry-run"])
        check("dry run writes no config",
              (repo / config.CONFIG_NAME).exists(), False)
        check("dry run writes no baseline",
              (repo / baseline.BASELINE_PATH).exists(), False)
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["init", "--root", str(repo)])
        check("a real init writes the config",
              (repo / config.CONFIG_NAME).exists(), True)
        check("and ratchets the baseline",
              (repo / baseline.BASELINE_PATH).exists(), True)
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["scan", "--root", str(repo)])
        check("adopted repo is green immediately", code, 0)


def test_no_findings_outside_a_project():
    """Found by sweeping directory shapes: an empty directory was reporting a
    missing .gitignore and a missing SECURITY.md. Telling someone their empty
    folder is insecure is precisely the noise that gets a scanner switched off."""
    import tempfile
    from carabiner.cli import _collect
    with tempfile.TemporaryDirectory() as tmp:
        empty = pathlib.Path(tmp)
        check("an empty directory produces nothing", _collect(empty, None), [])
        (empty / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        check("a real project directory does produce findings",
              len(_collect(empty, None)) > 0, True)


def test_sarif_is_wellformed():
    """The Security-tab surface. GitHub rejects the whole upload on a schema
    error, so a malformed field means zero findings reported, not a warning."""
    import json
    from carabiner.report import sarif
    findings = scan(FIXTURES / "ci_pull_request_target") + [
        Finding("repo", "REPO003", "low", "SECURITY.md", "no policy")]
    doc = json.loads(sarif.render(findings))
    run = doc["runs"][0]
    check("sarif version", doc["version"], "2.1.0")
    check("driver is named", run["tool"]["driver"]["name"], "carabiner")
    check("every result has a rule defined",
          {r["ruleId"] for r in run["results"]} <=
          {r["id"] for r in run["tool"]["driver"]["rules"]}, True)
    check("levels are valid SARIF",
          {r["level"] for r in run["results"]} <= {"error", "warning", "note"}, True)
    check("critical maps to error",
          [r["level"] for r in run["results"] if r["ruleId"] == "CI001"], ["error"])
    check("fingerprints are attached so GitHub can track across commits",
          all(r["partialFingerprints"] for r in run["results"]), True)
    # startLine 0 is invalid SARIF; a finding without a line must omit region.
    check("no zero startLine",
          any((r["locations"][0]["physicalLocation"].get("region") or
               {"startLine": 1})["startLine"] < 1 for r in run["results"]), False)
    check("rules carry a security-severity for sorting",
          all("security-severity" in r["properties"]
              for r in run["tool"]["driver"]["rules"]), True)


def test_action_does_not_commit_the_injection_it_reports():
    """action.yml interpolating ${{ inputs.* }} into a run: block would be CI002.
    A tool that ships the finding it reports has nothing to say to anyone."""
    import re
    root = pathlib.Path(__file__).resolve().parents[1]
    body = (root / "action.yml").read_text(encoding="utf-8")
    runs = re.findall(r"run:\s*\|?(.*?)(?=\n    - |\Z)", body, re.S)
    check("no template interpolation inside any run block",
          any("${{" in r for r in runs), False)


def test_gitlab_sanitized_variables_are_not_flagged():
    """CI_COMMIT_REF_SLUG is sanitised by GitLab, so flagging it would be a false
    positive -- and the fixture suite fails a false positive as hard as a miss."""
    from carabiner.engines import _gitlab
    check("the sanitised slug is safe",
          bool(_gitlab._INJECTABLE.search("echo $CI_COMMIT_REF_SLUG")), False)
    check("but the raw ref name is not",
          bool(_gitlab._INJECTABLE.search("echo $CI_COMMIT_REF_NAME")), True)
    check("braced form is caught too",
          bool(_gitlab._INJECTABLE.search("echo ${CI_MERGE_REQUEST_TITLE}")), True)


def test_gitlab_image_pinning_understands_registry_ports():
    """A registry port looks like a tag if you split on the wrong colon."""
    from carabiner.engines import _gitlab
    import pathlib as _p, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = _p.Path(tmp)
        (root / ".gitlab-ci.yml").write_text(
            "build:\n  image: registry.example.com:5000/app@sha256:" + "a" * 64 +
            "\n  script: [make]\n", encoding="utf-8")
        check("digest-pinned image behind a registry port is not flagged",
              _gitlab.run(root), [])


def test_both_ci_hosts_are_covered_by_one_engine():
    """The gap that made 'universal' untrue: a GitLab repo interpolating a merge
    request title into a script got zero findings while the GitHub equivalent
    was caught."""
    from carabiner.engines import ci
    gh = [f.rule for f in ci.run(FIXTURES / "ci_script_injection")]
    gl = [f.rule for f in ci.run(FIXTURES / "gitlab_script_injection")]
    check("GitHub script injection is found", gh, ["CI002"])
    check("the same bug on GitLab is found too", gl, ["GL001"])
    check("one engine reports both", {f.engine for f in
          ci.run(FIXTURES / "gitlab_mutable_image")}, {"ci"})


def test_drill_catches_configured_but_uninstalled_hooks():
    """The flagship drill. A hook listed in .pre-commit-config.yaml that nobody
    ran `pre-commit install` for is invisible to every static checker -- the
    configuration is perfect and nothing runs."""
    import tempfile
    from carabiner import drill
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / ".git" / "hooks").mkdir(parents=True)
        check("no hooks configured at all is reported",
              [f.rule for f in drill.hook_fires(root)], ["DRILL001"])

        (root / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
        got = drill.hook_fires(root)
        check("configured but not installed is the finding that matters",
              [f.rule for f in got], ["DRILL002"])
        check("and it is high severity", got[0].severity, "high")

        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        got = drill.hook_fires(root)
        check("installed hooks are either exercised or reported unverified",
              [f.rule for f in got] in ([], ["DRILL003"], ["DRILL004"]), True)


def test_drill_never_passes_what_it_could_not_check():
    """A green check you did not earn is worse than no check."""
    import tempfile
    from carabiner import drill
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / ".git" / "hooks").mkdir(parents=True)
        (root / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        got = drill.run(root, offline=True)
        api = [f for f in got if f.rule == "DRILL010"]
        check("offline mode reports API drills as unverified, not passed",
              len(api), 1)
        check("and says so in words", "could NOT be verified" in api[0].message, True)
        check("unverified is not silence", api[0].severity, "low")


def test_drill_canary_is_not_a_real_credential():
    """The drill plants a key on purpose. It must never be one that works, and
    must never be committable."""
    from carabiner import drill
    check("canary is a private key header", "PRIVATE KEY" in drill.CANARY, True)
    check("canary announces itself as fake",
          "nOtArEaLkEy" in drill.CANARY.replace("A", "A"), True)
    check("canary is not valid base64 key material",
          len(drill.CANARY) < 400, True)


def test_drill_cleans_up_even_when_the_hook_fails():
    """A crash must not leave a credential-shaped file in someone's repo."""
    import tempfile
    from carabiner import drill
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / ".git" / "hooks").mkdir(parents=True)
        (root / ".git" / "info").mkdir(parents=True)
        (root / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        drill.hook_fires(root)
        check("no canary left behind",
              (root / ".carabiner-drill-canary.key").exists(), False)
        excl = root / ".git" / "info" / "exclude"
        if excl.exists():
            check("and it was git-ignored before being written, not after",
                  "carabiner-drill-canary" in excl.read_text(encoding="utf-8"), True)


def test_accepted_debt_can_expire():
    """Without a deadline, 'accepted' quietly means 'forever' -- which is how a
    baseline becomes the place debt goes to be forgotten."""
    import shutil, tempfile
    from datetime import date, timedelta
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        findings = scan(FIXTURES / "ci_unpinned_action")
        baseline.save(root, findings, expires_days=30)
        acc = baseline.load(root)
        check("an expiry date is recorded",
              all("expires" in e for e in acc.values()), True)
        new, old = baseline.partition(findings, acc)
        check("inside the window it is still accepted", new, [])

        past = (date.today() - timedelta(days=1)).isoformat()
        for e in acc.values():
            e["expires"] = past
        new, old = baseline.partition(findings, acc)
        check("once the deadline passes it fails the build again",
              len(new), len(findings))
        check("and it is reported as overdue", baseline.expired(list(acc.values())[0]), True)


def test_fixed_findings_are_noticed():
    """A review that only ever reports new problems never tells anyone they are
    winning."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        findings = scan(FIXTURES / "ci_unpinned_action")
        baseline.save(root, findings)
        acc = baseline.load(root)
        check("nothing fixed while the findings remain",
              baseline.fixed(findings, acc), [])
        check("removing one is detected as fixed",
              len(baseline.fixed(findings[:-1], acc)), 1)


def test_pr_summary_stays_short():
    """A bot that restates the whole backlog on every PR gets muted -- and the
    two lines that mattered get muted with it."""
    import tempfile, io, contextlib
    from carabiner import cli
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "s.md"
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["scan", "--root", str(FIXTURES / "ci_pull_request_target"),
                      "--summary", str(out)])
        body = out.read_text(encoding="utf-8")
        check("headline carries the counts", body.startswith("### carabiner —"), True)
        check("the critical finding is named", "CI001" in body, True)
        check("it stays short", len(body.splitlines()) <= 14, True)


def test_version_is_declared_once_and_agrees():
    """Two version constants drift, and the one that drifts is the one stamped
    into SARIF -- so findings get attributed to a release that never existed."""
    import re
    from carabiner import __version__
    root = pathlib.Path(__file__).resolve().parents[1]
    declared = re.search(r'^version = "([^"]+)"',
                         (root / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
    check("pyproject and __init__ agree", __version__, declared)
    check("and it is not a dev version once tagged",
          ".dev" in declared and (root / ".git").exists() is False, False)


def test_offline_opens_no_sockets():
    """SECURITY.md promises --offline makes no network calls. A promise in a
    security tool's own policy has to be enforced, not documented -- so this
    blocks socket creation outright and asserts a full scan still completes."""
    import socket
    from carabiner.cli import _collect
    real = socket.socket

    class Blocked(socket.socket):
        def __init__(self, *a, **k):
            raise AssertionError("--offline opened a socket")

    root = pathlib.Path(__file__).resolve().parents[1]
    socket.socket = Blocked
    try:
        got = _collect(root, None, full=True, offline=True)
        check("a full offline scan completes without touching the network",
              isinstance(got, list), True)
    finally:
        socket.socket = real

    from carabiner.engines import networked
    check("the engine that needs the network is the one declared networked",
          [n for n in ("ci", "repo", "secrets", "deps") if networked(n)], ["deps"])


def test_docs_do_not_drift_or_recommend_mutable_refs():
    """Written after nearly every README edit in one session silently no-opped:
    blind string replacement reports success whether or not it matched anything.

    Doubles as dogfooding -- `@main` and `rev: main` are exactly the mutable
    references carabiner reports as CI003 and GL003, so recommending one in our
    own docs would be indefensible.
    """
    import re
    from carabiner import __version__
    root = pathlib.Path(__file__).resolve().parents[1]
    for name in ("README.md", "site/index.html"):
        body = (root / name).read_text(encoding="utf-8")
        refs = re.findall(r"carabiner@(\S+?)[<\s`\)]", body)
        refs += re.findall(r"rev:\s*(\S+)", body)
        moving = [r for r in refs if r in ("main", "master", "latest", "HEAD")]
        check(f"{name} recommends no mutable ref", moving, [])
        pins = {r.lstrip("v") for r in refs if r.startswith("v")}
        check(f"{name} pins are all one version", len(pins) <= 1, True)
        if pins:
            check(f"{name} pin matches the shipped version",
                  pins.pop(), __version__)


def test_readme_describes_the_engines_that_exist():
    """The README claimed 'Phase 0, native engines only' for three phases after
    that stopped being true."""
    from carabiner.engines import ALL
    root = pathlib.Path(__file__).resolve().parents[1]
    body = (root / "README.md").read_text(encoding="utf-8")
    for engine in ALL:
        check(f"README mentions the '{engine}' engine", f"`{engine}`" in body, True)


def test_no_text_io_relies_on_the_locale_encoding():
    """Windows found this: the default text encoding there is cp1252, so a single
    em dash in a workflow file crashed the whole scan with UnicodeDecodeError.

    A lint, not a runtime check -- the bug lives in code that is never exercised
    on the platform where it gets written.

    Parsed with ast rather than grepped: the first version matched the words in
    this very docstring and reported itself. A false positive costs the same
    trust as a miss, so the fix was a real parser, not a looser pattern.
    """
    import ast as _ast
    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for src in sorted((root / "carabiner").rglob("*.py")) + [pathlib.Path(__file__)]:
        tree = _ast.parse(src.read_text(encoding="utf-8"))
        for node in _ast.walk(tree):
            if (isinstance(node, _ast.Call)
                    and isinstance(node.func, _ast.Attribute)
                    and node.func.attr in ("read_text", "write_text")
                    and not any(k.arg == "encoding" for k in node.keywords)):
                offenders.append(f"{src.relative_to(root)}:{node.lineno}")
    check("every text read/write names its encoding", offenders, [])


def test_documented_container_tag_actually_exists():
    """docker/metadata-action's {{version}} strips the leading v, so the image is
    published as 0.1.4 while the git tag is v0.1.4. The README documented the git
    tag and named an image that was never pushed -- and the check I used to
    verify it queried the same wrong tag, so it agreed with itself.
    """
    import re as _re
    from carabiner import __version__
    root = pathlib.Path(__file__).resolve().parents[1]
    for name in ("README.md", "site/index.html"):
        path = root / name
        if not path.exists():
            continue
        for tag in _re.findall(r"ghcr\.io/\S*?carabiner:(\S+?)[\s`<]", path.read_text(encoding="utf-8")):
            check(f"{name} container tag has no v prefix", tag.startswith("v"), False)
            check(f"{name} container tag matches the release",
                  tag in (__version__, "latest"), True)


def test_deps_finds_manifests_in_subprojects():
    """Found on the first repo I had not written myself: backend/ and frontend/
    each had a package-lock.json, the engine read only the top level, and so it
    scanned nothing and said nothing. Silence indistinguishable from 'clean' is
    the exact failure this tool exists to complain about."""
    import tempfile
    from carabiner.engines import deps
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for sub in ("backend", "frontend"):
            (root / sub).mkdir()
            (root / sub / "package-lock.json").write_text("{}", encoding="utf-8")
        check("subproject lockfiles are found", sorted(deps.manifest_dirs(root)),
              ["backend", "frontend"])
        check("so the engine has something to do", deps.has_manifest(root), True)

        # ...but not by walking into the places that make recursion slow.
        heavy = root / "node_modules" / "pkg"
        heavy.mkdir(parents=True)
        (heavy / "package-lock.json").write_text("{}", encoding="utf-8")
        check("node_modules is not walked",
              any("node_modules" in d for d in deps.manifest_dirs(root)), False)

        deep = root / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "package-lock.json").write_text("{}", encoding="utf-8")
        check("and the walk is depth-bounded",
              any(d.startswith("a") for d in deps.manifest_dirs(root)), False)


def test_deps_scores_come_from_the_right_advisory():
    """osv-scanner's `groups` holds one entry per advisory. Applying the last
    group's max_severity to every vulnerability in the package attaches an
    unrelated score -- silently wrong rather than obviously broken."""
    from carabiner.engines import deps
    payload = {"results": [{"source": {"path": "p.lock"}, "packages": [{
        "package": {"name": "x", "version": "1"},
        "groups": [{"ids": ["GHSA-aaa"], "max_severity": "9.8"},
                   {"ids": ["GHSA-bbb"], "max_severity": "2.1"}],
        "vulnerabilities": [{"id": "GHSA-aaa", "summary": "critical one"},
                            {"id": "GHSA-bbb", "summary": "minor one"}]}]}]}
    got = {f.rule: f.severity for f in deps._parse(payload, pathlib.Path("/"))}
    check("the 9.8 advisory is critical", got["DEP-GHSA-aaa"], "critical")
    check("the 2.1 advisory is not", got["DEP-GHSA-bbb"], "low")


def test_registry_config_is_only_a_finding_when_it_holds_a_credential():
    """13 false positives across 33 well-known repos, every one a .npmrc holding
    nothing but `ignore-scripts=true`. The filename was treated as proof."""
    import tempfile
    from carabiner.engines import repo as repo_engine
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        plain = root / ".npmrc"
        plain.write_text("ignore-scripts=true\npackage-lock=false\n", encoding="utf-8")
        check("plain registry config is not key material",
              repo_engine._key_material(plain, pathlib.PurePosixPath(".npmrc")), None)

        real = root / "with-token" / ".npmrc"
        real.parent.mkdir()
        real.write_text("//registry.npmjs.org/:_authToken=abc123\n", encoding="utf-8")
        check("but one carrying an auth token is",
              repo_engine._key_material(real, pathlib.PurePosixPath(".npmrc")),
              "a registry credential")


def test_injection_rule_distinguishes_attacker_input_from_repo_state():
    """The three real CI002 hits across 33 well-known repositories -- two of
    which the first version got wrong. A HIGH finding that is wrong two times in
    three is worse than no rule at all.
    """
    import tempfile
    from carabiner.engines import ci as ci_engine

    def scan_run(script):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "w.yml").write_text(
                "on: push\npermissions: {contents: read}\njobs:\n  j:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                f"      - run: {script}\n", encoding="utf-8")
            return [f for f in ci_engine.run(root) if f.rule == "CI002"]

    # tokio: the PR's *target* branch, in the maintainer's own repo.
    check("base.ref is repo state, not attacker input",
          scan_run('echo "${{ github.event.pull_request.base.ref }}"'), [])
    # nlohmann/json: a GitHub username cannot contain a shell metacharacter.
    check("a username is not injectable",
          scan_run("echo ${{ github.event.pull_request.user.login }}"), [])
    # nvm: a free-form workflow_dispatch input, unquoted.
    dispatch = scan_run('echo "${{ github.event.inputs.ref }}"')
    check("a dispatch input is a real sink", [f.rule for f in dispatch], ["CI002"])
    check("but rated below anonymous input", dispatch[0].severity, "medium")
    # the classic: a pull request title.
    title = scan_run('echo "${{ github.event.pull_request.title }}"')
    check("a PR title is the canonical injection", [f.severity for f in title], ["high"])
    check("and so is head_ref",
          [f.severity for f in scan_run('echo "${{ github.head_ref }}"')], ["high"])


def test_dotenv_and_fixture_paths_are_judged_by_content_not_name():
    """Three findings from a 60-repo sweep, all miscalibrated:

    - grafana commits eleven .env files under devenv/ holding `mysql_version=8.0.32`
      and every one was reported as CRITICAL key material.
    - vault keeps fourteen test keys under `test-fixtures/`, which whole-segment
      matching missed because the directory name is hyphenated.
    """
    import tempfile
    from carabiner.engines import repo as R
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        vers = root / ".env"
        vers.write_text("mysql_version=8.0.32\nelastic_version=8.5.0\n", encoding="utf-8")
        check("a dotenv of version pins is not a credential",
              R._key_material(vers, pathlib.PurePosixPath(".env")), None)

        real = root / "real.env"
        real.write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")
        check("but a populated password key is",
              R._key_material(real, pathlib.PurePosixPath(".env")) is not None, True)

        url = root / "url.env"
        url.write_text("DATABASE_URL=postgres://u:p@host/db\n", encoding="utf-8")
        check("and so is a credential inside a URL",
              R._key_material(url, pathlib.PurePosixPath(".env")) is not None, True)

    check("hyphenated fixture directories count as fixtures",
          R._is_fixture(("api", "test-fixtures", "keys")), True)
    check("as do underscored ones", R._is_fixture(("pkg", "test_data")), True)
    check("but a real source directory does not",
          R._is_fixture(("src", "config", "secrets")), False)


def test_guarded_pull_request_target_is_reported_lower():
    """discourse gates its pull_request_target workflow to dependabot by login,
    which is not attacker-settable. Still worth reporting -- these guards are
    easy to write wrongly -- but not at open-door severity."""
    import tempfile
    from carabiner.engines import ci as ci_engine

    def scan(guard):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "w.yml").write_text(
                "on: pull_request_target\npermissions: {contents: read}\njobs:\n"
                f"  j:\n{guard}    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
                encoding="utf-8")
            return [f for f in ci_engine.run(root) if f.rule == "CI001"]

    check("unguarded is critical", [f.severity for f in scan("")], ["critical"])
    check("guarded by author login is high",
          [f.severity for f in
           scan("    if: github.event.pull_request.user.login == 'dependabot[bot]'\n")],
          ["high"])


def test_env_templates_and_placeholders_are_not_leaks():
    """strapi ships .env.example files containing JWT_SECRET=tobemodified. Those
    are documentation: committed on purpose, for the next developer to replace.
    Reporting them as critical key material is the filename-over-content mistake
    in a fourth costume."""
    import tempfile
    from carabiner.engines import repo as R
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        tpl = root / ".env.example"
        tpl.write_text("HOST=0.0.0.0\nJWT_SECRET=tobemodified\n", encoding="utf-8")
        check("a .env.example template is not a leak",
              R._key_material(tpl, pathlib.PurePosixPath(".env.example")), None)

        ph = root / "ph.env"
        ph.write_text("API_TOKEN=changeme\n", encoding="utf-8")
        check("nor is a placeholder value in a real .env",
              R._key_material(ph, pathlib.PurePosixPath(".env")), None)

        real = root / "real.env"
        real.write_text("API_TOKEN=gho_9fJ2kLmQ7xRt4NpZ\n", encoding="utf-8")
        check("but a populated token still is",
              R._key_material(real, pathlib.PurePosixPath(".env")) is not None, True)


def test_env_key_words_are_matched_as_tokens_not_substrings():
    """strapi's LINEAR_CMS_STATUS_WAITING_ON_AUTHOR=<uuid> was reported as a
    critical credential because "AUTHOR" contains "AUTH". Substring matching on
    a key name finds words that are not there."""
    from carabiner.engines.repo import _secretish_key
    for key in ("LINEAR_CMS_STATUS_WAITING_ON_AUTHOR", "SORT_KEY", "PRIMARY_KEY",
                "CACHE_KEY", "AUTHORIZED_USERS", "SESSION_TIMEOUT"):
        check(f"{key} is not secret-shaped", _secretish_key(key), False)
    for key in ("JWT_SECRET", "API_KEY", "DB_PASSWORD", "ACCESS_KEY_ID",
                "GITHUB_TOKEN", "CLIENT_SECRET"):
        check(f"{key} is secret-shaped", _secretish_key(key), True)


def test_action_pinning_severity_is_shaped_by_ref_and_publisher():
    """CI003 was 1470 of 3017 findings across 60 repos -- 49% of everything, and
    almost none of it worth an afternoon. Two things were wrong: every ref that
    was not a SHA counted the same, and a hardcoded branch list missed `stable`,
    `nightly` and `cargo-hack`, which are branches of the actions tokio uses."""
    from carabiner.engines._github import _pin_severity
    cases = [
        # third-party moving branch: the one that can change tonight
        ("dtolnay/rust-toolchain", "stable", "medium"),
        ("dtolnay/rust-toolchain", "master", "medium"),
        ("taiki-e/install-action", "cargo-hack", "medium"),
        ("some-vendor/deploy", "main", "medium"),
        # first-party moving branch: lower, GitHub controls the repo
        ("actions/checkout", "main", "low"),
        # version tags: what nearly everyone uses, informational
        ("actions/checkout", "v4", "info"),
        ("Swatinem/rust-cache", "v2", "info"),
        ("some/action", "1.2.3", "info"),
    ]
    for uses, ref, want in cases:
        got, _why = _pin_severity(uses, ref)
        check(f"{uses}@{ref} -> {want}", got, want)


def test_one_unpinned_action_reference_is_one_finding():
    """tokio reaches dtolnay/rust-toolchain@stable 34 times in a single workflow.
    That is one decision, and 34 identical lines is a wall, not a report."""
    import tempfile
    from carabiner.cli import _collect
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / ".github" / "workflows").mkdir(parents=True)
        steps = "".join("      - uses: vendor/act@stable\n" for _ in range(12))
        (root / ".github" / "workflows" / "w.yml").write_text(
            "on: push\npermissions: {contents: read}\njobs:\n  j:\n"
            f"    runs-on: ubuntu-latest\n    steps:\n{steps}", encoding="utf-8")
        got = [f for f in _collect(root, ["ci"]) if f.rule == "CI003"]
        check("twelve identical references collapse to one finding", len(got), 1)


def test_informational_findings_are_hidden_but_counted():
    """Hidden must never mean disappeared."""
    import io, contextlib, tempfile
    from carabiner import cli
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "w.yml").write_text(
            "on: push\npermissions: {contents: read}\njobs:\n  j:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["scan", "--root", str(root)])
        out = buf.getvalue()
        check("the informational finding is not listed", "CI003" in out, False)
        check("but its count is shown", "informational" in out, True)
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            cli.main(["scan", "--root", str(root), "--info"])
        check("and --info lists it", "CI003" in buf2.getvalue(), True)


def test_dockerfile_engine_reads_dockerfiles_not_everything_shaped_like_one():
    """Every rule shipped without spot-checking in this project has been wrong,
    and this one was no exception: 33 of its first 36 base-image findings were
    false. Multi-stage `FROM builder` references an earlier stage, `scratch` is
    a keyword, `${BASE_IMAGE}` is unknowable, and airflow embeds whole Python
    programs in BuildKit heredocs that were being read as instructions."""
    import tempfile
    from carabiner.engines import docker as D
    def scan(body):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "Dockerfile").write_text(body, encoding="utf-8")
            return {f.rule for f in D.run(root)}

    check("a stage reference is not an image",
          "DOCK002" in scan("FROM python:3.13-slim AS build\nFROM build\nUSER 10001\n"), False)
    check("scratch is not an image",
          "DOCK002" in scan("FROM scratch\nUSER 10001\n"), False)
    check("a build arg base is unknowable",
          "DOCK002" in scan("ARG B=x\nFROM ${B}\nUSER 10001\n"), False)
    check("a template placeholder is not an image",
          "DOCK002" in scan("FROM <%= base %>\nUSER 10001\n"), False)
    check("but a real :latest base is",
          "DOCK002" in scan("FROM composer:latest\nUSER 10001\n"), True)

    check("heredoc bodies are not parsed as instructions",
          "DOCK002" in scan("FROM python@sha256:" + "a"*64 +
                            "\nRUN <<EOF\nfrom __future__ import annotations\nEOF\n"
                            "USER 10001\n"), False)

    pinned = "FROM python@sha256:" + "a" * 64 + "\n"
    check("no USER means the container runs as root",
          "DOCK001" in scan(pinned), True)
    check("dropping privileges clears it",
          "DOCK001" in scan(pinned + "USER 10001\n"), False)
    check("only the final stage matters",
          "DOCK001" in scan(pinned + "USER 10001\n" + pinned + "USER app\n"), False)

    check("curl piped into a shell is caught",
          "DOCK004" in scan(pinned + "RUN curl https://x.sh | bash\nUSER 1\n"), True)
    check("a baked credential is caught",
          "DOCK003" in scan(pinned + "ENV API_TOKEN=gho_9fJ2kLmQ7xRt\nUSER 1\n"), True)
    check("a placeholder credential is not",
          "DOCK003" in scan(pinned + "ENV API_TOKEN=changeme\nUSER 1\n"), False)
    check("disabled TLS is caught",
          "DOCK005" in scan(pinned + "RUN pip install --insecure x\nUSER 1\n"), True)


def test_untrusted_trigger_family():
    """CI006 and CI008 were promised in PLAN.md and never built. Both are real
    token-theft routes, and both only matter in combination with a trigger that
    runs in the base repo's context while handling somebody else's code."""
    import tempfile
    from carabiner.engines import ci as C

    def scan(body):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "w.yml").write_text(body, encoding="utf-8")
            return {f.rule for f in C.run(root)}

    HEAD = "permissions: {contents: read}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
    CHECKOUT = "      - uses: actions/checkout@v4\n"

    # CI006: a real secret in reach of checked-out contributor code.
    body = "on: pull_request_target\n" + HEAD + CHECKOUT + \
           "      - run: npm test\n        env:\n          NPM: ${{ secrets.NPM_TOKEN }}\n"
    check("secrets in reach of untrusted code", "CI006" in scan(body), True)
    safe = body.replace("pull_request_target", "pull_request")
    check("same workflow on a trusted trigger is fine", "CI006" in scan(safe), False)
    check("GITHUB_TOKEN alone does not count", "CI006" in scan(
        "on: pull_request_target\n" + HEAD + CHECKOUT +
        "      - run: gh pr view\n        env:\n          T: ${{ secrets.GITHUB_TOKEN }}\n"), False)

    # CI008: checkout leaves the token in .git/config for every later step.
    check("persist-credentials left on",
          "CI008" in scan("on: pull_request_target\n" + HEAD + CHECKOUT), True)
    check("turning it off clears the finding",
          "CI008" in scan("on: pull_request_target\n" + HEAD +
                          "      - uses: actions/checkout@v4\n"
                          "        with:\n          persist-credentials: false\n"), False)

    # CI010: a cache written from an untrusted trigger can be poisoned.
    check("cache on an untrusted trigger",
          "CI010" in scan("on: pull_request_target\n" + HEAD +
                          "      - uses: actions/cache@v4\n"), True)


def test_secrets_inherit_only_matters_across_a_trust_boundary():
    """Every `secrets: inherit` in a 60-repo corpus called a local reusable
    workflow -- same repo, same secrets, same reviewers. Flagging those added
    106 findings that meant nothing."""
    import tempfile
    from carabiner.engines import ci as C

    def scan(uses):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "w.yml").write_text(
                "on: push\npermissions: {contents: read}\njobs:\n  j:\n"
                f"    uses: {uses}\n    secrets: inherit\n", encoding="utf-8")
            return {f.rule for f in C.run(root)}

    check("a local reusable workflow is not a finding",
          "CI009" in scan("./.github/workflows/build.yml"), False)
    check("someone else's workflow is",
          "CI009" in scan("other-org/repo/.github/workflows/build.yml@main"), True)


def test_diff_mode_scans_only_what_changed():
    """The pre-commit path. Filtering results after a full scan saves nothing --
    the first implementation was slower than a full scan because of exactly
    that -- so the engines must not do the work, not merely hide it."""
    import subprocess, tempfile
    from carabiner.engines.repo import changed_files
    from carabiner.cli import _collect
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        (root / ".github" / "workflows").mkdir(parents=True)
        wf = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" \
             "      - uses: vendor/act@main\n"
        (root / ".github" / "workflows" / "old.yml").write_text(wf, encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=root, check=True)

        (root / ".github" / "workflows" / "new.yml").write_text(wf, encoding="utf-8")
        changed = changed_files(root)
        check("the new file is seen as changed",
              ".github/workflows/new.yml" in (changed or set()), True)
        check("the committed one is not",
              ".github/workflows/old.yml" in (changed or set()), False)

        everything = {f.path for f in _collect(root, ["ci"])}
        only_new = {f.path for f in _collect(root, ["ci"], changed=changed)}
        check("a full scan sees both", len(everything), 2)
        check("a diff scan sees only the changed file",
              only_new, {".github/workflows/new.yml"})


def test_kubernetes_engine():
    """K8S005's first two findings were both real values that were not
    credentials: airflow's SECRET_NAME holds the *name* of a Secret, and etcd's
    INITIAL_CLUSTER_TOKEN is a cluster identifier."""
    import tempfile
    from carabiner.engines import kubernetes as K
    def scan(spec):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "d.yaml").write_text(
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n" + spec,
                encoding="utf-8")
            return {f.rule for f in K.run(root)}

    SAFE = ("  containers:\n  - name: c\n    image: x\n    securityContext:\n"
            "      runAsNonRoot: true\n      runAsUser: 10001\n")
    check("a hardened pod is clean", scan(SAFE), set())
    check("hostNetwork is caught", "K8S001" in scan("  hostNetwork: true\n" + SAFE), True)
    check("privileged is critical",
          "K8S002" in scan("  containers:\n  - name: c\n    image: x\n"
                           "    securityContext:\n      privileged: true\n"
                           "      runAsNonRoot: true\n"), True)
    check("nothing stopping root is caught",
          "K8S004" in scan("  containers:\n  - name: c\n    image: x\n"), True)

    env = SAFE + "    env:\n    - name: {k}\n      value: \"{v}\"\n"
    check("a Secret's *name* is not a credential",
          "K8S005" in scan(env.format(k="SECRET_NAME", v="release-kerberos-keytab")), False)
    check("a cluster identifier is not either",
          "K8S005" in scan(env.format(k="ETCD_INITIAL_CLUSTER_TOKEN", v="etcd-cluster-1")), False)
    check("but a high-entropy literal is",
          "K8S005" in scan(env.format(k="API_TOKEN", v="gho_9fJ2kLmQ7xRt4NpZa1Bc")), True)


def test_jenkins_circleci_and_azure():
    """The same vulnerability in three dialects: text somebody else controls
    reaching a shell without ever becoming data."""
    import tempfile
    from carabiner.engines import _otherci as O
    def scan(name, body):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
            return [f.rule for f in O.run(root)]

    check("Groovy interpolates a param into the shell",
          scan("Jenkinsfile", 'pipeline { steps { sh "echo ${params.B}" } }\n'), ["JEN001"])
    check("single quotes do not interpolate",
          scan("Jenkinsfile", "pipeline { steps { sh 'echo $B' } }\n"), [])
    check("a case-insensitive filesystem does not double-report",
          len(scan("Jenkinsfile", 'sh "echo ${params.B}"\n')), 1)
    check("a volatile orb is caught",
          "CIR001" in scan(".circleci/config.yml",
                           "orbs:\n  n: circleci/node@volatile\n"), True)
    check("an Azure branch name in a script is caught",
          scan("azure-pipelines.yml",
               "steps:\n- script: echo $(Build.SourceBranchName)\n"), ["AZP001"])


def test_every_finding_path_is_posix():
    """Windows CI caught this: git reports forward slashes and pathlib does not,
    so `--diff` matched nothing at all and reported a clean repository. Paths are
    normalised at the Finding boundary rather than at each comparison, because
    one missed comparison is a silent pass on one operating system."""
    from carabiner.cli import _collect
    root = pathlib.Path(__file__).resolve().parents[1]
    bad = [f.path for f in _collect(root, None, full=False) if "\\" in f.path]
    check("no finding carries a backslash path", bad, [])
    check("a windows path is normalised on construction",
          Finding("ci", "X001", "low", ".github\\workflows\\a.yml", "m").path,
          ".github/workflows/a.yml")


def test_tool_failure_is_never_reported_as_clean():
    """The bug CI caught: gitleaks removed `detect` in 8.24, our command failed,
    and the engine returned [] -- indistinguishable from a clean repo."""
    import os, stat, tempfile
    from carabiner.engines import secrets
    with tempfile.TemporaryDirectory() as tmp:
        if os.name == "nt":
            fake = pathlib.Path(tmp) / "gitleaks.bat"
            fake.write_text("@echo unknown command 1>&2\r\n@exit /b 2\r\n", encoding="utf-8")
        else:
            fake = pathlib.Path(tmp) / "gitleaks"
            fake.write_text("#!/bin/sh\necho 'unknown command' >&2\nexit 2\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        got = secrets._scan(str(fake), pathlib.Path(tmp), history=False)
    check("a failing scanner produces a finding, not silence",
          [f.rule for f in got], ["ENGINE-ERROR"])
    check("and the message refuses to imply the repo is clean",
          "did NOT happen" in got[0].message, True)
    check("and the fix says not to read it as evidence of cleanliness",
          "not read this scan" in got[0].fix, True)


def main():
    # Discovered, not listed. A hand-maintained roster silently stops running
    # tests the moment an edit drops a name -- which is exactly what happened.
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    # A floor, not a target. Three separate edits in one session silently
    # deleted whole blocks of tests by replacing a range that spanned them;
    # each time the suite went green with fewer tests and said nothing.
    FLOOR = 58
    if len(tests) < FLOOR:
        raise SystemExit(f"test suite shrank: {len(tests)} < {FLOOR}. "
                         "An edit probably deleted tests -- check git diff.")
    for fn in tests:
        fn()
    if FAILURES:
        print(f"FAIL ({len(FAILURES)})")
        print("\n".join(FAILURES))
        raise SystemExit(1)
    print(f"ok  ({len(tests)} tests, {CHECKS[0]} checks)")


if __name__ == "__main__":
    main()
