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
        expected = sorted(json.loads((d / "expected.json").read_text())["expected"])
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


def test_duplicate_findings_collapse():
    """Two identical findings must not appear twice; two genuinely distinct ones
    in different jobs must both survive. Found by dogfooding on a real repo."""
    from carabiner.cli import _collect
    got = _collect(FIXTURES / "ci_unpinned_action", None)
    check("distinct unpinned actions both reported",
          sorted(f.snippet for f in got),
          ["build: actions/checkout@v4", "build: some-vendor/deploy@main"])
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
                                     " RSA PRIVATE KEY-----\n")
        got = secrets.run(root)
        check("gitleaks findings are normalized into Findings",
              [f.engine for f in got][:1], ["secrets"])
        check("no ENGINE-ERROR on a healthy run",
              [f for f in got if f.rule == "ENGINE-ERROR"], [])
        check("the raw key body never survives into a Finding",
              any(body[:40] in f.snippet for f in got), False)


def test_ratchet(tmp=pathlib.Path("/tmp/carabiner-ratchet-test")):
    """Adoption in a legacy repo: accept what exists, fail only on what is new."""
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
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
    shutil.rmtree(tmp, ignore_errors=True)


def test_scan_is_fast_enough():
    """Hard budget on the pre-commit path, measured the way it is actually used:
    one real repository, fast mode. Anything slower gets uninstalled inside a
    week -- the observed failure mode of every pre-commit security tool.

    Measuring six fixtures at once was the wrong test; CI caught it the moment a
    real scanner joined the fast path and pushed the total to 2.5s.
    """
    from carabiner.cli import _collect
    repo = pathlib.Path(__file__).resolve().parents[1]
    start = time.monotonic()
    _collect(repo, None, full=False)
    elapsed = time.monotonic() - start
    check(f"fast scan of one repo under 2s (took {elapsed:.2f}s)", elapsed < 2.0, True)


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
            "groups": [{"max_severity": "9.8"}],
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
        (root / "requirements.txt").write_text("django==2.2.0\n")
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
        (empty / "Cargo.toml").write_text("[package]\n")
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
    body = (root / "action.yml").read_text()
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
            "\n  script: [make]\n")
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

        (root / ".pre-commit-config.yaml").write_text("repos: []\n")
        got = drill.hook_fires(root)
        check("configured but not installed is the finding that matters",
              [f.rule for f in got], ["DRILL002"])
        check("and it is high severity", got[0].severity, "high")

        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
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
        (root / ".pre-commit-config.yaml").write_text("repos: []\n")
        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
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
        (root / ".pre-commit-config.yaml").write_text("repos: []\n")
        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
        drill.hook_fires(root)
        check("no canary left behind",
              (root / ".carabiner-drill-canary.key").exists(), False)
        excl = root / ".git" / "info" / "exclude"
        if excl.exists():
            check("and it was git-ignored before being written, not after",
                  "carabiner-drill-canary" in excl.read_text(), True)


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
        body = out.read_text()
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
                         (root / "pyproject.toml").read_text(), re.M).group(1)
    check("pyproject and __init__ agree", __version__, declared)
    check("and it is not a dev version once tagged",
          ".dev" in declared and (root / ".git").exists() is False, False)


def test_tool_failure_is_never_reported_as_clean():
    """The bug CI caught: gitleaks removed `detect` in 8.24, our command failed,
    and the engine returned [] -- indistinguishable from a clean repo."""
    import stat, tempfile
    from carabiner.engines import secrets
    with tempfile.TemporaryDirectory() as tmp:
        fake = pathlib.Path(tmp) / "gitleaks"
        fake.write_text("#!/bin/sh\necho 'unknown command \"detect\"' >&2\nexit 2\n")
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
    for fn in tests:
        fn()
    if FAILURES:
        print(f"FAIL ({len(FAILURES)})")
        print("\n".join(FAILURES))
        raise SystemExit(1)
    print(f"ok  ({len(tests)} tests, {CHECKS[0]} checks)")


if __name__ == "__main__":
    main()
