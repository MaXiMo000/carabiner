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
          "NOT checked" in got[0].message, True)


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
