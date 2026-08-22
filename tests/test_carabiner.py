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


def check(label, got, expected):
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


def test_ratchet(tmp=pathlib.Path("/tmp/carabiner-ratchet-test")):
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
    """Hard budget. Anything slower than this is uninstalled from pre-commit
    within a week -- the observed failure mode of every pre-commit security tool."""
    start = time.monotonic()
    for d in (p for p in FIXTURES.iterdir() if p.is_dir()):
        scan(d)
    elapsed = time.monotonic() - start
    check(f"full fixture scan under 2s (took {elapsed:.2f}s)", elapsed < 2.0, True)


def main():
    for fn in (test_fixtures, test_clean_is_silent,
               test_fingerprint_survives_reformatting, test_redaction_is_structural,
               test_ratchet, test_duplicate_findings_collapse,
               test_scan_is_fast_enough):
        fn()
    if FAILURES:
        print(f"FAIL ({len(FAILURES)})")
        print("\n".join(FAILURES))
        raise SystemExit(1)
    print("ok  (7 checks)")


if __name__ == "__main__":
    main()
