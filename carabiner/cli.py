"""carabiner -- one command makes a repo secure by default, and keeps it that way.

    carabiner scan     what is new since the baseline   (pre-commit, CI)
    carabiner lock     accept what exists today          (adoption, deliberate debt)
    carabiner debt     what we are carrying              (sprint planning)
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

from . import baseline
from .engines import ALL
from .engines import missing as engines_missing
from .finding import rank
from .report import human


def _collect(root: pathlib.Path, only: list[str] | None, full: bool = False):
    findings = []
    for name, engine in ALL.items():
        if only and name not in only:
            continue
        if engine.available(root):
            findings.extend(engine.run(root, full))
    return dedupe(findings)


def dedupe(findings):
    """Collapse identical findings, keeping the most severe.

    Severity is load-bearing, not cosmetic. The same secret found in the working
    tree AND in history is one problem, but only the history version carries the
    right remediation -- rotate and purge, not just delete. Keeping whichever
    arrived first would quietly downgrade it. Same rule covers Trivy and
    OSV-Scanner disagreeing about a CVE's severity: believe the worse one.
    """
    best: dict[str, object] = {}
    for f in findings:
        prior = best.get(f.fingerprint)
        if prior is None or rank(f.severity) > rank(prior.severity):
            best[f.fingerprint] = f
    return list(best.values())


def _gate(new, threshold: str) -> int:
    worst = max((rank(f.severity) for f in new), default=-1)
    return 1 if worst >= rank(threshold) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="carabiner")
    ap.add_argument("command", choices=["scan", "lock", "debt"])
    ap.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    ap.add_argument("--engine", action="append", dest="engines")
    ap.add_argument("--fail-on", default="medium",
                    help="lowest severity that exits non-zero (default: medium)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all", action="store_true", dest="full",
                    help="every engine, whole history. CI cadence, not pre-commit.")
    # No --token flag, deliberately: argv is world-readable via /proc and CI
    # logs echo commands. Tokens come from the environment only.
    args = ap.parse_args(argv)

    root = args.root.resolve()
    started = time.monotonic()
    findings = _collect(root, args.engines, args.full)
    skipped = engines_missing(root)
    accepted_map = baseline.load(root)
    new, accepted = baseline.partition(findings, accepted_map)

    if args.command == "lock":
        n = baseline.save(root, findings)
        print(f"ratcheted: {n} findings accepted -> {baseline.BASELINE_PATH}")
        print("only new findings will fail the build from here.")
        return 0

    if args.command == "debt":
        for fp, e in sorted(accepted_map.items(),
                            key=lambda kv: -rank(kv[1]["severity"])):
            print(f"  {e['severity']:<8} {e['rule']:<8} {e['path']}"
                  f"   since {e['first_seen']}")
        print(f"\n{len(accepted_map)} accepted findings")
        return 0

    if args.json:
        print(json.dumps({"new": [f.as_dict() for f in new],
                          "accepted": len(accepted)}, indent=2))
    else:
        print(human.render(new, accepted, time.monotonic() - started, skipped))
    return _gate(new, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
