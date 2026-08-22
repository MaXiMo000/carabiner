"""carabiner -- make a repo secure by default, keep it that way, prove it fires.

    carabiner init     adopt: detect, configure, ratchet    once per repo
    carabiner scan     what is new since the baseline       pre-commit, CI
    carabiner lock     accept what exists today             deliberate debt
    carabiner debt     what we are carrying                 sprint planning
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

from . import baseline, config
from .engines import ALL
from .engines import missing as engines_missing
from .finding import rank
from .report import human


def _collect(root: pathlib.Path, only: list[str] | None, full: bool = False,
             cfg: config.Config | None = None):
    cfg = cfg or config.Config()
    findings = []
    for name, engine in ALL.items():
        if only and name not in only:
            continue
        if not cfg.enabled(name):
            continue
        if engine.available(root):
            findings.extend(engine.run(root, full))
    return [f for f in dedupe(findings) if not cfg.ignored(f)]


def dedupe(findings):
    """Collapse identical findings, keeping the most severe.

    Severity is load-bearing, not cosmetic. The same secret found in the working
    tree AND in history is one problem, but only the history version carries the
    right remediation -- rotate and purge, not just delete. Keeping whichever
    arrived first would quietly downgrade it. Same rule covers two scanners
    disagreeing about a CVE's severity: believe the worse one.
    """
    best: dict[str, object] = {}
    for f in findings:
        prior = best.get(f.fingerprint)
        if prior is None or rank(f.severity) > rank(prior.severity):
            best[f.fingerprint] = f
    return list(best.values())


TEMPLATE = """\
# carabiner -- https://github.com/MaXiMo000/carabiner
version: 1

engines:
{engines}
# Every suppression must carry a written reason. An ignore without one is a
# config error, not a warning -- an unexplained ignore list is how a scan
# quietly becomes decorative.
#
# ignore:
#   - path: tests/fixtures/**
#     reason: "deliberately vulnerable corpus"
"""


def _init(root: pathlib.Path, dry_run: bool) -> int:
    detected = config.detect(root)
    print("detected:")
    for name, why in detected.items():
        print(f"  {name:<9} {why}")

    skipped = engines_missing(root)
    for name, hint in skipped:
        print(f"\n  '{name}' has nothing installed to run -- {hint}")

    lines = "".join(
        f"  {n}: {{enabled: true, fail_on: {'high' if n == 'deps' else 'medium'}}}\n"
        for n in detected)
    body = TEMPLATE.format(engines=lines)
    cfg_path = root / config.CONFIG_NAME

    print(f"\nwould write {config.CONFIG_NAME}:" if dry_run
          else f"\nwriting {config.CONFIG_NAME}:")
    print("".join(f"  | {l}\n" for l in body.splitlines()))

    findings = _collect(root, None, full=True)
    print(f"first scan: {len(findings)} findings")

    if dry_run:
        print(f"\n--dry-run: nothing written. Drop the flag to adopt.")
        return 0

    if cfg_path.exists():
        print(f"{config.CONFIG_NAME} already exists -- left alone.")
    else:
        cfg_path.write_text(body)
    n = baseline.save(root, findings, reason="accepted at carabiner init")

    print(f"ratcheted {n} findings into {baseline.BASELINE_PATH}\n")
    print("CI is green from here, and only NEW findings will fail it.")
    print("Existing debt is recorded, not deleted -- see `carabiner debt`.")
    print("Commit .carabiner.yml and .carabiner/ so the ratchet is shared.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="carabiner")
    ap.add_argument("command", choices=["init", "scan", "lock", "debt"])
    ap.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    ap.add_argument("--engine", action="append", dest="engines")
    ap.add_argument("--fail-on", default=None,
                    help="override the per-engine threshold from .carabiner.yml")
    ap.add_argument("--all", action="store_true", dest="full",
                    help="every engine, whole history. CI cadence, not pre-commit.")
    ap.add_argument("--dry-run", action="store_true", help="init: write nothing")
    ap.add_argument("--json", action="store_true")
    # No --token flag, deliberately: argv is world-readable via /proc and CI
    # logs echo commands. Tokens come from the environment only.
    args = ap.parse_args(argv)

    root = args.root.resolve()
    try:
        cfg = config.load(root)
    except config.ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.command == "init":
        return _init(root, args.dry_run)

    started = time.monotonic()
    findings = _collect(root, args.engines, args.full, cfg)
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

    if args.fail_on:
        worst = max((rank(f.severity) for f in new), default=-1)
        return 1 if worst >= rank(args.fail_on) else 0
    return cfg.gate(new)


if __name__ == "__main__":
    sys.exit(main())
