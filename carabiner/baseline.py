"""The ratchet.

Existing findings are accepted once and recorded. From then on only *new*
findings fail the build. Security tightens or holds; it does not loosen.

This is what makes the tool installable in a ten-year-old repo on a Tuesday
afternoon instead of requiring a cleanup sprint nobody will schedule.
"""

from __future__ import annotations

import json
import pathlib
from datetime import date

from .finding import Finding

BASELINE_PATH = pathlib.Path(".carabiner/baseline.json")


def load(root: pathlib.Path) -> dict[str, dict]:
    path = root / BASELINE_PATH
    if not path.exists():
        return {}
    data = json.loads(path.read_text() or "{}")
    return data.get("accepted", {})


def save(root: pathlib.Path, findings: list[Finding], reason: str = "") -> int:
    """Accept everything currently found. Keeps first_seen for entries we
    already knew about, so the age of the debt survives a re-lock."""
    path = root / BASELINE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load(root)
    today = date.today().isoformat()
    accepted = {}
    for f in findings:
        prior = existing.get(f.fingerprint, {})
        accepted[f.fingerprint] = {
            "rule": f.rule, "path": f.path, "severity": f.severity,
            "message": f.message,
            "first_seen": prior.get("first_seen", today),
            "reason": prior.get("reason") or reason,
        }
    path.write_text(json.dumps(
        {"version": 1, "accepted": accepted}, indent=2, sort_keys=True) + "\n")
    return len(accepted)


def partition(findings: list[Finding], accepted: dict[str, dict]
              ) -> tuple[list[Finding], list[Finding]]:
    """-> (new, already_accepted). Only the first list should fail a build."""
    new, old = [], []
    for f in findings:
        (old if f.fingerprint in accepted else new).append(f)
    return new, old
