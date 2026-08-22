"""The ratchet.

Existing findings are accepted once and recorded. From then on only *new*
findings fail the build. Security tightens or holds; it does not loosen.

This is what makes the tool installable in a ten-year-old repo on a Tuesday
afternoon instead of requiring a cleanup sprint nobody will schedule.
"""

from __future__ import annotations

import json
import pathlib
from datetime import date, timedelta

from .finding import Finding

BASELINE_PATH = pathlib.Path(".carabiner/baseline.json")


def load(root: pathlib.Path) -> dict[str, dict]:
    path = root / BASELINE_PATH
    if not path.exists():
        return {}
    data = json.loads(path.read_text() or "{}")
    return data.get("accepted", {})


def expired(entry: dict, today: str | None = None) -> bool:
    """An accepted finding with a date on it stops being accepted when that date
    passes. Without expiry, 'accepted' quietly means 'forever', which is how a
    baseline turns into a place debt goes to be forgotten."""
    stamp = entry.get("expires")
    return bool(stamp) and stamp < (today or date.today().isoformat())


def fixed(findings: list[Finding], accepted: dict[str, dict]) -> list[dict]:
    """Accepted entries whose finding is gone. Worth saying out loud -- a review
    that only ever reports new problems never tells anyone they are winning."""
    live = {f.fingerprint for f in findings}
    return [e for fp, e in accepted.items() if fp not in live]


def save(root: pathlib.Path, findings: list[Finding], reason: str = "",
         expires_days: int | None = None) -> int:
    """Accept everything currently found. Keeps first_seen for entries we
    already knew about, so the age of the debt survives a re-lock."""
    path = root / BASELINE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load(root)
    today = date.today().isoformat()
    horizon = ((date.today() + timedelta(days=expires_days)).isoformat()
               if expires_days else None)
    accepted = {}
    for f in findings:
        prior = existing.get(f.fingerprint, {})
        entry = {
            "rule": f.rule, "path": f.path, "severity": f.severity,
            "message": f.message,
            "first_seen": prior.get("first_seen", today),
            "reason": prior.get("reason") or reason,
        }
        deadline = horizon or prior.get("expires")
        if deadline:
            entry["expires"] = deadline
        accepted[f.fingerprint] = entry
    path.write_text(json.dumps(
        {"version": 1, "accepted": accepted}, indent=2, sort_keys=True) + "\n")
    return len(accepted)


def partition(findings: list[Finding], accepted: dict[str, dict]
              ) -> tuple[list[Finding], list[Finding]]:
    """-> (new, still_accepted). Only the first list should fail a build.

    An expired acceptance counts as new. That is the whole point of putting a
    date on it: the deadline has to actually arrive.
    """
    new, old = [], []
    for f in findings:
        entry = accepted.get(f.fingerprint)
        (old if entry and not expired(entry) else new).append(f)
    return new, old
