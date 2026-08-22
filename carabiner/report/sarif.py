"""SARIF 2.1.0 -- the format that puts findings in a PR's Security tab.

This is the whole adoption surface for GitHub users: findings appear inline on
the diff instead of buried in a log nobody opens.

`partialFingerprints` carries our own stable fingerprint, which is what lets
GitHub track a finding across commits rather than reporting it as new every time
someone reformats the file. It is the same property the ratchet depends on, so
the two agree by construction.
"""

from __future__ import annotations

import json

from ..finding import Finding

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
HOME = "https://github.com/MaXiMo000/carabiner"

# GitHub renders `level`, but sorts and filters on `security-severity`.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}
_SCORE = {"critical": "9.5", "high": "7.5", "medium": "5.0",
          "low": "3.0", "info": "1.0"}


def render(findings: list[Finding], version: str = "0.1.0") -> str:
    rules, seen = [], set()
    for f in findings:
        if f.rule in seen:
            continue
        seen.add(f.rule)
        rules.append({
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": f.message[:120]},
            "fullDescription": {"text": f.message},
            "help": {"text": f.fix or f.message,
                     "markdown": f"**{f.rule}**\n\n{f.message}\n\n_Fix:_ {f.fix}"},
            "properties": {"security-severity": _SCORE.get(f.severity, "5.0"),
                           "tags": ["security", f.engine]},
        })

    results = [{
        "ruleId": f.rule,
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": f.message + (f"\nFix: {f.fix}" if f.fix else "")},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path},
            # SARIF regions are 1-based and a startLine of 0 is invalid, so a
            # finding without a line reports the file rather than a fake line 1.
            **({"region": {"startLine": f.line}} if f.line else {}),
        }}],
        "partialFingerprints": {"carabinerFingerprint/v1": f.fingerprint},
    } for f in findings]

    return json.dumps({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "carabiner", "version": version,
                "informationUri": HOME, "rules": rules}},
            "results": results,
        }],
    }, indent=2)
