"""GitLab SAST report format -- the JSON GitLab CI natively renders in a
merge request's Security widget, the same adoption surface `sarif.py` gives
on GitHub.

Schema: gitlab.com/gitlab-org/security-products/security-report-schemas,
sast-report-format.json, report schema version 15. Validated against the
published schema in tests/test_carabiner.py -- the same discipline the
Finding schema itself gets, and for the same reason: a malformed report is
invisible until someone opens a merge request and the widget silently shows
nothing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

UTC = timezone.utc

from ..finding import Finding

REPORT_SCHEMA_VERSION = "15.0.6"

_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info"}

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


def render(findings: list[Finding], version: str = "0.1.0", *,
          started: datetime | None = None) -> str:
    """`started` is injectable for tests; a real run has no reason to pass it."""
    start = started or datetime.now(UTC)
    end = datetime.now(UTC)

    vulnerabilities = [{
        "id": f.fingerprint,
        "name": f.rule,
        "description": f.message,
        "severity": _SEVERITY.get(f.severity, "Unknown"),
        "solution": f.fix,
        # GitLab's schema calls the first entry the Primary Identifier and
        # gives it special meaning; carabiner has exactly one identifier per
        # finding, its own rule id, so there is no ordering choice to make.
        "identifiers": [{"type": "carabiner_rule", "name": f.rule, "value": f.rule}],
        "location": {
            "file": f.path,
            **({"start_line": f.line, "end_line": f.line} if f.line else {}),
        },
    } for f in findings]

    scanner = {
        "id": "carabiner", "name": "carabiner", "version": version,
        "vendor": {"name": "MaXiMo000"},
        "url": "https://github.com/MaXiMo000/carabiner",
    }

    return json.dumps({
        "version": REPORT_SCHEMA_VERSION,
        "vulnerabilities": vulnerabilities,
        "scan": {
            "analyzer": scanner,
            "scanner": scanner,
            "type": "sast",
            "start_time": start.strftime(_TIME_FORMAT),
            "end_time": end.strftime(_TIME_FORMAT),
            "status": "success",
        },
    }, indent=2)
