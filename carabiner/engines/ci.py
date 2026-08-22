"""CI pipeline security, dispatched by host.

The engine is called `ci` because that is what it checks. GitHub Actions and
GitLab CI get their own parsers -- the vulnerabilities are the same shapes with
different spellings, and a repo using either should not have to know which
module found the problem.

Rule prefixes stay distinct (CI* for Actions, GL* for GitLab) so a finding names
its host without the user reading the source.
"""

from __future__ import annotations

import pathlib

from . import _github, _gitlab
from ..finding import Finding

HOSTS = (_github, _gitlab)


def available(root: pathlib.Path) -> bool:
    return any(h.available(root) for h in HOSTS)


def run(root: pathlib.Path, full: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for host in HOSTS:
        if host.available(root):
            out.extend(host.run(root))
    return out
