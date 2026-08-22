"""Engines. Each exposes `available(root) -> bool` and `run(root) -> [Finding]`.

Native engines (ci, repo) are always available and are why the first run finds
something real even on a machine with no scanners installed. Wrapped engines
(secrets, deps, container) arrive in Phase 1 and degrade to an install hint
rather than a crash.
"""

from . import ci, repo

ALL = {"ci": ci, "repo": repo}
