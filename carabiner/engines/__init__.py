"""Engines. Each exposes `available(root) -> bool` and `run(root) -> [Finding]`.

Native engines (ci, repo) need nothing installed and are why the first run finds
something real instead of handing you a shopping list. Wrapped engines expose
`missing(root) -> str | None` and degrade to an install hint, never a crash: a
scan that dies because trivy is absent teaches people to stop running scans.
"""

import pathlib

from . import ci, deps, repo, secrets

ALL = {"ci": ci, "repo": repo, "secrets": secrets, "deps": deps}


def networked(name: str) -> bool:
    return bool(getattr(ALL[name], "NETWORK", False))


def full_only(name: str) -> bool:
    return bool(getattr(ALL[name], "FULL_ONLY", False))


def missing(root: pathlib.Path) -> list[tuple[str, str]]:
    """[(engine, install hint)] for engines that could contribute here but can't run."""
    out = []
    for name, engine in ALL.items():
        fn = getattr(engine, "missing", None)
        hint = fn(root) if fn else None
        if hint:
            out.append((name, hint))
    return out
