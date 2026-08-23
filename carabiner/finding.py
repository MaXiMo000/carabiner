"""The one findings model every engine reports into.

The redaction rule is structural, not procedural: `snippet` is scrubbed in
__post_init__, so it is not possible to construct a Finding holding a raw
secret. Removing that protection means changing this file, which shows up in a
diff. See tests/test_carabiner.py::test_redaction_is_structural.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")


def rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


# A credential is a long *unbroken* run of token characters. Slashes, dots and
# hyphens are separators in the identifiers this tool reports constantly --
# `dtolnay/rust-toolchain@stable` and `gcr.io/distroless/base-debian13` were both
# being mangled into unreadable stubs, which quietly damaged every finding that
# named an action or an image. Splitting on those separators keeps identifiers
# legible while still catching keys, which have no separators to split on.
_TOKENY = re.compile(r"[A-Za-z0-9+=_]{20,}")


def redact(text: str, keep: int = 4) -> str:
    """first4...last4 for anything token-shaped. Never the middle."""
    def scrub(m: re.Match) -> str:
        s = m.group(0)
        return f"{s[:keep]}...{s[-keep:]}" if len(s) > keep * 2 + 3 else "..."
    return _TOKENY.sub(scrub, text)[:200]


@dataclass(frozen=True)
class Finding:
    engine: str
    rule: str
    severity: str
    path: str
    message: str
    fix: str = ""
    # Context only. Redacted on construction; never a credential.
    snippet: str = ""
    # Reported for humans, deliberately NOT part of the fingerprint.
    line: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "snippet", redact(self.snippet))
        # Paths are always POSIX, whatever the host. git reports forward
        # slashes, SARIF requires them, and ignore globs are written with them --
        # so a Windows backslash here silently breaks every comparison that
        # matters. --diff matched nothing at all on Windows because of this,
        # and reported a clean repo, which is the failure this tool exists to
        # complain about.
        object.__setattr__(self, "path", str(self.path).replace("\\", "/"))
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def fingerprint(self) -> str:
        """Stable across reformatting, line shifts and whitespace changes.

        Line number is excluded on purpose. A baseline keyed on line numbers
        resurrects every accepted finding the first time someone adds an import
        at the top of the file, which is why baseline features in other tools
        get abandoned.
        """
        norm = re.sub(r"\s+", " ", self.snippet).strip().lower()
        raw = "|".join((self.engine, self.rule, self.path, norm))
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def as_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint, "engine": self.engine,
            "rule": self.rule, "severity": self.severity, "path": self.path,
            "line": self.line, "message": self.message, "fix": self.fix,
            "snippet": self.snippet,
        }
