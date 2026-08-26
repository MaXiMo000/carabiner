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

# The one shape the rule above cannot see, and the one this tool reports on
# purpose: `scheme://user:SECRET@host`.
#
# Splitting on separators is what keeps identifiers legible, and a password is
# free to contain exactly those separators. `Tr0ub4dor-3-correct-horse` is four
# runs of under twenty characters and passes through untouched; so does an AWS
# secret key, whose slashes cut it into runs of 13, 7 and 18. REPO004 puts a
# git remote line into a snippet, so that was a real credential reaching a
# report and, through SARIF, a code-scanning alert.
#
# Matched by *shape*, never by entropy. A scheme, a userinfo colon and an `@`
# are unambiguous; an entropy heuristic would eventually decide that
# `MyOrg123/some-long-action-name` is a secret and mangle the identifiers the
# rule above exists to protect.
#
# The password may contain slashes, so this deliberately over-reaches: a URL
# like `https://host:8080/path@x` loses its port and path. That is the right
# direction to be wrong in *here*, and it is the opposite of the rule this tool
# applies to findings. A false positive in a report wastes an afternoon; a
# false negative in a redactor puts a live credential in a code-scanning
# alert.
_URL_CRED = re.compile(r"(?P<head>[a-zA-Z][A-Za-z0-9+.-]*://[^\s:@/]+:)[^\s@]+(?=@)")


def redact(text: str, keep: int = 4) -> str:
    """first4...last4 for anything token-shaped. Never the middle."""
    def scrub(m: re.Match) -> str:
        s = m.group(0)
        return f"{s[:keep]}...{s[-keep:]}" if len(s) > keep * 2 + 3 else "..."
    # URL credentials first: the password is removed outright rather than
    # shortened, because unlike a token there is no version of it that is
    # useful to a reader.
    text = _URL_CRED.sub(lambda m: m.group("head") + "***", text)
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
