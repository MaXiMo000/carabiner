"""`.carabiner.yml` -- and the one piece of process the tool imposes.

Every suppression must carry a written reason. An ignore without one is a config
error, not a warning. That single rule is the difference between a tool people
keep and a tool people route around: a silent `ignore:` list grows until the
scan is decorative, whereas a reason has to be defended in code review.
"""

from __future__ import annotations

import fnmatch
import pathlib

import yaml

from .finding import Finding, rank

CONFIG_NAME = ".carabiner.yml"
DEFAULT_FAIL_ON = "medium"


class ConfigError(Exception):
    """Raised rather than warned. A misread config silently disables checks."""


class Config:
    def __init__(self, data: dict | None = None):
        data = data or {}
        self.engines: dict = data.get("engines") or {}
        self.ignores: list[dict] = []
        for i, entry in enumerate(data.get("ignore") or []):
            if not isinstance(entry, dict) or not str(entry.get("reason") or "").strip():
                raise ConfigError(
                    f"{CONFIG_NAME}: ignore[{i}] has no `reason`. Every "
                    "suppression must say why, in writing -- an unexplained "
                    "ignore list is how a scan quietly becomes decorative.")
            self.ignores.append(entry)

    def enabled(self, engine: str) -> bool:
        return (self.engines.get(engine) or {}).get("enabled", True) is not False

    def fail_on(self, engine: str) -> str:
        return (self.engines.get(engine) or {}).get("fail_on", DEFAULT_FAIL_ON)

    def ignored(self, f: Finding) -> bool:
        for entry in self.ignores:
            pat, rule = entry.get("path"), entry.get("check")
            if pat and not fnmatch.fnmatch(f.path, pat):
                continue
            if rule and rule != f.rule:
                continue
            if pat or rule:
                return True
        return False

    def gate(self, findings: list[Finding]) -> int:
        """Exit code. Per-engine thresholds, because a missing SECURITY.md and a
        leaked key do not deserve the same gate."""
        for f in findings:
            if rank(f.severity) >= rank(self.fail_on(f.engine)):
                return 1
        return 0


def load(root: pathlib.Path) -> Config:
    path = root / CONFIG_NAME
    if not path.exists():
        return Config()
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ConfigError(f"{CONFIG_NAME} is not valid YAML: {e}") from e
    if data is not None and not isinstance(data, dict):
        raise ConfigError(f"{CONFIG_NAME} must be a mapping")
    return Config(data)


def detect(root: pathlib.Path) -> dict[str, str]:
    """What this repo actually is -> what to switch on. Reported to the user
    rather than applied silently."""
    from .engines import deps

    found = {}
    if (root / ".github" / "workflows").is_dir():
        found["ci"] = "GitHub Actions workflows"
    found["repo"] = "repository hygiene (always on)"
    if (root / ".git").is_dir():
        found["secrets"] = "git repository"
    present = [m for m in deps.MANIFESTS if (root / m).exists()]
    if present:
        found["deps"] = ", ".join(present[:3])
    return found
