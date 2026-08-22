"""Vulnerable dependencies. Wraps osv-scanner.

The plan called for pip-audit, npm audit and osv-scanner. It gets one: osv-scanner
reads lockfiles for PyPI, npm, Go, Maven, crates.io, RubyGems and more from the
same OSV database the others draw from, so shipping three parsers would be three
times the maintenance for the same findings. Add pip-audit only if someone
reports a case osv-scanner genuinely misses.

Advisory ids are normalized to a canonical form before they become findings.
Without that, osv-scanner's GHSA-xxxx and pip-audit's PYSEC-xxxx for the same
vulnerability are two different fingerprints, and the developer sees one problem
reported twice -- which costs trust faster than a missed finding.
"""

from __future__ import annotations

import json
import pathlib
import shutil

from . import _tool
from ..finding import Finding

REQUIRES = "osv-scanner"
INSTALL = "brew install osv-scanner   (or https://github.com/google/osv-scanner/releases)"

# osv-scanner exits 1 when it finds vulnerabilities, 0 when clean.
_VULNS_FOUND = 1

# Manifests worth scanning. Absent all of these, the engine has nothing to say
# and should not report itself as skipped.
MANIFESTS = (
    "requirements.txt", "poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock", "pom.xml",
)

_OSV_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
    "MEDIUM": "medium", "LOW": "low",
}


def _bin() -> str | None:
    return shutil.which(REQUIRES)


def has_manifest(root: pathlib.Path) -> bool:
    # ponytail: top level only. A recursive glob here runs on every pre-commit
    # invocation and blows the 2s budget on a monorepo. Nested manifests come
    # with monorepo support in Phase 5, behind --all.
    return any((root / m).exists() for m in MANIFESTS)


def available(root: pathlib.Path) -> bool:
    return _bin() is not None and has_manifest(root)


def missing(root: pathlib.Path) -> str | None:
    """Only nag about a missing tool in a repo that actually has dependencies."""
    if not has_manifest(root) or _bin():
        return None
    return INSTALL


def canonical_id(primary: str, aliases: list[str]) -> str:
    """One id per vulnerability, so two scanners agree on the fingerprint.

    CVE wins because every database carries it; GHSA is the common fallback.
    """
    ids = [str(primary)] + [str(a) for a in (aliases or [])]
    for prefix in ("CVE-", "GHSA-"):
        for i in ids:
            if i.upper().startswith(prefix):
                return i.upper() if prefix == "CVE-" else i
    return str(primary)


def _severity(vuln: dict, group_max: str | None) -> str:
    named = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    if named in _OSV_SEVERITY:
        return _OSV_SEVERITY[named]
    # CVSS base score -> the usual buckets.
    try:
        score = float(group_max)
    except (TypeError, ValueError):
        # A known advisory with no score attached is not "low". Unknown is not
        # the same as harmless, and defaulting down is how real CVEs get muted.
        return "high"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _parse(payload: dict, root: pathlib.Path) -> list[Finding]:
    """Read defensively: osv-scanner's JSON shape has moved between majors, and
    an engine that raises on an unknown key takes the whole scan down."""
    out = []
    for result in (payload or {}).get("results") or []:
        raw_src = str((result.get("source") or {}).get("path") or "?")
        try:
            src = str(pathlib.Path(raw_src).relative_to(root))
        except ValueError:
            src = pathlib.Path(raw_src).name
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            name = str(info.get("name") or "?")
            version = str(info.get("version") or "?")
            worst = None
            for group in pkg.get("groups") or []:
                worst = group.get("max_severity") or worst
            for vuln in pkg.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = canonical_id(vuln.get("id") or "UNKNOWN", vuln.get("aliases"))
                out.append(Finding(
                    engine="deps", rule=f"DEP-{vid}",
                    severity=_severity(vuln, worst), path=src,
                    message=f"{name} {version}: "
                            f"{str(vuln.get('summary') or vid)[:140]}",
                    fix=f"upgrade {name}; see https://osv.dev/vulnerability/"
                        f"{vuln.get('id')}",
                    # The dedup key. Identical across any scanner reporting the
                    # same advisory for the same package.
                    snippet=f"{name}@{version}"))
    return out


def run(root: pathlib.Path, full: bool = False) -> list[Finding]:
    binary = _bin()
    if not binary or not has_manifest(root):
        return []
    if _tool.supports(binary, "scan"):
        cmd = [binary, "scan", "source", "--format", "json", "-r", str(root)]
    else:
        cmd = [binary, "--format", "json", "-r", str(root)]
    stdout, err = _tool.invoke(cmd, ok_codes=(0, _VULNS_FOUND))
    if err:
        return [_tool.error("deps", REQUIRES, err)]
    try:
        return _parse(json.loads(stdout or "{}"), root)
    except (json.JSONDecodeError, ValueError) as e:
        return [_tool.error("deps", REQUIRES, f"unparseable report: {e}")]
