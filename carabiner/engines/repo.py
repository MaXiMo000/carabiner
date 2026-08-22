"""Repository hygiene. Native, instant, always available.

These are the cheapest checks in the tool and they catch the failure that
actually costs people money: a credential in the tree.
"""

from __future__ import annotations

import pathlib
import subprocess

from ..finding import Finding

# Container formats we cannot read a header from; the extension is all we have.
OPAQUE_KEYSTORES = {".p12", ".pfx", ".jks", ".ppk"}
# Extensions worth opening. A .pem is just as often a public certificate.
MAYBE_KEY_SUFFIXES = {".pem", ".key", ".crt", ".cer"}

PRIVATE_MARKERS = ("PRIVATE KEY-----", "BEGIN OPENSSH PRIVATE KEY",
                   "BEGIN PGP PRIVATE KEY")

# A private key under one of these is almost always a deliberate test fixture.
# Still worth reporting -- people commit real keys to test directories -- but
# not at the severity reserved for a live credential.
FIXTURE_HINTS = ("test", "tests", "__tests__", "fixture", "fixtures", "spec",
                 "example", "examples", "sample", "samples", "mock", "mocks",
                 "testdata", "e2e")
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc"}
MUST_IGNORE = (".env", "*.pem", "*.key")


# Evidence that this directory is a project at all. Without one of these, the
# repo engine has no business reporting: scanning an empty directory and telling
# the user it has no .gitignore and no SECURITY.md is exactly the noise that
# gets a security tool switched off.
PROJECT_MARKERS = (".git", ".gitignore", ".github", "package.json",
                   "pyproject.toml", "setup.py", "Cargo.toml", "go.mod",
                   "pom.xml", "Gemfile", "composer.json", "Makefile")


def available(root: pathlib.Path) -> bool:
    return any((root / m).exists() for m in PROJECT_MARKERS)


def _tracked(root: pathlib.Path) -> list[str]:
    try:
        r = subprocess.run(["git", "ls-files", "-z"], cwd=root, timeout=20,
                           capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    return [p for p in r.stdout.split("\0") if p]


def _key_material(path: pathlib.Path, name: pathlib.PurePosixPath) -> str | None:
    """What kind of secret this file holds, or None.

    Reads the header instead of trusting the extension. A .pem is just as often
    a public certificate, and reporting somebody's committed CA chain as
    critical key material is the kind of noise that gets a scanner switched off
    -- half of these across ten well-known repositories were certificates.
    """
    if name.name == ".env" or name.name in KEY_NAMES:
        return "key material"
    if name.suffix in OPAQUE_KEYSTORES:
        return "a keystore"
    if name.suffix not in MAYBE_KEY_SUFFIXES:
        return None
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:400]
    except OSError:
        return None
    if any(m in head for m in PRIVATE_MARKERS):
        return "a private key"
    # A certificate is public by design. Not a finding.
    return None


def run(root: pathlib.Path, full: bool = False) -> list[Finding]:
    out: list[Finding] = []

    gitignore = root / ".gitignore"
    body = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.exists() else ""
    missing = [p for p in MUST_IGNORE if p not in body]
    if missing:
        out.append(Finding(
            "repo", "REPO001", "medium", ".gitignore",
            f"not ignored: {', '.join(missing)} -- one `git add .` away from a "
            "credential in history",
            fix="add them to .gitignore; a secret removed in a later commit is "
                "still in the pack file and still needs rotating",
            snippet=" ".join(missing)))

    for rel in _tracked(root):
        name = pathlib.PurePosixPath(rel)
        kind = _key_material(root / rel, name)
        if kind is None:
            continue
        fixture = any(part.lower() in FIXTURE_HINTS for part in name.parts[:-1])
        out.append(Finding(
            "repo", "REPO002", "medium" if fixture else "critical", rel,
            f"{kind} is committed to the repository"
            + (" (looks like a test fixture, so reported lower -- but real keys "
               "do get committed to test directories)" if fixture else ""),
            fix="rotate the credential first, then purge it from history "
                "(git-filter-repo). Deleting the file is not remediation.",
            snippet=name.name))

    if not any((root / n).exists() for n in ("SECURITY.md", ".github/SECURITY.md")):
        out.append(Finding(
            "repo", "REPO003", "low", "SECURITY.md",
            "no SECURITY.md -- there is no documented way to report a "
            "vulnerability to you privately",
            fix="add SECURITY.md with a contact address and a disclosure window",
            snippet="SECURITY.md absent"))

    gitconfig = root / ".git" / "config"
    if gitconfig.exists():
        text = gitconfig.read_text(encoding="utf-8", errors="replace")
        if "://" in text and "@" in text and any(
                f"{s}:" in text for s in ("https", "http")):
            for line in text.splitlines():
                if "url =" in line and "@" in line and "://" in line:
                    cred = line.split("://", 1)[1].split("@")[0]
                    if ":" in cred:
                        out.append(Finding(
                            "repo", "REPO004", "high", ".git/config",
                            "a credential is embedded in a git remote URL",
                            fix="use a credential helper or SSH; this value is "
                                "readable by anything that can read the repo dir",
                            snippet=line.strip()))
    return out
