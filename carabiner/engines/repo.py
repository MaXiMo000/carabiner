"""Repository hygiene. Native, instant, always available.

These are the cheapest checks in the tool and they catch the failure that
actually costs people money: a credential in the tree.
"""

from __future__ import annotations

import pathlib
import subprocess

from ..finding import Finding

# Extensions that are key material by definition, not by heuristic.
KEY_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".ppk"}
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc"}
MUST_IGNORE = (".env", "*.pem", "*.key")


def available(root: pathlib.Path) -> bool:
    return True


def _tracked(root: pathlib.Path) -> list[str]:
    try:
        r = subprocess.run(["git", "ls-files", "-z"], cwd=root, timeout=20,
                           capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    return [p for p in r.stdout.split("\0") if p]


def run(root: pathlib.Path) -> list[Finding]:
    out: list[Finding] = []

    gitignore = root / ".gitignore"
    body = gitignore.read_text() if gitignore.exists() else ""
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
        if name.suffix in KEY_SUFFIXES or name.name in KEY_NAMES or \
                name.name == ".env":
            out.append(Finding(
                "repo", "REPO002", "critical", rel,
                "key material is committed to the repository",
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
        text = gitconfig.read_text(errors="replace")
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
