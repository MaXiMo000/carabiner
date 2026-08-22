"""Repository hygiene. Native, instant, always available.

These are the cheapest checks in the tool and they catch the failure that
actually costs people money: a credential in the tree.
"""

from __future__ import annotations

import pathlib
import re
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
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}

# Registry config files hold a credential only sometimes. Across 33 well-known
# repositories every committed .npmrc was plain configuration -- ignore-scripts,
# package-lock=false -- so treating the filename as proof produced 13 false
# positives and nothing else.
CREDENTIAL_CONFIGS = {".npmrc", ".pypirc", ".netrc"}
CREDENTIAL_KEYS = ("_authToken", "_auth=", "_auth ", "_password", "password =",
                   "password=", "login ", "machine ")
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


# Matched as whole tokens, never as substrings. "AUTH" inside
# LINEAR_CMS_STATUS_WAITING_ON_AUTHOR made a Linear workflow UUID look like a
# credential -- substring matching on a key name finds words that are not there.
ENV_SECRET_TOKENS = {"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "APIKEY",
                     "CREDENTIAL", "CREDENTIALS", "PRIVATEKEY"}
ENV_SECRET_PAIRS = (("API", "KEY"), ("ACCESS", "KEY"), ("SECRET", "KEY"),
                    ("PRIVATE", "KEY"), ("AUTH", "TOKEN"), ("CLIENT", "SECRET"))


def _secretish_key(key: str) -> bool:
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", key.upper()) if t]
    if any(t in ENV_SECRET_TOKENS for t in toks):
        return True
    return any(a in toks and b in toks for a, b in ENV_SECRET_PAIRS)

# Committed on purpose, as documentation. Flagging a template for containing the
# word SECRET is the same filename-over-content mistake in yet another costume.
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

# Values that exist to be replaced. strapi ships JWT_SECRET=tobemodified.
TRIVIAL_VALUES = {"true", "false", "on", "off", "yes", "no", "0", "1", "none", "null"}

PLACEHOLDERS = ("tobemodified", "changeme", "change_me", "your", "xxx", "todo",
                "replace", "placeholder", "example", "dummy", "insert", "<", "...")


def _env_has_secret(body: str) -> bool:
    """Does this dotenv file actually carry a credential?

    A version pin is not a secret. A populated SECRET/TOKEN/PASSWORD key is, and
    so is a URL with a password embedded in its authority.
    """
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("\"'")
        if not value or value.startswith("${"):
            continue
        if _secretish_key(key):
            # A secret-shaped key whose value is obviously a stand-in is not a
            # leak; it is a instruction to the next developer.
            # A length threshold was wrong here -- "hunter2" is seven
            # characters and still a password. Only obvious stand-ins and
            # boolean config are skipped.
            if any(ph in value.lower() for ph in PLACEHOLDERS) or \
                    value.lower() in TRIVIAL_VALUES:
                continue
            return True
        if "://" in value and "@" in value.split("://", 1)[1].split("/")[0]:
            return True
    return any(m in body for m in PRIVATE_MARKERS)


def _is_fixture(parts) -> bool:
    """`test-fixtures` is a fixture directory. Matching whole path segments
    missed all fourteen of vault's committed test keys, which sit under exactly
    that name."""
    for part in parts:
        if any(tok in FIXTURE_HINTS for tok in re.split(r"[-_. ]", part.lower())):
            return True
    return False


def _key_material(path: pathlib.Path, name: pathlib.PurePosixPath) -> str | None:
    """What kind of secret this file holds, or None.

    Reads the header instead of trusting the extension. A .pem is just as often
    a public certificate, and reporting somebody's committed CA chain as
    critical key material is the kind of noise that gets a scanner switched off
    -- half of these across ten well-known repositories were certificates.
    """
    if name.name in KEY_NAMES:
        return "key material"
    if name.suffix in ENV_TEMPLATE_SUFFIXES or name.name.endswith(ENV_TEMPLATE_SUFFIXES):
        return None
    if name.name == ".env" or name.name.startswith(".env."):
        # Third time this mistake has been made in this codebase: the filename
        # is not the evidence. grafana commits eleven .env files under devenv/
        # that contain nothing but `mysql_version=8.0.32`.
        try:
            return ("an environment file with credentials in it"
                    if _env_has_secret(path.read_text(encoding="utf-8",
                                                      errors="replace")[:8000])
                    else None)
        except OSError:
            return None
    if name.name in CREDENTIAL_CONFIGS:
        try:
            body = path.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            return None
        return ("a registry credential"
                if any(k in body for k in CREDENTIAL_KEYS) else None)
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
            # Fires on essentially every repository, so it carries no signal on
            # its own. Informational: real when a key later lands, noise today.
            "repo", "REPO001", "info", ".gitignore",
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
        fixture = _is_fixture(name.parts[:-1])
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
            "repo", "REPO003", "info", "SECURITY.md",
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
