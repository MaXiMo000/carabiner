"""Jenkins, CircleCI and Azure Pipelines.

Closes the last host gap. The vulnerability is the same one in every dialect:
text somebody else controls reaching a shell without ever becoming data.

Jenkinsfiles are Groovy, so this is regex-level rather than parsed -- stated
plainly because it means the coverage is shallower than the GitHub and GitLab
engines, not because Groovy is hard.
"""

from __future__ import annotations

import pathlib
import re

import yaml

from ..finding import Finding

JENKINS = ("Jenkinsfile", "jenkinsfile", "Jenkinsfile.groovy")
CIRCLE = ".circleci/config.yml"
AZURE = ("azure-pipelines.yml", "azure-pipelines.yaml", ".azure-pipelines.yml")

# Groovy interpolates ${...} inside DOUBLE quotes before the shell ever sees it,
# so a build parameter lands in the command as code. Single quotes do not
# interpolate, which is why the quote style is the whole finding.
_GROOVY_SH = re.compile(r"""\b(sh|bat|powershell)\s*\(?\s*"([^"]*\$\{[^}]*\}[^"]*)\"""")
_GROOVY_UNTRUSTED = re.compile(
    r"\$\{\s*(params\.[A-Za-z_]\w*|env\.(CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR|"
    r"BRANCH_NAME|ghprbPullTitle|ghprbSourceBranch))", re.I)
_CREDENTIAL_LITERAL = re.compile(
    r"""(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['"]([^'"\s]{8,})['"]""")
_PLACEHOLDER = ("change", "your", "xxx", "todo", "replace", "placeholder",
                "example", "dummy", "credentials(", "${", "<")

# CircleCI orbs: `volatile` always resolves to the newest publish.
_ORB_VOLATILE = re.compile(r"@volatile\b")
_CIRCLE_PARAM = re.compile(r"<<\s*pipeline\.(parameters|git)\.[A-Za-z_]\w*\s*>>")
_AZURE_PARAM = re.compile(r"\$\(\s*(Build\.SourceBranchName|Build\.SourceVersionMessage|"
                          r"System\.PullRequest\.SourceBranch)\s*\)", re.I)


def _files(root: pathlib.Path) -> list[pathlib.Path]:
    """Deduplicated by resolved path: macOS and Windows are case-insensitive, so
    `Jenkinsfile` and `jenkinsfile` are the same file and were being scanned
    twice, reporting every finding twice."""
    seen, found = set(), []
    for name in (*JENKINS, CIRCLE, *AZURE):
        path = root / name
        if not path.is_file():
            continue
        key = str(path.resolve()).lower()
        if key not in seen:
            seen.add(key)
            found.append(path)
    return found


def available(root: pathlib.Path) -> bool:
    return bool(_files(root))


def _jenkins(path: pathlib.Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in _GROOVY_SH.finditer(text):
        inner = m.group(2)
        u = _GROOVY_UNTRUSTED.search(inner)
        if not u:
            continue
        out.append(Finding(
            "ci", "JEN001", "high", rel,
            "a build parameter or branch name is interpolated into a double-quoted "
            "shell step -- Groovy expands it before the shell runs, so the value "
            "arrives as code",
            fix="use single quotes and pass the value through `environment {}`, "
                "then reference \"$VAR\" quoted inside the script",
            snippet=u.group(0)[:50],
            line=text[:m.start()].count("\n") + 1))
    for m in _CREDENTIAL_LITERAL.finditer(text):
        if any(p in m.group(0).lower() for p in _PLACEHOLDER):
            continue
        out.append(Finding(
            "ci", "JEN002", "high", rel,
            f"a literal value is assigned to `{m.group(1)}` in the pipeline -- "
            "anything committed here is in your git history",
            fix="use the credentials binding plugin: "
                "`withCredentials([string(credentialsId: ..., variable: ...)])`",
            snippet=f"{m.group(1)}: <redacted>",
            line=text[:m.start()].count("\n") + 1))
    return out


def _circle(path: pathlib.Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in _ORB_VOLATILE.finditer(text):
        out.append(Finding(
            "ci", "CIR001", "medium", rel,
            "an orb is pinned to `@volatile`, which always resolves to the most "
            "recent publish -- your pipeline runs code you have never seen",
            fix="pin the orb to an exact version",
            snippet="@volatile", line=text[:m.start()].count("\n") + 1))
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return out
    for m in _CIRCLE_PARAM.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        context = text.splitlines()[max(0, line_no - 3):line_no]
        if any("run" in c for c in context):
            out.append(Finding(
                "ci", "CIR002", "medium", rel,
                "a pipeline parameter is substituted into a run step -- CircleCI "
                "expands `<< >>` before the shell, so the value arrives as code",
                fix="assign it to an environment variable and reference \"$VAR\"",
                snippet=m.group(0)[:50], line=line_no))
    return out


def _azure(path: pathlib.Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in _AZURE_PARAM.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        context = "\n".join(text.splitlines()[max(0, line_no - 3):line_no])
        if re.search(r"\b(script|bash|powershell|pwsh)\s*:", context):
            out.append(Finding(
                "ci", "AZP001", "high", rel,
                "a branch name or commit message is substituted into a script "
                "step -- Azure expands `$( )` before the shell, so contributor "
                "text arrives as code",
                fix="map it into `env:` and reference \"$VAR\" quoted",
                snippet=m.group(0)[:50], line=line_no))
    return out


def run(root: pathlib.Path) -> list[Finding]:
    out: list[Finding] = []
    for path in _files(root):
        rel = str(path.relative_to(root))
        try:
            if path.name.lower().startswith("jenkinsfile"):
                out.extend(_jenkins(path, rel))
            elif rel == CIRCLE:
                out.extend(_circle(path, rel))
            else:
                out.extend(_azure(path, rel))
        except (OSError, UnicodeDecodeError):
            continue
    return out
