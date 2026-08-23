"""Dockerfile security. Native -- our own code, no wrapper.

Trivy scans a *built image*: it needs a daemon, a build, and minutes. A
Dockerfile is text, and the mistakes that matter most are visible in it before
anything is built. That gap is why this engine exists rather than shelling out.

Deliberately not checked here: package CVEs. Trivy and osv-scanner do that far
better, and two tools reporting one problem is how a scanner loses trust.
"""

from __future__ import annotations

import pathlib
import re

from ..finding import Finding

MAX_DEPTH = 3
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "vendor", "target",
             "dist", "build", "__pycache__", "testdata", "fixtures"}

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}", re.I)
# Secret-shaped build args and env vars, matched as whole tokens: "AUTHOR"
# contains "AUTH", and that mistake has already been made once in this codebase.
_SECRET_TOKENS = {"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "APIKEY",
                  "CREDENTIAL", "CREDENTIALS", "PRIVATEKEY"}
_SECRET_PAIRS = (("API", "KEY"), ("ACCESS", "KEY"), ("SECRET", "KEY"),
                 ("PRIVATE", "KEY"), ("AUTH", "TOKEN"))
_PLACEHOLDER = ("change", "your", "xxx", "todo", "replace", "placeholder",
                "example", "dummy", "tobemodified", "<", "${", "$(")
# curl | sh: the remote script is fetched and executed unverified, at build time.
_PIPE_TO_SHELL = re.compile(
    r"(curl|wget)\b[^|&;]*\|\s*(sudo\s+)?(ba|z|d)?sh\b", re.I)
_TLS_OFF = re.compile(
    r"(--insecure\b|--no-check-certificate\b|-k\s|GIT_SSL_NO_VERIFY|"
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0)", re.I)


def _secretish(name: str) -> bool:
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", name.upper()) if t]
    return (any(t in _SECRET_TOKENS for t in toks)
            or any(a in toks and b in toks for a, b in _SECRET_PAIRS))


def _dockerfiles(root: pathlib.Path) -> list[pathlib.Path]:
    import os
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = pathlib.Path(dirpath).relative_to(root)
        depth = 0 if str(rel) == "." else len(rel.parts)
        dirnames[:] = [] if depth >= MAX_DEPTH else [
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.lower().startswith("dockerfile"):
                found.append(pathlib.Path(dirpath) / fn)
    return found


def available(root: pathlib.Path) -> bool:
    return bool(_dockerfiles(root))


# BuildKit heredocs: `RUN <<EOF` ... `EOF`. Airflow's Dockerfile embeds whole
# Python programs this way, and reading their bodies as Dockerfile instructions
# turned `from __future__ import annotations` into a FROM with a bad base image.
_HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")


def _blank_heredocs(text: str) -> str:
    """Blank out heredoc bodies, preserving line numbers."""
    lines, out, terminator = text.splitlines(), [], None
    for line in lines:
        if terminator is None:
            out.append(line)
            m = _HEREDOC.search(line)
            if m and not line.lstrip().startswith("#"):
                terminator = m.group(1)
        else:
            out.append("")
            if line.strip() == terminator:
                terminator = None
    return "\n".join(out)


def _logical_lines(text: str):
    """Join backslash continuations -- a `curl | sh` split across five lines is
    still a `curl | sh`, and line-at-a-time matching misses every one of them."""
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        yield start, (buf + line).strip()
        buf = ""
    if buf:
        yield start, buf.strip()


def run(root: pathlib.Path, full: bool = False,
        changed: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for df in sorted(_dockerfiles(root)):
        rel = str(df.relative_to(root))
        try:
            text = _blank_heredocs(df.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue

        # `FROM builder` refers to an earlier stage, not to an image. Nineteen
        # of the first thirty-six findings from this rule were exactly that, plus
        # `FROM scratch` (a keyword for the empty image) and `FROM ${BASE_IMAGE}`
        # (unknowable without the build args). Only three were real.
        stage_names: set[str] = set()
        stages, user_set, last_from_line = 0, False, None
        for lineno, line in _logical_lines(text):
            if not line or line.startswith("#"):
                continue
            verb, _, rest = line.partition(" ")
            verb = verb.upper()

            if verb == "FROM":
                stages += 1
                user_set = False          # each stage starts as root again
                last_from_line = lineno
                image = rest.split(" AS ")[0].split(" as ")[0].strip()
                alias = re.search(r"\s+as\s+(\S+)", rest, re.I)
                if alias:
                    stage_names.add(alias.group(1).strip().lower())
                unknowable = (image.lower() in stage_names
                              or image.lower() == "scratch"
                              # build args, and ERB/Jinja/Go templates: logstash
                              # ships Dockerfile.erb with `FROM <%= base_image %>`
                              or any(t in image for t in ("$", "<%", "{{")))
                if not unknowable and not _DIGEST.search(image):
                    tag = image.rpartition(":")[2] if ":" in image.rpartition("/")[2] else ""
                    if tag in ("", "latest"):
                        out.append(Finding(
                            "docker", "DOCK002", "medium", rel, line=lineno,
                            message=f"base image `{image}` is untagged or :latest "
                                    "-- the image you build tomorrow is not the "
                                    "one you tested",
                            fix="pin the base by digest: image@sha256:<64 hex>",
                            snippet=image))
            elif verb == "USER":
                user_set = rest.strip().split(":")[0] not in ("root", "0", "")
            elif verb in ("ARG", "ENV"):
                for pair in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)", rest):
                    key, val = pair.group(1), pair.group(2).strip("\"'")
                    if _secretish(key) and val and not any(
                            p in val.lower() for p in _PLACEHOLDER):
                        out.append(Finding(
                            "docker", "DOCK003", "high", rel, line=lineno,
                            message=f"`{verb} {key}` carries a value that looks "
                                    "like a credential -- build args and env vars "
                                    "are baked into the image layers and readable "
                                    "with `docker history`",
                            fix="pass it at runtime, or use a BuildKit secret "
                                "mount (--mount=type=secret), never ARG or ENV",
                            snippet=f"{verb} {key}=..."))
            elif verb == "RUN":
                if _PIPE_TO_SHELL.search(rest):
                    out.append(Finding(
                        "docker", "DOCK004", "medium", rel, line=lineno,
                        message="a remote script is piped straight into a shell "
                                "-- whatever that URL serves at build time runs "
                                "with full rights inside your image",
                        fix="download to a file, verify a checksum, then execute",
                        snippet=_PIPE_TO_SHELL.search(rest).group(0)[:60]))
                if _TLS_OFF.search(rest):
                    out.append(Finding(
                        "docker", "DOCK005", "high", rel, line=lineno,
                        message="certificate verification is disabled during the "
                                "build -- anything on the path can substitute "
                                "what you install",
                        fix="fix the trust store instead; a build that needs "
                            "--insecure is installing something unverified",
                        snippet=_TLS_OFF.search(rest).group(0)[:40]))

        # Only the final stage ships. Earlier build stages running as root is
        # normal and flagging them would be noise.
        if stages and not user_set:
            out.append(Finding(
                "docker", "DOCK001", "medium", rel, line=last_from_line,
                message="the final stage never drops privileges -- the container "
                        "runs as root",
                fix="add `USER 10001` (or any non-root uid) before CMD",
                snippet="no USER instruction"))
    return _filter(out, changed)


def _filter(out, changed):
    return out if changed is None else [f for f in out if f.path in changed]
