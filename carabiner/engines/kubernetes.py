"""Kubernetes manifest security. Native -- our own code, no wrapper.

A manifest is YAML, and the settings that matter most are visible in it long
before anything reaches a cluster. Admission controllers catch these at deploy
time; this catches them at review time, which is where they are cheap to fix.

Deliberately not checked: image CVEs (Trivy), RBAC graph analysis (a real
problem, and a much bigger one than a file-at-a-time reader should attempt).
"""

from __future__ import annotations

import os
import pathlib

import yaml

from ..finding import Finding

MAX_DEPTH = 4
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "vendor", "target",
             "dist", "build", "__pycache__"}
# Workload kinds carry a pod template; the checks below live inside it.
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
             "ReplicaSet", "ReplicationController"}
SECRET_TOKENS = {"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "APIKEY",
                 "CREDENTIAL", "CREDENTIALS"}
SECRET_PAIRS = (("API", "KEY"), ("ACCESS", "KEY"), ("SECRET", "KEY"),
                ("PRIVATE", "KEY"), ("AUTH", "TOKEN"))
PLACEHOLDERS = ("change", "your", "xxx", "todo", "replace", "placeholder",
                "example", "dummy", "tobemodified", "<", "${", "{{")

# Keys that *name or locate* a secret rather than hold one. airflow's
# SECRET_NAME carries the name of a Kubernetes Secret; etcd's
# INITIAL_CLUSTER_TOKEN is a cluster identifier. Both matched on the word alone.
REFERENCE_SUFFIXES = {"NAME", "FILE", "PATH", "ID", "URL", "URI", "REF", "DIR",
                      "ENABLED", "TYPE", "MODE", "TTL", "TIMEOUT", "FORMAT",
                      "VERSION", "CLASS", "PROVIDER", "BACKEND", "METHOD"}
MIN_ENTROPY, MIN_LENGTH = 3.6, 12


def _entropy(text: str) -> float:
    """Shannon entropy per character. A cluster name scores near 3; a real
    credential scores well above 4."""
    import collections
    import math
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n)
                for c in collections.Counter(text).values())


def _manifests(root: pathlib.Path) -> list[pathlib.Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = pathlib.Path(dirpath).relative_to(root)
        depth = 0 if str(rel) == "." else len(rel.parts)
        dirnames[:] = [] if depth >= MAX_DEPTH else [
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith((".yaml", ".yml")):
                found.append(pathlib.Path(dirpath) / fn)
    return found


def _is_k8s(doc) -> bool:
    return (isinstance(doc, dict) and isinstance(doc.get("kind"), str)
            and "apiVersion" in doc)


def _pod_spec(doc: dict) -> dict | None:
    """The pod spec, wherever this kind happens to keep it."""
    kind = doc.get("kind")
    if kind not in WORKLOADS:
        return None
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec if isinstance(spec, dict) else None
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    tmpl = (spec.get("template") or {}).get("spec")
    return tmpl if isinstance(tmpl, dict) else None


def _secretish(name: str) -> bool:
    import re
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", name.upper()) if t]
    if not toks or toks[-1] in REFERENCE_SUFFIXES:
        return False
    return (any(t in SECRET_TOKENS for t in toks)
            or any(a in toks and b in toks for a, b in SECRET_PAIRS))


def _looks_like_a_credential(value: str) -> bool:
    """Both of this rule's first two findings were real values that were not
    credentials. A name is low-entropy by design; a secret is not."""
    return (len(value) >= MIN_LENGTH and _entropy(value) >= MIN_ENTROPY
            and not any(p in value.lower() for p in PLACEHOLDERS))


def available(root: pathlib.Path) -> bool:
    for path in _manifests(root):
        try:
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8",
                                                         errors="replace")):
                if _is_k8s(doc):
                    return True
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            continue
    return False


def run(root: pathlib.Path, full: bool = False,
        changed: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for path in sorted(_manifests(root)):
        rel = path.relative_to(root).as_posix()
        if changed is not None and rel not in changed:
            continue
        try:
            docs = list(yaml.safe_load_all(
                path.read_text(encoding="utf-8", errors="replace")))
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            continue

        for doc in docs:
            if not _is_k8s(doc):
                continue
            name = ((doc.get("metadata") or {}).get("name")) or doc["kind"]
            pod = _pod_spec(doc)
            if pod is None:
                continue

            # K8S001 -- the node's network stack, and every local service on it.
            for key, why in (("hostNetwork", "the node's network namespace"),
                             ("hostPID", "the node's process table"),
                             ("hostIPC", "the node's shared memory")):
                if pod.get(key) is True:
                    out.append(Finding(
                        "kubernetes", "K8S001", "high", rel,
                        f"`{name}` sets {key}: true -- the container shares "
                        f"{why}, so a compromise inside it is a compromise of "
                        "the node",
                        fix=f"remove {key}; if a workload genuinely needs it, "
                            "isolate it on a dedicated node pool",
                        snippet=f"{key}: true"))

            containers = [c for c in (list(pod.get("containers") or [])
                                      + list(pod.get("initContainers") or []))
                          if isinstance(c, dict)]
            pod_ctx = pod.get("securityContext") or {}
            for c in containers:
                cname = c.get("name") or "?"
                ctx = c.get("securityContext") or {}

                # K8S002 -- privileged is root on the node in all but name.
                if ctx.get("privileged") is True:
                    out.append(Finding(
                        "kubernetes", "K8S002", "critical", rel,
                        f"container `{cname}` in `{name}` runs privileged -- it "
                        "holds every capability and can reach the host devices; "
                        "this is root on the node in all but name",
                        fix="drop privileged and grant only the specific "
                            "capabilities the workload needs",
                        snippet="privileged: true"))

                # K8S003 -- escalating back to root after being told not to.
                if ctx.get("allowPrivilegeEscalation") is True:
                    out.append(Finding(
                        "kubernetes", "K8S003", "medium", rel,
                        f"container `{cname}` in `{name}` allows privilege "
                        "escalation -- a setuid binary can regain what the "
                        "securityContext took away",
                        fix="set allowPrivilegeEscalation: false",
                        snippet="allowPrivilegeEscalation: true"))

                # K8S004 -- nothing says "not root", so it is root.
                non_root = ctx.get("runAsNonRoot", pod_ctx.get("runAsNonRoot"))
                as_user = ctx.get("runAsUser", pod_ctx.get("runAsUser"))
                if non_root is not True and as_user in (None, 0):
                    out.append(Finding(
                        "kubernetes", "K8S004", "medium", rel,
                        f"container `{cname}` in `{name}` has nothing stopping it "
                        "running as root -- neither runAsNonRoot nor a non-zero "
                        "runAsUser is set",
                        fix="set `runAsNonRoot: true` and a runAsUser above 0",
                        snippet="no runAsNonRoot / runAsUser"))

                # K8S005 -- a credential written into the manifest, in the repo.
                for env in (c.get("env") or []):
                    if not isinstance(env, dict) or "value" not in env:
                        continue
                    key, val = str(env.get("name", "")), str(env.get("value", ""))
                    if _secretish(key) and _looks_like_a_credential(val):
                        out.append(Finding(
                            "kubernetes", "K8S005", "high", rel,
                            f"container `{cname}` in `{name}` has a literal value "
                            f"for `{key}` -- a credential committed in a manifest "
                            "is a credential in your git history",
                            fix="reference a Secret with valueFrom.secretKeyRef, "
                                "and keep the Secret out of the repository",
                            snippet=f"{key}: <redacted>"))
    return out
