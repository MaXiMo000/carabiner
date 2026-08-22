"""Default output. Terse on purpose: a wall of text is how a tool gets muted."""

from __future__ import annotations

import sys

from ..finding import Finding, rank

COLOR = {"critical": "\033[41;97m", "high": "\033[31m", "medium": "\033[33m",
         "low": "\033[36m", "info": "\033[90m"}
RESET = "\033[0m"


def _c(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLOR.get(severity, '')}{text}{RESET}"


def render(new: list[Finding], accepted: list[Finding], elapsed: float,
           skipped: list[tuple[str, str]] | None = None) -> str:
    lines = []
    for f in sorted(new, key=lambda x: -rank(x.severity)):
        loc = f"{f.path}:{f.line}" if f.line else f.path
        sev = _c(f.severity.upper().ljust(8), f.severity)
        lines.append(f"  {sev} {f.rule}  {loc}")
        lines.append(f"           {f.message}")
        if f.fix:
            lines.append(f"           fix: {f.fix}")
        lines.append("")
    head = f"{len(new)} new"
    if accepted:
        head += f", {len(accepted)} accepted (carabiner debt)"
    lines.append(f"{head}   {elapsed:.2f}s")
    # Never silently skip an engine. A scan that reports "0 findings" while three
    # engines never ran is a lie the user has no way to detect.
    for name, hint in (skipped or []):
        lines.append(f"  note: engine '{name}' not run -- {hint}")
    return "\n".join(lines)
