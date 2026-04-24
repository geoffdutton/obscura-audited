#!/usr/bin/env python3
"""PreToolUse gate: block Claude.ai session-identifying links from commits,
PRs, issue comments, and review replies. Policy: CLAUDE.md 'Commit / PR
hygiene'. Wired up in .claude/settings.json."""
from __future__ import annotations

import json
import re
import sys

PATTERN = re.compile(
    r"claude\.ai/(chat|share|code)/"
    r"|(?<![A-Za-z0-9_])session_[A-Za-z0-9_-]{8,}"
    r"|(?<![A-Za-z0-9_])gsd_[A-Za-z0-9_-]{8,}"
)

# Only gate Bash commands that actually publish text to the repo surface.
# Reads (grep, cat, etc.) are allowed to mention the forbidden strings.
GATE_BASH = re.compile(r"\bgit\s+commit\b|\bgh\s+(pr|issue|release)\b")

REASON = (
    "CLAUDE.md 'Commit / PR hygiene' forbids claude.ai/chat, claude.ai/share, "
    "claude.ai/code, session_*, and gsd_* in commits, PRs, issue comments, "
    "or review replies. Remove the trailer and retry."
)


def scan(value):
    if isinstance(value, str):
        m = PATTERN.search(value)
        return m.group(0) if m else None
    if isinstance(value, dict):
        for v in value.values():
            hit = scan(v)
            if hit:
                return hit
    if isinstance(value, list):
        for v in value:
            hit = scan(v)
            if hit:
                return hit
    return None


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}

    if tool_name == "Bash":
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        if not GATE_BASH.search(command):
            return 0
        hit = scan(command)
    else:
        hit = scan(tool_input)

    if hit is None:
        return 0

    print(f"Blocked: {tool_name} input contains {hit!r}. {REASON}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
