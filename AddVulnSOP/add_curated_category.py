#!/usr/bin/env python3
"""Append one new entry to gen_vuln_yaml.py's _CURATED dict.

This is a deterministic text edit: locate the `_CURATED = {` line and its
matching closing `}` by simple brace-depth counting over the dict *body*
(counting only `{`/`}` characters, which is safe here because the existing
_CURATED entries are flat "key": "value", # comment lines with no nested
braces), then insert a new
    "<bug_id>": "<category>",  # <reason>
line immediately before that closing `}`.

gen_vuln_yaml.py (in the answers repo) is the one legitimate write target for
this script -- unlike every other file this AddVulnSOP toolkit touches, this
is explicitly the file this tool is meant to append a line to. See
onboarding_lib.find_repo_paths() for how the default path is resolved.

Usage:
    add_curated_category.py --bug-id <id> --category <one-of-CANONICAL_CATEGORIES> \\
        --reason "<short comment text>" [--gen-vuln-yaml-path <path>] [--dry-run]
"""
from __future__ import annotations

import argparse
import re

import onboarding_lib as lib

# Mirrors gen_vuln_yaml.py's CANONICAL_CATEGORIES exactly (hardcoded here per
# spec rather than imported, since this directory has no dependency on the
# answers repo's own package).
CANONICAL_CATEGORIES = {
    "out-of-bounds-read", "out-of-bounds-write",
    "use-after-free", "null-pointer-dereference",
    "memory-leak", "memory-exhaustion", "excessive-computation", "stack-exhaustion",
    "reachable-assertion", "type-confusion", "uncaught-exception",
    "undefined-behavior",
}

_CURATED_ENTRY_RE = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*,')


def find_curated_block(lines: list[str]) -> tuple[int, int]:
    """Return (open_idx, close_idx), 0-based line indices of the line
    containing '_CURATED = {' and the line containing its matching closing
    '}', found by brace-depth counting from the open line onward."""
    open_idx = None
    for i, line in enumerate(lines):
        if re.match(r"^_CURATED\s*=\s*\{", line):
            open_idx = i
            break
    if open_idx is None:
        raise ValueError("could not find '_CURATED = {' line")

    depth = 0
    started = False
    for i in range(open_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return open_idx, i
    raise ValueError("could not find matching closing '}' for _CURATED dict")


def existing_category(lines: list[str], open_idx: int, close_idx: int, bug_id: str) -> str | None:
    for i in range(open_idx + 1, close_idx):
        m = _CURATED_ENTRY_RE.match(lines[i])
        if m and m.group(1) == bug_id:
            return m.group(2)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Append a new bug_id -> category entry to gen_vuln_yaml.py's _CURATED dict"
    )
    ap.add_argument("--gen-vuln-yaml-path", default=None,
                     help="path to tools/gen_vuln_yaml.py; default <answers-repo>/tools/gen_vuln_yaml.py")
    ap.add_argument("--answers-repo", default=None, help="override the answers-repo default location")
    ap.add_argument("--bug-id", required=True)
    ap.add_argument("--category", required=True)
    ap.add_argument("--reason", required=True, help="short comment text explaining the classification")
    ap.add_argument("--dry-run", action="store_true", help="report what would be inserted, write nothing")
    args = ap.parse_args()

    if args.category not in CANONICAL_CATEGORIES:
        lib.emit({
            "changed": False,
            "reason": f"invalid category {args.category!r}; must be one of {sorted(CANONICAL_CATEGORIES)}",
        })
        return 1

    if args.gen_vuln_yaml_path:
        gvy_path = args.gen_vuln_yaml_path
    else:
        paths = lib.find_repo_paths(answers_repo=args.answers_repo)
        gvy_path = str(paths.answers / "tools" / "gen_vuln_yaml.py")

    text = open(gvy_path, encoding="utf-8").read()
    lines = text.splitlines(keepends=True)

    open_idx, close_idx = find_curated_block(lines)

    existing = existing_category(lines, open_idx, close_idx, args.bug_id)
    if existing is not None:
        lib.emit({
            "changed": False,
            "reason": "already curated",
            "existing_category": existing,
        })
        return 0

    reason = args.reason.strip()
    new_line = f'    "{args.bug_id}": "{args.category}",  # {reason}\n'

    if args.dry_run:
        lib.emit({
            "changed": False,
            "dry_run": True,
            "bug_id": args.bug_id,
            "category": args.category,
            "would_insert_line": new_line.rstrip("\n"),
            "gen_vuln_yaml_path": gvy_path,
        })
        return 0

    new_lines = lines[:close_idx] + [new_line] + lines[close_idx:]
    with open(gvy_path, "w", encoding="utf-8") as fp:
        fp.writelines(new_lines)

    lib.emit({
        "changed": True,
        "bug_id": args.bug_id,
        "category": args.category,
        "inserted_line": new_line.rstrip("\n"),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
