#!/usr/bin/env python3
"""Find (and optionally delete) changelog/history/security-advisory files in
a source tree that could leak a vulnerability's identity to a benchmark
solver (CVE numbers, "fixed in version X.Y.Z" notes, etc).

Two independent sweeps, matching the SOP's own documented approach:
  - name sweep: filenames starting with NEWS/CHANGELOG/SECURITY/HISTORY
    (case-insensitive), anywhere in the tree.
  - content sweep: README*/*.md/*.txt files at shallow depth, grepped for a
    small set of loaded phrases ("CVE-", "vulnerability", "security
    advisory", "fixed in version"). This is a simple heuristic -- false
    positives are expected and fine (a human/agent reviews the excerpts
    before deciding what to --apply); it is deliberately not trying to be a
    precise classifier.

Without --apply: read-only, reports candidates + short excerpts.
With --apply <comma-separated relative paths>: deletes exactly those paths
under --context-dir and nothing else.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import onboarding_lib as lib

NAME_SWEEP_RE = re.compile(r"^(news|changelog|security|history)", re.IGNORECASE)
CONTENT_SWEEP_GLOB_RE = re.compile(r"^(readme.*|.*\.md|.*\.txt)$", re.IGNORECASE)
CONTENT_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE),
    re.compile(r"vulnerabilit(y|ies)", re.IGNORECASE),
    re.compile(r"security advisory", re.IGNORECASE),
    re.compile(r"fixed in version", re.IGNORECASE),
]
SHALLOW_DEPTH = 2  # relative path component count -- "README.md" = 1, "doc/README.md" = 2
EXCERPT_LEN = 200


def _shallow(rel: Path) -> bool:
    return len(rel.parts) <= SHALLOW_DEPTH


def _name_sweep(root: Path) -> list[str]:
    hits = []
    for p in root.rglob("*"):
        if p.is_file() and NAME_SWEEP_RE.match(p.name):
            hits.append(p.relative_to(root).as_posix())
    return sorted(hits)


def _first_matching_line(text: str) -> str | None:
    for line in text.splitlines():
        for pat in CONTENT_PATTERNS:
            if pat.search(line):
                return line.strip()
    return None


def _content_sweep(root: Path) -> dict[str, str]:
    """Returns {relpath: matching excerpt} for shallow README/*.md/*.txt
    files that hit one of the loaded phrases."""
    hits: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if not _shallow(rel) or not CONTENT_SWEEP_GLOB_RE.match(p.name):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        excerpt = _first_matching_line(text)
        if excerpt is not None:
            hits[rel.as_posix()] = excerpt[:EXCERPT_LEN]
    return hits


def _excerpt_for_name_hit(root: Path, relpath: str) -> str:
    p = root / relpath
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    stripped = text.strip()
    return stripped[:EXCERPT_LEN]


def sweep(context_dir: Path) -> dict:
    name_hits = _name_sweep(context_dir)
    content_hits = _content_sweep(context_dir)

    excerpts: dict[str, str] = dict(content_hits)
    for relpath in name_hits:
        if relpath not in excerpts:
            excerpts[relpath] = _excerpt_for_name_hit(context_dir, relpath)

    content_sweep = sorted(content_hits.keys())
    return {
        "name_sweep": name_hits,
        "content_sweep": content_sweep,
        "excerpts": excerpts,
    }


def apply_deletions(context_dir: Path, relpaths: list[str]) -> dict:
    deleted, not_found = [], []
    for relpath in relpaths:
        relpath = relpath.strip()
        if not relpath:
            continue
        target = (context_dir / relpath).resolve()
        # keep deletions confined to context_dir
        try:
            target.relative_to(context_dir.resolve())
        except ValueError:
            not_found.append(relpath)
            continue
        if target.is_file():
            target.unlink()
            deleted.append(relpath)
        else:
            not_found.append(relpath)
    return {"deleted": deleted, "not_found": not_found}


def main():
    ap = argparse.ArgumentParser(
        description="Sweep a source tree for changelog/history/security-advisory files that could "
                    "leak a vulnerability's identity, and optionally delete a chosen subset."
    )
    ap.add_argument("--context-dir", required=True, help="path to the source tree to sweep")
    ap.add_argument("--apply", default=None,
                     help="comma-separated relative paths (from --context-dir) to delete")
    args = ap.parse_args()

    context_dir = Path(args.context_dir).resolve()

    if args.apply is not None:
        result = apply_deletions(context_dir, args.apply.split(","))
    else:
        result = sweep(context_dir)

    lib.emit(result)


if __name__ == "__main__":
    main()
